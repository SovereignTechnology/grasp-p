/// NIP-34 Git Repository Event Handling
///
/// This module handles Git repository announcements (kind 30617) and
/// repository state announcements (kind 30618) according to NIP-34 and GRASP-01.
///
/// Reference:
/// - NIP-34: https://nips.nostr.com/34
/// - GRASP-01: https://gitworkshop.dev/danconwaydev.com/grasp/01.md
use anyhow::{anyhow, Result};
use nostr_sdk::prelude::{Event, Kind, ToBech32};

// NOTE: Using rust-nostr Kind variants instead of hardcoded constants:
// - KIND_REPOSITORY_ANNOUNCEMENT -> Kind::GitRepoAnnouncement (30617)
// - KIND_REPOSITORY_STATE -> Kind::RepoState (30618)
// - KIND_PR -> Kind::GitPullRequest (1618)
// - KIND_PR_UPDATE -> Kind::GitPullRequestUpdate (1619)
// - KIND_USER_GRASP_LIST -> Kind::GitUserGraspList (10317)

/// Repository announcement details extracted from NIP-34 event
#[derive(Debug, Clone)]
pub struct RepositoryAnnouncement {
    pub event: Event,
    pub identifier: String,
    pub name: Option<String>,
    pub description: Option<String>,
    pub clone_urls: Vec<String>,
    pub relays: Vec<String>,
    pub web_urls: Vec<String>,
    /// Pubkeys from the deprecated `maintainers` tag. Empty when the
    /// announcement uses `M`/`m` role tags, which take precedence per NIP-34.
    pub maintainers: Vec<String>,
    /// Currently-active maintainer pubkeys from NIP-34 `M`/`m` role tags;
    /// `None` when the announcement contains no `M`/`m` tags.
    ///
    /// The lead (`M`) / co-maintainer (`m`) distinction carries no meaning
    /// for this service, so both collapse into one maintainer set. Entries
    /// whose role history shows the role has ended are excluded entirely: an
    /// ended role means the pubkey is no longer a maintainer, and historic
    /// listing never grants authority for a past period.
    pub role_maintainers: Option<Vec<String>>,
    /// Whether any role tag names the author, active or ended. Per NIP-34 an
    /// author without a self-entry is implicitly a maintainer for the
    /// repository's entire history.
    author_has_role_entry: bool,
}

impl RepositoryAnnouncement {
    /// Parse a repository announcement from a NIP-34 kind 30617 event
    pub fn from_event(event: Event) -> Result<Self> {
        if event.kind != Kind::GitRepoAnnouncement {
            return Err(anyhow!(
                "Invalid event kind: expected {}, got {}",
                Kind::GitRepoAnnouncement,
                event.kind
            ));
        }

        // Extract identifier (required)
        let identifier = event
            .tags
            .iter()
            .find(|t| t.kind() == "d")
            .and_then(|t| t.content())
            .ok_or_else(|| anyhow!("Repository announcement missing 'd' tag (identifier)"))?
            .to_string();

        // Extract optional name
        let name = event
            .tags
            .iter()
            .find(|t| t.kind() == "name")
            .and_then(|t| t.content())
            .map(|s| s.to_string());

        // Extract description from content
        let description = if event.content.is_empty() {
            None
        } else {
            Some(event.content.clone())
        };

        // Extract clone URLs
        let clone_urls = event
            .tags
            .iter()
            .filter(|t| t.kind() == "clone")
            .flat_map(|t| {
                let vec = t.clone().to_vec();
                // Skip first element (tag name), rest are values
                vec.into_iter().skip(1)
            })
            .collect();

        // return error if mutliple clone tags (incorrect formatting)
        let clone_tag_count = event.tags.iter().filter(|t| t.kind() == "clone").count();

        if clone_tag_count > 1 {
            return Err(anyhow::anyhow!("multiple clone tags found. correct format is single clone tag with multiple values"));
        }

        // Extract relays
        let relays = event
            .tags
            .iter()
            .filter(|t| t.kind() == "relays")
            .flat_map(|t| {
                let vec = t.clone().to_vec();
                // Skip first element (tag name), rest are values
                vec.into_iter().skip(1)
            })
            .collect();

        // Extract web URLs
        let web_urls = event
            .tags
            .iter()
            .filter(|t| t.kind() == "web")
            .flat_map(|t| {
                let vec = t.clone().to_vec();
                // Skip first element (tag name), rest are values
                vec.into_iter().skip(1)
            })
            .collect();

        // Extract maintainer pubkeys from NIP-34 `M`/`m` role tags
        // Format: ["M"|"m", "<pubkey-hex>", "<start>", "<end>", ...]
        // A role tag lists a pubkey followed by optional alternating start/end
        // history timestamps; it is currently active when it has fewer than
        // four elements or an odd number of elements. Ended entries are
        // ignored entirely. A pubkey may appear in one `M` and one `m` tag to
        // record a transition between the roles and remains a maintainer
        // while either entry is active; a second tag under the same letter is
        // malformed and rejects the announcement.
        let author_hex = event.pubkey.to_hex();
        let mut role_tags_present = false;
        let mut author_has_role_entry = false;
        let mut role_active: Vec<String> = Vec::new();
        let mut seen_role_entries: Vec<(String, String)> = Vec::new();
        for tag in event.tags.iter() {
            let slice = tag.as_slice();
            let Some(kind) = slice.first() else { continue };
            if kind != "M" && kind != "m" {
                continue;
            }
            role_tags_present = true;
            let Some(pubkey) = slice.get(1).filter(|value| !value.is_empty()) else {
                continue;
            };
            let entry = (kind.clone(), pubkey.clone());
            if seen_role_entries.contains(&entry) {
                return Err(anyhow!("duplicate `{kind}` role tag for pubkey {pubkey}"));
            }
            seen_role_entries.push(entry);
            if *pubkey == author_hex {
                author_has_role_entry = true;
            }
            let active = slice.len() < 4 || slice.len() % 2 == 1;
            if active && !role_active.contains(pubkey) {
                role_active.push(pubkey.clone());
            }
        }
        let role_maintainers = role_tags_present.then_some(role_active);

        // Extract maintainers from the deprecated "maintainers" tag per NIP-34
        // Format: ["maintainers", "<pubkey1-hex>", "<pubkey2-hex>", ...]
        // Ignored entirely when `M` or `m` role tags are present.
        let maintainers = if role_tags_present {
            Vec::new()
        } else {
            event
                .tags
                .iter()
                .find(|tag| tag.as_slice().first().map(|s| s.as_str()) == Some("maintainers"))
                .map(|tag| {
                    tag.as_slice()[1..] // Skip the "maintainers" tag name
                        .iter()
                        .map(|s| s.to_string())
                        .collect()
                })
                .unwrap_or_default()
        };

        Ok(RepositoryAnnouncement {
            event,
            identifier,
            name,
            description,
            clone_urls,
            relays,
            web_urls,
            maintainers,
            role_maintainers,
            author_has_role_entry,
        })
    }

    /// Pubkeys this announcement currently lists as maintainers, excluding
    /// the author (who implicitly asserts maintainership of their own
    /// announcement).
    ///
    /// This is the invitation set for membership computation: listed pubkeys'
    /// announcements must be fetched so their acceptance is noticed, but a
    /// listing alone makes none of their events authoritative.
    pub fn listed_maintainers(&self) -> Vec<String> {
        let author = self.event.pubkey.to_hex();
        let source = self
            .role_maintainers
            .as_deref()
            .unwrap_or(&self.maintainers);
        let mut listed: Vec<String> = Vec::new();
        for pubkey in source {
            if *pubkey != author && !listed.contains(pubkey) {
                listed.push(pubkey.clone());
            }
        }
        listed
    }

    /// Whether this announcement asserts an active maintainer role for its
    /// own author.
    ///
    /// With `M`/`m` role tags the author is active via an active self-entry,
    /// or implicitly: per NIP-34 an author who appears in no role tag is a
    /// maintainer for the repository's entire history. Only an ended
    /// self-entry means the author has left, which takes precedence over
    /// assignments in other announcements. In the deprecated format the
    /// author always asserts maintainership; a `u` (subordinate fork) tag
    /// has no effect on maintainership.
    pub fn author_role_active(&self) -> bool {
        match &self.role_maintainers {
            Some(active) => {
                !self.author_has_role_entry || active.contains(&self.event.pubkey.to_hex())
            }
            None => true,
        }
    }

    /// Whether this announcement shows its author has left: a role tag names
    /// the author but none of their entries is active.
    ///
    /// An author absent from all role tags has *not* left - they are
    /// implicitly a maintainer for the repository's entire history.
    pub fn author_has_left(&self) -> bool {
        self.role_maintainers.is_some() && !self.author_role_active()
    }

    /// Check if this announcement lists the given domain in clone URLs
    ///
    /// Compares parsed host and port semantics, not substrings, so a URL such
    /// as `https://gitnostr.com.attacker.example/` cannot satisfy a check for
    /// `gitnostr.com`.
    pub fn has_clone_url(&self, domain: &str) -> bool {
        self.clone_urls
            .iter()
            .any(|url| crate::outbound::url_matches_service_domain(url, domain))
    }

    /// Check if this announcement lists the given relay
    ///
    /// Uses the same exact host and port comparison as [`Self::has_clone_url`].
    pub fn has_relay(&self, relay: &str) -> bool {
        self.relays
            .iter()
            .any(|r| crate::outbound::relay_url_matches_service(r, relay))
    }

    /// Check if this announcement lists the service (both clone and relay)
    ///
    /// GRASP-01 requirement: MUST reject announcements that do not list
    /// the service in both `clone` and `relays` tags unless implementing GRASP-05.
    pub fn lists_service(&self, domain: &str) -> bool {
        self.has_clone_url(domain) && self.has_relay(domain)
    }

    /// Get the npub of the repository owner
    pub fn owner_npub(&self) -> String {
        self.event.pubkey.to_bech32().unwrap_or_default()
    }

    /// Get the repository path: <npub>/<identifier>.git
    pub fn repo_path(&self) -> String {
        format!("{}/{}.git", self.owner_npub(), self.identifier)
    }
}

/// Repository state details extracted from NIP-34 event
#[derive(Debug, Clone)]
pub struct RepositoryState {
    pub event: Event,
    pub identifier: String,
    pub branches: Vec<BranchState>,
    pub tags: Vec<TagState>,
    /// HEAD reference (e.g., "refs/heads/main") if specified
    pub head: Option<String>,
}

/// Branch state (ref with commit hash)
#[derive(Debug, Clone)]
pub struct BranchState {
    pub name: String,
    pub commit: String,
}

/// Tag state (ref with commit hash)
#[derive(Debug, Clone)]
pub struct TagState {
    pub name: String,
    pub commit: String,
}

impl RepositoryState {
    /// Parse a repository state from a NIP-34 kind 30618 event
    pub fn from_event(event: Event) -> Result<Self> {
        if event.kind != Kind::RepoState {
            return Err(anyhow!(
                "Invalid event kind: expected {}, got {}",
                Kind::RepoState,
                event.kind
            ));
        }

        // Extract identifier (required)
        let identifier = event
            .tags
            .iter()
            .find(|t| t.kind() == "d")
            .and_then(|t| t.content())
            .ok_or_else(|| anyhow!("Repository state missing 'd' tag (identifier)"))?
            .to_string();

        // Extract branches (refs/heads/*)
        // Tag format: ["refs/heads/main", "commit_hash"]
        let branches = event
            .tags
            .iter()
            .filter_map(|t| {
                let kind = t.kind();
                if kind.starts_with("refs/heads/") {
                    let parts = t.clone().to_vec();
                    if parts.len() >= 2 {
                        Some(BranchState {
                            name: kind.strip_prefix("refs/heads/").unwrap().to_string(),
                            commit: parts[1].clone(),
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        // Extract tags (refs/tags/*)
        // Tag format: ["refs/tags/v1.0", "commit_hash"]
        // Exclude peeled tag notation ("refs/tags/v1.0^{}") — these are git's internal
        // dereference markers pointing to the underlying commit, not real refs.
        let tags = event
            .tags
            .iter()
            .filter_map(|t| {
                let kind = t.kind();
                if kind.starts_with("refs/tags/") && !kind.ends_with("^{}") {
                    let parts = t.clone().to_vec();
                    if parts.len() >= 2 {
                        Some(TagState {
                            name: kind.strip_prefix("refs/tags/").unwrap().to_string(),
                            commit: parts[1].clone(),
                        })
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();

        // Extract HEAD reference per NIP-34
        // Tag format: ["HEAD", "ref: refs/heads/main"] or ["HEAD", "refs/heads/main"]
        let head = event
            .tags
            .iter()
            .find(|t| t.kind() == "HEAD")
            .and_then(|t| {
                let parts = t.clone().to_vec();
                if parts.len() >= 2 {
                    let head_value = &parts[1];
                    // Handle both "ref: refs/heads/main" and "refs/heads/main" formats
                    if let Some(stripped) = head_value.strip_prefix("ref: ") {
                        Some(stripped.to_string())
                    } else {
                        Some(head_value.clone())
                    }
                } else {
                    None
                }
            });

        Ok(RepositoryState {
            event,
            identifier,
            branches,
            tags,
            head,
        })
    }

    /// Get the commit hash for a branch
    pub fn get_branch_commit(&self, branch: &str) -> Option<&str> {
        self.branches
            .iter()
            .find(|b| b.name == branch)
            .map(|b| b.commit.as_str())
    }

    /// Get the commit hash for a tag
    pub fn get_tag_commit(&self, tag: &str) -> Option<&str> {
        self.tags
            .iter()
            .find(|t| t.name == tag)
            .map(|t| t.commit.as_str())
    }

    /// Get the owner npub
    pub fn owner_npub(&self) -> String {
        self.event.pubkey.to_bech32().unwrap_or_default()
    }

    /// Get the HEAD branch name (without refs/heads/ prefix)
    pub fn get_head_branch(&self) -> Option<&str> {
        self.head
            .as_ref()
            .and_then(|h| h.strip_prefix("refs/heads/"))
    }

    /// Check if the HEAD commit is available in the git repository
    /// Returns true if we have the git data for the HEAD branch
    pub fn head_commit_available(&self) -> bool {
        if let Some(head_branch) = self.get_head_branch() {
            self.get_branch_commit(head_branch).is_some()
        } else {
            false
        }
    }
}

/// Validate that a repository identifier is safe for use as a filesystem path component.
///
/// NIP-34 places no restriction on `d` tag characters beyond NIP-01 (any string).
/// Identifiers are stored on disk verbatim and percent-encoded when used in URLs
/// (per NIP-34 `nostr://` spec and GRASP-01 HTTP path spec). This function only
/// rejects identifiers that cannot safely be stored as a filesystem directory name:
///
/// - Empty string
/// - Path separators (`/`, `\`) — would escape the repository directory
/// - Null bytes — rejected by most filesystems
/// - `.` or `..` — reserved path components (directory traversal)
///
/// Whitespace and other characters that require percent-encoding in URLs are
/// explicitly allowed here; callers are responsible for encoding them in URLs.
pub fn validate_identifier(identifier: &str) -> Result<(), String> {
    if identifier.is_empty() {
        return Err("identifier must not be empty".to_string());
    }
    if identifier == "." || identifier == ".." {
        return Err(format!(
            "identifier '{}' is a reserved path component",
            identifier
        ));
    }
    for ch in identifier.chars() {
        if ch == '/' || ch == '\\' {
            return Err(format!(
                "identifier '{}' contains path separator '{}'",
                identifier, ch
            ));
        }
        if ch == '\0' {
            return Err(format!("identifier '{}' contains a null byte", identifier));
        }
    }
    Ok(())
}

/// Validate a repository announcement according to GRASP-01 and GRASP-05
///
/// Returns:
/// - Accept: Announcement lists our service (GRASP-01) AND matches repository whitelist (if enabled)
/// - AcceptArchive: Announcement matches archive config (GRASP-05)
/// - Reject: Validation failed
///
/// Blacklist takes precedence over all whitelists:
/// - If blacklisted, always reject with specific reason (npub/identifier/npub+identifier)
///
/// When archive_read_only is true:
/// - ONLY accept announcements matching archive whitelist/all
/// - REJECT announcements listing our service but not in whitelist (read-only sync mode)
///
/// When repository_whitelist is set:
/// - Announcements must BOTH list our service AND match the repository whitelist
///
/// Note: AcceptMaintainer is NOT returned here (requires database access)
pub fn validate_announcement(
    event: &Event,
    config: &crate::config::Config,
) -> crate::nostr::policy::AnnouncementResult {
    use crate::nostr::policy::AnnouncementResult;

    // Must be kind 30617
    if event.kind != Kind::GitRepoAnnouncement {
        return AnnouncementResult::Reject(format!(
            "Invalid kind: expected {}",
            Kind::GitRepoAnnouncement
        ));
    }

    // Must have identifier
    let has_identifier = event.tags.iter().any(|t| t.kind() == "d");
    if !has_identifier {
        return AnnouncementResult::Reject("Missing required 'd' tag (identifier)".to_string());
    }

    // Parse full announcement to validate structure
    let announcement = match RepositoryAnnouncement::from_event(event.clone()) {
        Ok(a) => a,
        Err(e) => return AnnouncementResult::Reject(format!("Invalid announcement: {}", e)),
    };

    // Validate identifier is safe for filesystem and URL use
    if let Err(reason) = validate_identifier(&announcement.identifier) {
        return AnnouncementResult::Reject(format!("Invalid identifier: {}", reason));
    }

    // Get validated configs (config.validate() must be called at startup)
    let archive_config = config.archive_config();
    let repository_config = config.repository_config();
    let blacklist_config = config.blacklist_config();

    let npub = announcement.owner_npub();
    let lists_service = announcement.lists_service(&config.service_address());

    // Check blacklist FIRST - it overrides everything
    if let Some(reason) = blacklist_config.check(&npub, &announcement.identifier) {
        return AnnouncementResult::Reject(reason);
    }

    // GRASP-01: Normal mode - accept if announcement lists our service AND matches repository whitelist (if enabled)
    if lists_service && !archive_config.read_only {
        // Check repository whitelist if enabled
        if repository_config.enabled()
            && !repository_config.matches(&npub, &announcement.identifier)
        {
            return AnnouncementResult::Reject(format!(
                "Announcement lists service but does not match repository whitelist. \
                 Repository {}/{} not in whitelist",
                npub, announcement.identifier
            ));
        }
        return AnnouncementResult::Accept;
    }

    // GRASP-05: Archive mode - accept if announcement matches whitelist
    if archive_config.matches(&npub, &announcement.identifier) {
        return AnnouncementResult::AcceptArchive;
    }

    // GRASP-05: Archive mode - accept if announcement lists any configured GRASP service in clone URLs
    // Only check clone URLs (not relays) since we're archiving from OTHER services
    // Check if announcement matches any configured GRASP service domains
    if archive_config
        .grasp_services
        .iter()
        .any(|service| announcement.has_clone_url(service))
    {
        return AnnouncementResult::AcceptArchive;
    }

    // Reject with appropriate error message
    if archive_config.read_only {
        AnnouncementResult::Reject(format!(
            "Archive read-only mode: announcement must match archive whitelist. \
             Repository {}/{} not in whitelist",
            npub, announcement.identifier
        ))
    } else {
        AnnouncementResult::Reject(format!(
            "Announcement must list service in both 'clone' and 'relays' tags, or match archive whitelist. \
             Found clone URLs: {:?}, relays: {:?}",
            announcement.clone_urls, announcement.relays
        ))
    }
}

/// Validate a repository state announcement according to GRASP-01
///
/// Returns Ok(()) if valid, Err with reason if invalid.
pub fn validate_state(event: &Event) -> Result<()> {
    // Must be kind 30618
    if event.kind != Kind::RepoState {
        return Err(anyhow!("Invalid kind: expected {}", Kind::RepoState));
    }

    // Must have identifier
    let has_identifier = event.tags.iter().any(|t| t.kind() == "d");
    if !has_identifier {
        return Err(anyhow!("Missing required 'd' tag (identifier)"));
    }

    // Parse full state to validate structure
    let _state = RepositoryState::from_event(event.clone())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys};

    fn create_test_keys() -> Keys {
        Keys::generate()
    }

    fn create_announcement_event(
        keys: &Keys,
        identifier: &str,
        clone_urls: Vec<&str>,
        relays: Vec<&str>,
    ) -> Event {
        use nostr_sdk::prelude::Tag;

        let mut tags = vec![Tag::custom("d", vec![identifier.to_string()])];

        // NIP-34: Single clone tag with multiple values
        if !clone_urls.is_empty() {
            tags.push(Tag::custom(
                "clone",
                clone_urls.iter().map(|s| s.to_string()),
            ));
        }

        // NIP-34: Single relays tag with multiple values
        if !relays.is_empty() {
            tags.push(Tag::custom("relays", relays.iter().map(|s| s.to_string())));
        }

        EventBuilder::new(Kind::GitRepoAnnouncement, "Test repository")
            .tags(tags)
            .finalize(keys)
            .unwrap()
    }

    fn create_state_event(keys: &Keys, identifier: &str, branches: Vec<(&str, &str)>) -> Event {
        use nostr_sdk::prelude::Tag;

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

    #[test]
    fn test_parse_announcement() {
        let keys = create_test_keys();
        let event = create_announcement_event(
            &keys,
            "test-repo",
            vec!["https://gitnostr.com/alice/test-repo.git"],
            vec!["wss://gitnostr.com"],
        );

        let announcement = RepositoryAnnouncement::from_event(event).unwrap();

        assert_eq!(announcement.identifier, "test-repo");
        assert_eq!(announcement.clone_urls.len(), 1);
        assert_eq!(announcement.relays.len(), 1);
        assert!(announcement.has_clone_url("gitnostr.com"));
        assert!(announcement.has_relay("gitnostr.com"));
        assert!(announcement.lists_service("gitnostr.com"));
    }

    #[test]
    fn test_parse_announcement_missing_identifier() {
        let keys = create_test_keys();
        let event = EventBuilder::new(Kind::GitRepoAnnouncement, "Test repository")
            .finalize(&keys)
            .unwrap();

        let result = RepositoryAnnouncement::from_event(event);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("identifier"));
    }

    #[test]
    fn test_parse_state() {
        let keys = create_test_keys();
        let event = create_state_event(
            &keys,
            "test-repo",
            vec![("main", "a1b2c3d4"), ("develop", "e5f6g7h8")],
        );

        let state = RepositoryState::from_event(event).unwrap();

        assert_eq!(state.identifier, "test-repo");
        assert_eq!(state.branches.len(), 2);
        assert_eq!(state.get_branch_commit("main"), Some("a1b2c3d4"));
        assert_eq!(state.get_branch_commit("develop"), Some("e5f6g7h8"));
    }

    #[test]
    fn test_validate_announcement_success() {
        use crate::config::Config;
        use crate::nostr::policy::AnnouncementResult;

        let keys = create_test_keys();
        let event = create_announcement_event(
            &keys,
            "test-repo",
            vec!["https://gitnostr.com/alice/test-repo.git"],
            vec!["wss://gitnostr.com"],
        );

        let config = Config {
            domain: "gitnostr.com".to_string(),
            ..Config::for_testing()
        };
        let result = validate_announcement(&event, &config);
        assert!(matches!(result, AnnouncementResult::Accept));
    }

    #[test]
    fn path_mounted_service_requires_path_in_clone_and_relay_urls() {
        use crate::config::Config;
        use crate::nostr::policy::AnnouncementResult;

        let keys = create_test_keys();
        let config = Config {
            domain: "gitnostr.com".to_string(),
            base_path: "/grasp".to_string(),
            ..Config::for_testing()
        };
        let matching = create_announcement_event(
            &keys,
            "test-repo",
            vec!["https://gitnostr.com/grasp/alice/test-repo.git"],
            vec!["wss://gitnostr.com/grasp"],
        );
        let root_only = create_announcement_event(
            &keys,
            "test-repo",
            vec!["https://gitnostr.com/alice/test-repo.git"],
            vec!["wss://gitnostr.com"],
        );

        assert!(matches!(
            validate_announcement(&matching, &config),
            AnnouncementResult::Accept
        ));
        assert!(matches!(
            validate_announcement(&root_only, &config),
            AnnouncementResult::Reject(_)
        ));
    }

    #[test]
    fn test_validate_announcement_missing_clone() {
        use crate::config::Config;
        use crate::nostr::policy::AnnouncementResult;

        let keys = create_test_keys();
        let event = create_announcement_event(
            &keys,
            "test-repo",
            vec![], // No clone URLs
            vec!["wss://gitnostr.com"],
        );

        let config = Config {
            domain: "gitnostr.com".to_string(),
            ..Config::for_testing()
        };
        let result = validate_announcement(&event, &config);
        if let AnnouncementResult::Reject(reason) = result {
            assert!(reason.contains("clone"));
        } else {
            panic!("Expected Reject, got {:?}", result);
        }
    }

    #[test]
    fn test_validate_announcement_missing_relay() {
        use crate::config::Config;
        use crate::nostr::policy::AnnouncementResult;

        let keys = create_test_keys();
        let event = create_announcement_event(
            &keys,
            "test-repo",
            vec!["https://gitnostr.com/alice/test-repo.git"],
            vec![], // No relays
        );

        let config = Config {
            domain: "gitnostr.com".to_string(),
            ..Config::for_testing()
        };
        let result = validate_announcement(&event, &config);
        if let AnnouncementResult::Reject(reason) = result {
            assert!(reason.contains("relays"));
        } else {
            panic!("Expected Reject, got {:?}", result);
        }
    }

    #[test]
    fn test_validate_announcement_wrong_domain() {
        use crate::config::Config;
        use crate::nostr::policy::AnnouncementResult;

        let keys = create_test_keys();
        let event = create_announcement_event(
            &keys,
            "test-repo",
            vec!["https://other-service.com/alice/test-repo.git"],
            vec!["wss://other-service.com"],
        );

        let config = Config {
            domain: "gitnostr.com".to_string(),
            ..Config::for_testing()
        };
        let result = validate_announcement(&event, &config);
        assert!(matches!(result, AnnouncementResult::Reject(_)));
    }

    #[test]
    fn test_validate_state_success() {
        let keys = create_test_keys();
        let event = create_state_event(&keys, "test-repo", vec![("main", "a1b2c3d4")]);

        let result = validate_state(&event);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_state_missing_identifier() {
        let keys = create_test_keys();
        let event = EventBuilder::new(Kind::RepoState, "")
            .finalize(&keys)
            .unwrap();

        let result = validate_state(&event);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("identifier"));
    }

    #[test]
    fn test_announcement_maintainers() {
        use nostr_sdk::prelude::Tag;

        let keys = create_test_keys();
        let maintainer_keys = create_test_keys();

        let mut tags = vec![
            Tag::custom("d", vec!["test-repo".to_string()]),
            Tag::custom(
                "clone",
                vec!["https://gitnostr.com/alice/test-repo.git".to_string()],
            ),
            Tag::custom("relays", vec!["wss://gitnostr.com".to_string()]),
        ];

        // Add maintainer using NIP-34 "maintainers" tag format
        // Format: ["maintainers", "<pubkey1-hex>", "<pubkey2-hex>", ...]
        tags.push(Tag::custom(
            "maintainers",
            vec![maintainer_keys.public_key().to_hex()],
        ));

        let event = EventBuilder::new(Kind::GitRepoAnnouncement, "Test repository")
            .tags(tags)
            .finalize(&keys)
            .unwrap();

        let announcement = RepositoryAnnouncement::from_event(event).unwrap();
        assert_eq!(announcement.maintainers.len(), 1);
        assert_eq!(
            announcement.maintainers[0],
            maintainer_keys.public_key().to_hex()
        );
    }

    fn role_announcement(keys: &Keys, tags: Vec<(&str, Vec<String>)>) -> RepositoryAnnouncement {
        use nostr_sdk::prelude::Tag;

        let mut event_tags = vec![Tag::custom("d", vec!["test-repo".to_string()])];
        for (name, values) in tags {
            event_tags.push(Tag::custom(name, values));
        }
        let event = EventBuilder::new(Kind::GitRepoAnnouncement, "Test repository")
            .tags(event_tags)
            .finalize(keys)
            .unwrap();
        RepositoryAnnouncement::from_event(event).unwrap()
    }

    #[test]
    fn test_role_tag_activeness_by_element_count() {
        let keys = create_test_keys();
        let author = keys.public_key().to_hex();
        let other = create_test_keys().public_key().to_hex();

        // (history values after the pubkey, expected active)
        // Tag element counts: 2 -> active, 3 -> active, 4 -> ended,
        // 5 -> active, 6 -> ended.
        let cases: Vec<(Vec<&str>, bool)> = vec![
            (vec![], true),
            (vec!["100"], true),
            (vec!["100", "200"], false),
            (vec!["100", "200", "300"], true),
            (vec!["100", "200", "300", "400"], false),
        ];

        for (history, expected_active) in cases {
            let mut values = vec![other.clone()];
            values.extend(history.iter().map(|s| s.to_string()));
            let announcement =
                role_announcement(&keys, vec![("M", vec![author.clone()]), ("m", values)]);
            assert_eq!(
                announcement.listed_maintainers().contains(&other),
                expected_active,
                "history {history:?} expected active={expected_active}"
            );
        }
    }

    #[test]
    fn test_lead_and_co_maintainer_roles_are_equivalent() {
        let keys = create_test_keys();
        let author = keys.public_key().to_hex();
        let listed_as_lead = create_test_keys().public_key().to_hex();
        let listed_as_co = create_test_keys().public_key().to_hex();

        let announcement = role_announcement(
            &keys,
            vec![
                ("M", vec![author.clone()]),
                ("M", vec![listed_as_lead.clone()]),
                ("m", vec![listed_as_co.clone()]),
            ],
        );

        let listed = announcement.listed_maintainers();
        assert!(listed.contains(&listed_as_lead));
        assert!(listed.contains(&listed_as_co));
        assert!(
            !listed.contains(&author),
            "author is excluded from the listed set"
        );
        assert!(announcement.author_role_active());
    }

    #[test]
    fn test_maintainers_tag_ignored_when_role_tags_present() {
        let keys = create_test_keys();
        let author = keys.public_key().to_hex();
        let legacy_listed = create_test_keys().public_key().to_hex();

        let announcement = role_announcement(
            &keys,
            vec![
                ("M", vec![author]),
                ("maintainers", vec![legacy_listed.clone()]),
            ],
        );

        assert!(announcement.maintainers.is_empty());
        assert!(!announcement.listed_maintainers().contains(&legacy_listed));
    }

    #[test]
    fn test_author_leave_via_ended_self_role() {
        let keys = create_test_keys();
        let author = keys.public_key().to_hex();
        let lead = create_test_keys().public_key().to_hex();

        let announcement = role_announcement(
            &keys,
            vec![
                ("M", vec![lead.clone()]),
                ("m", vec![author, "0".to_string(), "1700000000".to_string()]),
            ],
        );

        assert!(!announcement.author_role_active());
        assert!(announcement.listed_maintainers().contains(&lead));
    }

    #[test]
    fn test_u_tag_has_no_effect_on_maintainership() {
        let keys = create_test_keys();
        let upstream = create_test_keys().public_key().to_hex();

        // Deprecated format: the author implicitly asserts maintainership,
        // with or without a `u` (subordinate fork) tag.
        let plain = role_announcement(&keys, vec![("maintainers", vec![upstream.clone()])]);
        assert!(plain.author_role_active());

        let fork = role_announcement(
            &keys,
            vec![
                ("maintainers", vec![upstream.clone()]),
                ("u", vec![format!("30617:{upstream}:test-repo")]),
            ],
        );
        assert!(fork.author_role_active());
        assert!(!fork.author_has_left());
    }

    #[test]
    fn test_author_without_self_role_entry_is_implicitly_active() {
        let keys = create_test_keys();
        let other = create_test_keys().public_key().to_hex();

        // Role tags that do not name the author: the author is implicitly a
        // maintainer for the repository's entire history.
        let announcement = role_announcement(&keys, vec![("m", vec![other])]);
        assert!(announcement.author_role_active());
        assert!(!announcement.author_has_left());
    }

    #[test]
    fn test_role_transition_across_letters_is_active_while_either_entry_active() {
        let keys = create_test_keys();
        let author = keys.public_key().to_hex();
        let demoted = create_test_keys().public_key().to_hex();
        let gone = create_test_keys().public_key().to_hex();

        // One `M` and one `m` tag for the same pubkey record a transition
        // between the roles: the pubkey is a maintainer while either entry
        // is active, and no longer one when both have ended.
        let announcement = role_announcement(
            &keys,
            vec![
                ("M", vec![author.clone()]),
                (
                    "M",
                    vec![demoted.clone(), "0".to_string(), "100".to_string()],
                ),
                ("m", vec![demoted.clone(), "100".to_string()]),
                ("M", vec![gone.clone(), "0".to_string(), "100".to_string()]),
                (
                    "m",
                    vec![gone.clone(), "100".to_string(), "200".to_string()],
                ),
            ],
        );

        let listed = announcement.listed_maintainers();
        assert!(listed.contains(&demoted));
        assert!(!listed.contains(&gone));
    }

    #[test]
    fn test_duplicate_same_letter_role_tag_rejects_announcement() {
        use nostr_sdk::prelude::Tag;

        let keys = create_test_keys();
        let author = keys.public_key().to_hex();
        let other = create_test_keys().public_key().to_hex();

        let event = EventBuilder::new(Kind::GitRepoAnnouncement, "Test repository")
            .tags(vec![
                Tag::custom("d", vec!["test-repo".to_string()]),
                Tag::custom("M", vec![author]),
                Tag::custom("m", vec![other.clone(), "0".to_string(), "100".to_string()]),
                Tag::custom("m", vec![other]),
            ])
            .finalize(&keys)
            .unwrap();

        let result = RepositoryAnnouncement::from_event(event);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("duplicate"));
    }

    #[test]
    fn test_state_with_tags() {
        use nostr_sdk::prelude::Tag;

        let keys = create_test_keys();
        let mut tags = vec![Tag::custom("d", vec!["test-repo".to_string()])];

        // Add branch
        tags.push(Tag::custom("refs/heads/main", vec!["a1b2c3d4".to_string()]));

        // Add tag
        tags.push(Tag::custom(
            "refs/tags/v1.0.0",
            vec!["e5f6g7h8".to_string()],
        ));

        let event = EventBuilder::new(Kind::RepoState, "")
            .tags(tags)
            .finalize(&keys)
            .unwrap();

        let state = RepositoryState::from_event(event).unwrap();
        assert_eq!(state.branches.len(), 1);
        assert_eq!(state.tags.len(), 1);
        assert_eq!(state.get_branch_commit("main"), Some("a1b2c3d4"));
        assert_eq!(state.get_tag_commit("v1.0.0"), Some("e5f6g7h8"));
    }

    #[test]
    fn test_state_with_head_ref_prefix() {
        use nostr_sdk::prelude::Tag;

        let keys = create_test_keys();
        let mut tags = vec![Tag::custom("d", vec!["test-repo".to_string()])];

        // Add branch
        tags.push(Tag::custom(
            "refs/heads/main",
            vec!["a1b2c3d4e5f6g7h8".to_string()],
        ));

        // Add HEAD with "ref: " prefix (common NIP-34 format)
        tags.push(Tag::custom(
            "HEAD",
            vec!["ref: refs/heads/main".to_string()],
        ));

        let event = EventBuilder::new(Kind::RepoState, "")
            .tags(tags)
            .finalize(&keys)
            .unwrap();

        let state = RepositoryState::from_event(event).unwrap();
        assert_eq!(state.head, Some("refs/heads/main".to_string()));
        assert_eq!(state.get_head_branch(), Some("main"));
        assert!(state.head_commit_available());
    }

    #[test]
    fn test_state_with_head_no_prefix() {
        use nostr_sdk::prelude::Tag;

        let keys = create_test_keys();
        let mut tags = vec![Tag::custom("d", vec!["test-repo".to_string()])];

        // Add branch
        tags.push(Tag::custom(
            "refs/heads/develop",
            vec!["deadbeefcafe".to_string()],
        ));

        // Add HEAD without "ref: " prefix (also valid)
        tags.push(Tag::custom("HEAD", vec!["refs/heads/develop".to_string()]));

        let event = EventBuilder::new(Kind::RepoState, "")
            .tags(tags)
            .finalize(&keys)
            .unwrap();

        let state = RepositoryState::from_event(event).unwrap();
        assert_eq!(state.head, Some("refs/heads/develop".to_string()));
        assert_eq!(state.get_head_branch(), Some("develop"));
        assert!(state.head_commit_available());
    }

    #[test]
    fn test_state_without_head() {
        use nostr_sdk::prelude::Tag;

        let keys = create_test_keys();
        let tags = vec![
            Tag::custom("d", vec!["test-repo".to_string()]),
            Tag::custom("refs/heads/main", vec!["a1b2c3d4".to_string()]),
        ];

        let event = EventBuilder::new(Kind::RepoState, "")
            .tags(tags)
            .finalize(&keys)
            .unwrap();

        let state = RepositoryState::from_event(event).unwrap();
        assert_eq!(state.head, None);
        assert_eq!(state.get_head_branch(), None);
        assert!(!state.head_commit_available());
    }

    #[test]
    fn test_state_head_commit_not_available() {
        use nostr_sdk::prelude::Tag;

        let keys = create_test_keys();
        let mut tags = vec![Tag::custom("d", vec!["test-repo".to_string()])];

        // Add branch for "main"
        tags.push(Tag::custom("refs/heads/main", vec!["a1b2c3d4".to_string()]));

        // HEAD points to "develop" which doesn't exist in branches
        tags.push(Tag::custom("HEAD", vec!["refs/heads/develop".to_string()]));

        let event = EventBuilder::new(Kind::RepoState, "")
            .tags(tags)
            .finalize(&keys)
            .unwrap();

        let state = RepositoryState::from_event(event).unwrap();
        assert_eq!(state.head, Some("refs/heads/develop".to_string()));
        assert_eq!(state.get_head_branch(), Some("develop"));
        // HEAD points to develop but only main branch exists in state
        assert!(!state.head_commit_available());
    }

    #[test]
    fn test_validate_announcement_with_trailing_slash_in_relay() {
        use crate::config::Config;
        use crate::nostr::policy::AnnouncementResult;

        let keys = create_test_keys();
        let event = create_announcement_event(
            &keys,
            "test-repo",
            vec!["https://git.shakespeare.diy/alice/test-repo.git"],
            vec!["wss://git.shakespeare.diy/"], // Trailing slash in relay
        );

        // Should accept despite trailing slash mismatch
        let config = Config {
            domain: "git.shakespeare.diy".to_string(),
            ..Config::for_testing()
        };
        let result = validate_announcement(&event, &config);
        assert!(matches!(result, AnnouncementResult::Accept));
    }

    #[test]
    fn test_validate_announcement_with_trailing_slash_in_clone_url() {
        use crate::config::Config;
        use crate::nostr::policy::AnnouncementResult;

        let keys = create_test_keys();
        let event = create_announcement_event(
            &keys,
            "test-repo",
            vec!["https://git.shakespeare.diy/"], // Trailing slash in clone URL
            vec!["wss://git.shakespeare.diy"],
        );

        // Should accept despite trailing slash mismatch
        let config = Config {
            domain: "git.shakespeare.diy".to_string(),
            ..Config::for_testing()
        };
        let result = validate_announcement(&event, &config);
        assert!(matches!(result, AnnouncementResult::Accept));
    }

    #[test]
    fn test_validate_announcement_with_trailing_slash_in_both() {
        use crate::config::Config;
        use crate::nostr::policy::AnnouncementResult;

        let keys = create_test_keys();
        let event = create_announcement_event(
            &keys,
            "test-repo",
            vec!["https://git.shakespeare.diy/alice/test-repo.git/"], // Trailing slash
            vec!["wss://git.shakespeare.diy/"],                       // Trailing slash
        );

        // Should accept with trailing slashes in both
        let config = Config {
            domain: "git.shakespeare.diy".to_string(),
            ..Config::for_testing()
        };
        let result = validate_announcement(&event, &config);
        assert!(matches!(result, AnnouncementResult::Accept));
    }

    #[test]
    fn test_validate_announcement_domain_with_trailing_slash() {
        use crate::config::Config;
        use crate::nostr::policy::AnnouncementResult;

        let keys = create_test_keys();
        let event = create_announcement_event(
            &keys,
            "test-repo",
            vec!["https://gitnostr.com/alice/test-repo.git"],
            vec!["wss://gitnostr.com"],
        );

        // Should accept even when domain parameter has trailing slash
        let config = Config {
            domain: "gitnostr.com/".to_string(),
            ..Config::for_testing()
        };
        let result = validate_announcement(&event, &config);
        assert!(matches!(result, AnnouncementResult::Accept));
    }

    #[test]
    fn test_has_clone_url_with_trailing_slashes() {
        let keys = create_test_keys();
        let event = create_announcement_event(
            &keys,
            "test-repo",
            vec!["https://example.com/repo.git/"],
            vec!["wss://example.com"],
        );

        let announcement = RepositoryAnnouncement::from_event(event).unwrap();

        // Should match with or without trailing slash
        assert!(announcement.has_clone_url("example.com"));
        assert!(announcement.has_clone_url("example.com/"));
    }

    #[test]
    fn test_has_relay_with_trailing_slashes() {
        let keys = create_test_keys();
        let event = create_announcement_event(
            &keys,
            "test-repo",
            vec!["https://example.com/repo.git"],
            vec!["wss://example.com/"],
        );

        let announcement = RepositoryAnnouncement::from_event(event).unwrap();

        // Should match with or without trailing slash
        assert!(announcement.has_relay("example.com"));
        assert!(announcement.has_relay("example.com/"));
    }

    #[test]
    fn test_validate_announcement_archive_mode_npub() {
        use crate::config::Config;
        use crate::nostr::policy::AnnouncementResult;

        let keys = create_test_keys();
        let npub = keys.public_key().to_bech32().unwrap();

        // Create announcement that does NOT list our service
        let event = create_announcement_event(
            &keys,
            "test-repo",
            vec!["https://other-service.com/alice/test-repo.git"],
            vec!["wss://other-service.com"],
        );

        // Create config that whitelists this npub
        let config = Config {
            domain: "gitnostr.com".to_string(),
            archive_whitelist: npub,
            archive_read_only: Some(false),
            ..Config::for_testing()
        };

        let result = validate_announcement(&event, &config);
        assert!(matches!(result, AnnouncementResult::AcceptArchive));
    }

    #[test]
    fn test_validate_announcement_archive_mode_identifier() {
        use crate::config::Config;
        use crate::nostr::policy::AnnouncementResult;

        let keys = create_test_keys();

        // Create announcement that does NOT list our service
        let event = create_announcement_event(
            &keys,
            "bitcoin-core",
            vec!["https://other-service.com/alice/bitcoin-core.git"],
            vec!["wss://other-service.com"],
        );

        // Create config that whitelists this identifier
        let config = Config {
            domain: "gitnostr.com".to_string(),
            archive_whitelist: "bitcoin-core".to_string(),
            archive_read_only: Some(false),
            ..Config::for_testing()
        };

        let result = validate_announcement(&event, &config);
        assert!(matches!(result, AnnouncementResult::AcceptArchive));
    }

    #[test]
    fn test_validate_announcement_archive_mode_repository() {
        use crate::config::Config;
        use crate::nostr::policy::AnnouncementResult;

        let keys = create_test_keys();
        let npub = keys.public_key().to_bech32().unwrap();

        // Create announcement that does NOT list our service
        let event = create_announcement_event(
            &keys,
            "linux",
            vec!["https://other-service.com/alice/linux.git"],
            vec!["wss://other-service.com"],
        );

        // Create config that whitelists this specific repo
        let config = Config {
            domain: "gitnostr.com".to_string(),
            archive_whitelist: format!("{}/linux", npub),
            archive_read_only: Some(false),
            ..Config::for_testing()
        };

        let result = validate_announcement(&event, &config);
        assert!(matches!(result, AnnouncementResult::AcceptArchive));
    }

    #[test]
    fn test_validate_announcement_archive_all() {
        use crate::config::Config;
        use crate::nostr::policy::AnnouncementResult;

        let keys = create_test_keys();

        // Create announcement that does NOT list our service
        let event = create_announcement_event(
            &keys,
            "any-repo",
            vec!["https://other-service.com/alice/any-repo.git"],
            vec!["wss://other-service.com"],
        );

        // Config with archive_all enabled
        let config = Config {
            domain: "gitnostr.com".to_string(),
            archive_all: true,
            archive_read_only: Some(false),
            ..Config::for_testing()
        };

        let result = validate_announcement(&event, &config);
        assert!(matches!(result, AnnouncementResult::AcceptArchive));
    }

    #[test]
    fn test_validate_announcement_reject_not_in_whitelist() {
        use crate::config::Config;
        use crate::nostr::policy::AnnouncementResult;

        let keys = create_test_keys();

        // Create announcement that does NOT list our service
        let event = create_announcement_event(
            &keys,
            "other-repo",
            vec!["https://other-service.com/alice/other-repo.git"],
            vec!["wss://other-service.com"],
        );

        // Config that whitelists different identifier
        let config = Config {
            domain: "gitnostr.com".to_string(),
            archive_whitelist: "bitcoin-core".to_string(),
            archive_read_only: Some(false),
            ..Config::for_testing()
        };

        let result = validate_announcement(&event, &config);
        assert!(matches!(result, AnnouncementResult::Reject(_)));
    }

    #[test]
    fn test_validate_announcement_grasp01_takes_precedence() {
        use crate::config::Config;
        use crate::nostr::policy::AnnouncementResult;

        let keys = create_test_keys();

        // Create announcement that DOES list our service
        let event = create_announcement_event(
            &keys,
            "test-repo",
            vec!["https://gitnostr.com/alice/test-repo.git"],
            vec!["wss://gitnostr.com"],
        );

        // With archive_read_only=false, GRASP-01 Accept takes precedence
        let config = Config {
            domain: "gitnostr.com".to_string(),
            archive_all: true,
            archive_read_only: Some(false),
            ..Config::for_testing()
        };

        let result = validate_announcement(&event, &config);
        assert!(matches!(result, AnnouncementResult::Accept));
    }

    #[test]
    fn test_archive_read_only_rejects_non_whitelisted() {
        use crate::config::Config;
        use crate::nostr::policy::AnnouncementResult;

        let keys = create_test_keys();

        // Create announcement that DOES list our service
        let event = create_announcement_event(
            &keys,
            "test-repo",
            vec!["https://gitnostr.com/alice/test-repo.git"],
            vec!["wss://gitnostr.com"],
        );

        // With archive_read_only=true and whitelist that doesn't include this repo,
        // should reject even though it lists our service
        let config = Config {
            domain: "gitnostr.com".to_string(),
            archive_whitelist: "bitcoin-core".to_string(),
            archive_read_only: Some(true),
            ..Config::for_testing()
        };

        let result = validate_announcement(&event, &config);
        assert!(matches!(result, AnnouncementResult::Reject(_)));
    }

    #[test]
    fn test_archive_read_only_accepts_whitelisted() {
        use crate::config::Config;
        use crate::nostr::policy::AnnouncementResult;

        let keys = create_test_keys();
        let npub = keys.public_key().to_bech32().unwrap();

        // Create announcement that lists our service
        let event = create_announcement_event(
            &keys,
            "test-repo",
            vec!["https://gitnostr.com/alice/test-repo.git"],
            vec!["wss://gitnostr.com"],
        );

        // With archive_read_only=true and whitelist that DOES include this repo,
        // should accept as AcceptArchive
        let config = Config {
            domain: "gitnostr.com".to_string(),
            archive_whitelist: npub,
            archive_read_only: Some(true),
            ..Config::for_testing()
        };

        let result = validate_announcement(&event, &config);
        assert!(matches!(result, AnnouncementResult::AcceptArchive));
    }

    #[test]
    fn test_archive_read_only_with_archive_all() {
        use crate::config::Config;
        use crate::nostr::policy::AnnouncementResult;

        let keys = create_test_keys();

        // Create announcement that lists our service
        let event = create_announcement_event(
            &keys,
            "any-repo",
            vec!["https://gitnostr.com/alice/any-repo.git"],
            vec!["wss://gitnostr.com"],
        );

        // With archive_read_only=true and archive_all=true,
        // should accept as AcceptArchive
        let config = Config {
            domain: "gitnostr.com".to_string(),
            archive_all: true,
            archive_read_only: Some(true),
            ..Config::for_testing()
        };

        let result = validate_announcement(&event, &config);
        assert!(matches!(result, AnnouncementResult::AcceptArchive));
    }

    #[test]
    fn test_repository_whitelist_accepts_matching() {
        use crate::config::Config;
        use crate::nostr::policy::AnnouncementResult;

        let keys = create_test_keys();
        let npub = keys.public_key().to_bech32().unwrap();

        // Create announcement that lists our service
        let event = create_announcement_event(
            &keys,
            "test-repo",
            vec!["https://gitnostr.com/alice/test-repo.git"],
            vec!["wss://gitnostr.com"],
        );

        // Config with repository whitelist that includes this repo
        let config = Config {
            domain: "gitnostr.com".to_string(),
            repository_whitelist: npub,
            ..Config::for_testing()
        };

        let result = validate_announcement(&event, &config);
        assert!(matches!(result, AnnouncementResult::Accept));
    }

    #[test]
    fn test_repository_whitelist_rejects_non_matching() {
        use crate::config::Config;
        use crate::nostr::policy::AnnouncementResult;

        let keys = create_test_keys();

        // Create announcement that lists our service
        let event = create_announcement_event(
            &keys,
            "test-repo",
            vec!["https://gitnostr.com/alice/test-repo.git"],
            vec!["wss://gitnostr.com"],
        );

        // Config with repository whitelist that does NOT include this repo
        let config = Config {
            domain: "gitnostr.com".to_string(),
            repository_whitelist: "bitcoin-core".to_string(),
            ..Config::for_testing()
        };

        let result = validate_announcement(&event, &config);
        assert!(matches!(result, AnnouncementResult::Reject(_)));
    }

    #[test]
    fn test_blacklist_rejects_npub() {
        use crate::config::Config;
        use crate::nostr::policy::AnnouncementResult;

        let keys = create_test_keys();
        let npub = keys.public_key().to_bech32().unwrap();

        // Create announcement that lists our service
        let event = create_announcement_event(
            &keys,
            "test-repo",
            vec!["https://gitnostr.com/alice/test-repo.git"],
            vec!["wss://gitnostr.com"],
        );

        // Config with blacklist for this npub
        let config = Config {
            domain: "gitnostr.com".to_string(),
            repository_blacklist: npub.clone(),
            ..Config::for_testing()
        };

        let result = validate_announcement(&event, &config);
        if let AnnouncementResult::Reject(reason) = result {
            assert!(reason.contains("owner"));
            assert!(reason.contains(&npub));
        } else {
            panic!("Expected Reject, got {:?}", result);
        }
    }

    #[test]
    fn test_blacklist_rejects_identifier() {
        use crate::config::Config;
        use crate::nostr::policy::AnnouncementResult;

        let keys = create_test_keys();

        // Create announcement that lists our service
        let event = create_announcement_event(
            &keys,
            "banned-repo",
            vec!["https://gitnostr.com/alice/banned-repo.git"],
            vec!["wss://gitnostr.com"],
        );

        // Config with blacklist for this identifier
        let config = Config {
            domain: "gitnostr.com".to_string(),
            repository_blacklist: "banned-repo".to_string(),
            ..Config::for_testing()
        };

        let result = validate_announcement(&event, &config);
        if let AnnouncementResult::Reject(reason) = result {
            assert!(reason.contains("identifier"));
            assert!(reason.contains("banned-repo"));
        } else {
            panic!("Expected Reject, got {:?}", result);
        }
    }

    #[test]
    fn test_blacklist_rejects_specific_repository() {
        use crate::config::Config;
        use crate::nostr::policy::AnnouncementResult;

        let keys = create_test_keys();
        let npub = keys.public_key().to_bech32().unwrap();

        // Create announcement that lists our service
        let event = create_announcement_event(
            &keys,
            "specific-repo",
            vec!["https://gitnostr.com/alice/specific-repo.git"],
            vec!["wss://gitnostr.com"],
        );

        // Config with blacklist for this specific repo
        let config = Config {
            domain: "gitnostr.com".to_string(),
            repository_blacklist: format!("{}/specific-repo", npub),
            ..Config::for_testing()
        };

        let result = validate_announcement(&event, &config);
        if let AnnouncementResult::Reject(reason) = result {
            assert!(reason.contains(&npub));
            assert!(reason.contains("specific-repo"));
        } else {
            panic!("Expected Reject, got {:?}", result);
        }
    }

    #[test]
    fn test_blacklist_overrides_repository_whitelist() {
        use crate::config::Config;
        use crate::nostr::policy::AnnouncementResult;

        let keys = create_test_keys();
        let npub = keys.public_key().to_bech32().unwrap();

        // Create announcement that lists our service
        let event = create_announcement_event(
            &keys,
            "test-repo",
            vec!["https://gitnostr.com/alice/test-repo.git"],
            vec!["wss://gitnostr.com"],
        );

        // Config with both whitelist and blacklist - blacklist should win
        let config = Config {
            domain: "gitnostr.com".to_string(),
            repository_whitelist: npub.clone(),
            repository_blacklist: npub.clone(),
            ..Config::for_testing()
        };

        let result = validate_announcement(&event, &config);
        assert!(matches!(result, AnnouncementResult::Reject(_)));
    }

    #[test]
    fn test_blacklist_overrides_archive_whitelist() {
        use crate::config::Config;
        use crate::nostr::policy::AnnouncementResult;

        let keys = create_test_keys();
        let npub = keys.public_key().to_bech32().unwrap();

        // Create announcement that does NOT list our service
        let event = create_announcement_event(
            &keys,
            "test-repo",
            vec!["https://other-service.com/alice/test-repo.git"],
            vec!["wss://other-service.com"],
        );

        // Config with archive whitelist and blacklist - blacklist should win
        let config = Config {
            domain: "gitnostr.com".to_string(),
            archive_whitelist: npub.clone(),
            archive_read_only: Some(false),
            repository_blacklist: npub.clone(),
            ..Config::for_testing()
        };

        let result = validate_announcement(&event, &config);
        assert!(matches!(result, AnnouncementResult::Reject(_)));
    }

    #[test]
    fn test_blacklist_allows_non_blacklisted() {
        use crate::config::Config;
        use crate::nostr::policy::AnnouncementResult;

        let keys = create_test_keys();

        // Create announcement that lists our service
        let event = create_announcement_event(
            &keys,
            "allowed-repo",
            vec!["https://gitnostr.com/alice/allowed-repo.git"],
            vec!["wss://gitnostr.com"],
        );

        // Config with blacklist for different identifier
        let config = Config {
            domain: "gitnostr.com".to_string(),
            repository_blacklist: "banned-repo".to_string(),
            ..Config::for_testing()
        };

        let result = validate_announcement(&event, &config);
        assert!(matches!(result, AnnouncementResult::Accept));
    }

    // -------------------------------------------------------------------------
    // validate_identifier tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_validate_identifier_valid() {
        assert!(validate_identifier("my-repo").is_ok());
        assert!(validate_identifier("my_repo").is_ok());
        assert!(validate_identifier("repo123").is_ok());
        assert!(validate_identifier("kuboslopp").is_ok());
        // Whitespace is valid — identifiers are stored verbatim on disk and
        // percent-encoded when used in URLs (NIP-34 / GRASP-01)
        assert!(validate_identifier("kuboslopp by Shakespeare").is_ok());
        assert!(validate_identifier("my\trepo").is_ok());
        assert!(validate_identifier("my repo").is_ok());
    }

    #[test]
    fn test_validate_identifier_rejects_empty() {
        assert!(validate_identifier("").is_err());
    }

    #[test]
    fn test_validate_identifier_rejects_dot_components() {
        assert!(validate_identifier(".").is_err());
        assert!(validate_identifier("..").is_err());
    }

    #[test]
    fn test_validate_identifier_rejects_path_separators() {
        assert!(validate_identifier("foo/bar").is_err());
        assert!(validate_identifier("foo\\bar").is_err());
    }

    #[test]
    fn test_validate_announcement_accepts_identifier_with_spaces() {
        use crate::config::Config;
        use crate::nostr::policy::AnnouncementResult;

        let keys = create_test_keys();
        // Identifier contains spaces — valid per NIP-34; must be percent-encoded in URLs
        let event = create_announcement_event(
            &keys,
            "kuboslopp by Shakespeare",
            vec!["https://gitnostr.com/alice/kuboslopp%20by%20Shakespeare.git"],
            vec!["wss://gitnostr.com"],
        );

        let config = Config {
            domain: "gitnostr.com".to_string(),
            ..Config::for_testing()
        };
        let result = validate_announcement(&event, &config);
        assert!(
            matches!(result, AnnouncementResult::Accept),
            "Expected Accept for identifier with spaces, got {:?}",
            result
        );
    }
}
