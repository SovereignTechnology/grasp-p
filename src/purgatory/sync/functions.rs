//! Core sync functions for identifier-based purgatory synchronization.
//!
//! This module provides the two main functions that both the main sync loop
//! and `DomainThrottle` queue processing use:
//!
//! - [`sync_identifier_next_url`]: Pure URL selection logic - finds next URL to try
//! - [`sync_identifier_from_url`]: Pure fetch logic - fetches from a specific URL
//!
//! The separation enables:
//! - Main sync loop to try non-throttled URLs immediately
//! - DomainThrottle to process queued identifiers when capacity frees
//! - Clean testability with mocked SyncContext

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::debug;

use super::context::SyncContext;
use super::throttle::ThrottleManager;
use crate::sync::naughty_list::NaughtyListTracker;

/// Extract domain from a URL.
///
/// Supports HTTP(S) URLs. SSH URLs (git@...) are not supported.
///
/// # Examples
///
/// ```ignore
/// assert_eq!(extract_domain("https://github.com/foo/bar.git"), Some("github.com".to_string()));
/// assert_eq!(extract_domain("http://example.com:8080/repo.git"), Some("example.com".to_string()));
/// assert_eq!(extract_domain("git@github.com:foo/bar.git"), None); // SSH URLs not supported
/// ```
pub(crate) fn extract_domain(url: &str) -> Option<String> {
    // Simple URL parsing for HTTP(S) URLs
    // Format: scheme://[user@]host[:port]/path
    let url = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;

    // Remove user info if present (e.g., "user@host" -> "host")
    let url = url.split('@').next_back()?;

    // Extract host (before first '/' or ':')
    let host = url.split('/').next()?;
    let host = host.split(':').next()?;

    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Find the next URL to try for an identifier.
///
/// This is pure URL selection logic with no side effects. It:
/// 1. Checks if there are pending events for the identifier
/// 2. Checks if there are OIDs still needed
/// 3. Gets repository data and extracts clone URLs
/// 4. Filters out our own domain and already-tried URLs
/// 5. Filters out naughty domains (with persistent SSL/DNS errors)
/// 6. Returns the first non-throttled URL (when `domain` is None)
///    or a URL from the specified domain (when `domain` is Some)
///
/// # Arguments
///
/// * `ctx` - The sync context providing repository data and OID information
/// * `identifier` - The repository identifier (d-tag value)
/// * `domain` - If Some, only return URLs from this specific domain.
///   If None, return any non-throttled URL.
/// * `tried_urls` - URLs that have already been tried (will be skipped)
/// * `throttle_manager` - Used to check if domains are throttled (when domain is None)
/// * `git_naughty_list` - Used to filter out domains with persistent errors
///
/// # Returns
///
/// * `Some(url)` - The next URL to try
/// * `None` - No suitable URL found (all tried, all throttled, or no URLs available)
pub async fn sync_identifier_next_url<C: SyncContext + ?Sized>(
    ctx: &C,
    identifier: &str,
    domain: Option<&str>,
    tried_urls: &HashSet<String>,
    throttle_manager: &ThrottleManager,
    git_naughty_list: &NaughtyListTracker,
) -> Option<String> {
    // 1. Check if we still have pending events
    if !ctx.has_pending_events(identifier) {
        debug!(
            identifier = %identifier,
            "No pending events - skipping URL selection"
        );
        return None;
    }

    // 2. Collect needed OIDs
    let needed_oids = ctx.collect_needed_oids(identifier);
    if needed_oids.is_empty() {
        debug!(
            identifier = %identifier,
            "No OIDs needed - sync is complete"
        );
        return None;
    }

    // 3. Get repository data
    let repo_data = match ctx.fetch_repository_data_with_purgatory(identifier).await {
        Ok(data) => data,
        Err(e) => {
            debug!(
                identifier = %identifier,
                error = %e,
                "Failed to fetch repository data"
            );
            return None;
        }
    };

    // 4. Collect clone URLs from announcements AND PR events in purgatory
    let our_domain = ctx.our_domain();

    // Get clone URLs from repository announcements
    let announcement_urls: HashSet<String> = repo_data
        .announcements
        .iter()
        .flat_map(|a| a.clone_urls.iter().cloned())
        .collect();

    // Get clone URLs from PR events in purgatory
    let pr_urls = ctx.collect_pr_clone_urls(identifier);

    // Merge and filter out our domain (exact host:port match, not substring)
    let all_urls: HashSet<String> = announcement_urls
        .union(&pr_urls)
        .filter(|url| {
            our_domain.is_none_or(|d| !crate::outbound::url_matches_service_domain(url, d))
        })
        .cloned()
        .collect();

    if all_urls.is_empty() {
        debug!(
            identifier = %identifier,
            "No clone URLs available (after filtering our domain)"
        );
        return None;
    }

    // 5. Group by domain
    let urls_by_domain: HashMap<String, Vec<String>> =
        all_urls.iter().fold(HashMap::new(), |mut acc, url| {
            if let Some(d) = extract_domain(url) {
                acc.entry(d).or_default().push(url.clone());
            }
            acc
        });

    // 6. Find an available URL
    match domain {
        Some(specific_domain) => {
            // Only look at URLs from this specific domain
            urls_by_domain
                .get(specific_domain)
                .and_then(|urls| urls.iter().find(|url| !tried_urls.contains(*url)).cloned())
        }
        None => {
            // Try any non-throttled, non-naughty domain
            for (d, domain_urls) in &urls_by_domain {
                if throttle_manager.is_throttled(d) {
                    debug!(
                        identifier = %identifier,
                        domain = %d,
                        "Domain is throttled - skipping"
                    );
                    continue;
                }

                // NEW: Skip naughty domains
                if git_naughty_list.is_naughty(d) {
                    debug!(
                        identifier = %identifier,
                        domain = %d,
                        "Domain is on git naughty list - skipping"
                    );
                    continue;
                }

                if let Some(url) = domain_urls.iter().find(|url| !tried_urls.contains(*url)) {
                    return Some(url.clone());
                }
            }
            None
        }
    }
}

/// Information about throttled domains with untried URLs.
///
/// Used by the main sync loop to know which `DomainThrottle` queues
/// to add the identifier to when it can't complete immediately.
#[derive(Debug, Clone)]
pub struct ThrottledDomainInfo {
    /// The throttled domain name
    pub domain: String,
    /// URLs from this domain that have already been tried
    pub tried_urls_for_domain: HashSet<String>,
}

/// Get information about throttled domains that have untried URLs.
///
/// Called by main sync loop to know which `DomainThrottle` queues to add
/// the identifier to when non-throttled URLs are exhausted.
///
/// # Arguments
///
/// * `ctx` - The sync context providing repository data
/// * `identifier` - The repository identifier
/// * `tried_urls` - All URLs that have been tried (across all domains)
/// * `throttle_manager` - Used to check which domains are throttled
/// * `git_naughty_list` - Used to filter out domains with persistent errors
///
/// # Returns
///
/// A list of throttled domains that still have untried URLs, along with
/// the tried URLs for each domain (for proper queue state).
pub async fn get_throttled_domains_with_untried_urls<C: SyncContext + ?Sized>(
    ctx: &C,
    identifier: &str,
    tried_urls: &HashSet<String>,
    throttle_manager: &ThrottleManager,
    git_naughty_list: &NaughtyListTracker,
) -> Vec<ThrottledDomainInfo> {
    let repo_data = match ctx.fetch_repository_data_with_purgatory(identifier).await {
        Ok(data) => data,
        Err(_) => return vec![],
    };

    let our_domain = ctx.our_domain();

    // Get clone URLs from repository announcements
    let announcement_urls: HashSet<String> = repo_data
        .announcements
        .iter()
        .flat_map(|a| a.clone_urls.iter().cloned())
        .collect();

    // Get clone URLs from PR events in purgatory
    let pr_urls = ctx.collect_pr_clone_urls(identifier);

    // Merge and filter out our domain (exact host:port match, not substring)
    let all_urls: HashSet<String> = announcement_urls
        .union(&pr_urls)
        .filter(|url| {
            our_domain.is_none_or(|d| !crate::outbound::url_matches_service_domain(url, d))
        })
        .cloned()
        .collect();

    let urls_by_domain: HashMap<String, Vec<String>> =
        all_urls.iter().fold(HashMap::new(), |mut acc, url| {
            if let Some(d) = extract_domain(url) {
                acc.entry(d).or_default().push(url.clone());
            }
            acc
        });

    urls_by_domain
        .into_iter()
        .filter_map(|(domain, domain_urls)| {
            if !throttle_manager.is_throttled(&domain) {
                return None; // Not throttled, skip
            }

            // Skip naughty domains
            if git_naughty_list.is_naughty(&domain) {
                return None; // On naughty list, skip
            }

            let untried: Vec<_> = domain_urls
                .iter()
                .filter(|url| !tried_urls.contains(*url))
                .collect();

            if untried.is_empty() {
                return None; // All URLs tried for this domain
            }

            // Collect tried URLs that belong to this domain
            let tried_urls_for_domain: HashSet<String> = tried_urls
                .iter()
                .filter(|url| extract_domain(url).as_deref() == Some(domain.as_str()))
                .cloned()
                .collect();

            Some(ThrottledDomainInfo {
                domain,
                tried_urls_for_domain,
            })
        })
        .collect()
}

/// Fetch git data from a specific URL for an identifier.
///
/// This function:
/// 1. Records the request with the throttle manager (for rate limiting)
/// 2. Performs the actual git fetch via the context
/// 3. Processes any events that can now be satisfied
/// 4. Records request completion
///
/// # Arguments
///
/// * `ctx` - The sync context providing fetch and processing capabilities
/// * `identifier` - The repository identifier
/// * `url` - The remote URL to fetch from
/// * `throttle_manager` - Used to track request start/completion for rate limiting
///
/// # Returns
///
/// The number of OIDs successfully fetched (0 on failure)
pub async fn sync_identifier_from_url<C: SyncContext + ?Sized>(
    ctx: &C,
    identifier: &str,
    url: &str,
    throttle_manager: &Arc<ThrottleManager>,
) -> usize {
    let domain = match extract_domain(url) {
        Some(d) => d,
        None => {
            debug!(
                identifier = %identifier,
                url = %url,
                "Could not extract domain from URL"
            );
            return 0;
        }
    };

    // Get repository data for target repo path
    let repo_data = match ctx.fetch_repository_data_with_purgatory(identifier).await {
        Ok(data) => data,
        Err(e) => {
            debug!(
                identifier = %identifier,
                error = %e,
                "Failed to fetch repo data"
            );
            return 0;
        }
    };

    let target_repo = match ctx.find_target_repo(&repo_data) {
        Some(path) => path,
        None => {
            debug!(identifier = %identifier, "No target repo found");
            return 0;
        }
    };

    // Collect needed OIDs
    let needed_oids: Vec<String> = ctx.collect_needed_oids(identifier).into_iter().collect();
    if needed_oids.is_empty() {
        debug!(
            identifier = %identifier,
            "No OIDs needed - nothing to fetch"
        );
        return 0;
    }

    // Perform the fetch with throttle tracking
    throttle_manager.start_request(&domain);
    let fetch_result = ctx.fetch_oids(&target_repo, url, &needed_oids).await;
    throttle_manager.complete_request(&domain);

    let fetched_oids = match fetch_result {
        Ok(fetched) if !fetched.is_empty() => {
            debug!(
                identifier = %identifier,
                url = %url,
                oids_fetched = fetched.len(),
                "Fetch succeeded"
            );
            fetched
        }
        Ok(_) => {
            debug!(
                identifier = %identifier,
                url = %url,
                "Fetch returned no OIDs (not available on remote)"
            );
            vec![]
        }
        Err(e) => {
            debug!(
                identifier = %identifier,
                url = %url,
                error = %e,
                "Fetch failed"
            );
            vec![]
        }
    };

    // Try to process any events that can now be satisfied
    if !fetched_oids.is_empty() {
        let new_oids: HashSet<String> = fetched_oids.iter().cloned().collect();
        if let Err(e) = ctx
            .process_newly_available_git_data(&target_repo, &new_oids)
            .await
        {
            debug!(
                identifier = %identifier,
                error = %e,
                "Failed to process newly available git data"
            );
        }
    }

    fetched_oids.len()
}

/// Sync git data for an identifier.
///
/// This is the main orchestration function called by the sync loop. It:
/// 1. Tries all non-throttled, non-naughty URLs in sequence
/// 2. After each fetch, checks if sync is complete (no pending events or no needed OIDs)
/// 3. When no non-throttled URLs remain, enqueues with throttled domains for later processing
/// 4. Returns without waiting for throttled domains to complete
///
/// # Arguments
///
/// * `ctx` - The sync context providing repository data and OID information
/// * `identifier` - The repository identifier (d-tag value)
/// * `throttle_manager` - Used for rate limiting and domain queue management
/// * `git_naughty_list` - Used to filter out domains with persistent errors
///
/// # Returns
///
/// * `true` - Sync completed (no pending events or all OIDs fetched)
/// * `false` - Events remain in purgatory (will be retried after backoff, or processed
///   by throttled domain queues)
pub async fn sync_identifier<C: SyncContext + ?Sized>(
    ctx: &C,
    identifier: &str,
    throttle_manager: &Arc<ThrottleManager>,
    git_naughty_list: &NaughtyListTracker,
) -> bool {
    let mut tried_urls: HashSet<String> = HashSet::new();

    debug!(
        identifier = %identifier,
        "Starting sync for identifier"
    );

    // Try all non-throttled, non-naughty URLs
    loop {
        match sync_identifier_next_url(
            ctx,
            identifier,
            None,
            &tried_urls,
            throttle_manager,
            git_naughty_list,
        )
        .await
        {
            Some(url) => {
                debug!(
                    identifier = %identifier,
                    url = %url,
                    "Found non-throttled URL to try"
                );

                // Fetch from this URL
                sync_identifier_from_url(ctx, identifier, &url, throttle_manager).await;
                tried_urls.insert(url);

                // Check if sync is now complete
                if !ctx.has_pending_events(identifier) {
                    debug!(
                        identifier = %identifier,
                        "Sync complete - no pending events"
                    );
                    return true;
                }

                let needed_oids = ctx.collect_needed_oids(identifier);
                if needed_oids.is_empty() {
                    debug!(
                        identifier = %identifier,
                        "Sync complete - all OIDs available"
                    );
                    return true;
                }

                // Continue trying more URLs
            }
            None => {
                // No more non-throttled URLs available
                debug!(
                    identifier = %identifier,
                    tried_count = tried_urls.len(),
                    "No more non-throttled URLs available"
                );
                break;
            }
        }
    }

    // Check if we're done (no pending events or no needed OIDs)
    if !ctx.has_pending_events(identifier) {
        debug!(
            identifier = %identifier,
            "Sync complete after exhausting URLs - no pending events"
        );
        return true;
    }

    let needed_oids = ctx.collect_needed_oids(identifier);
    if needed_oids.is_empty() {
        debug!(
            identifier = %identifier,
            "Sync complete after exhausting URLs - all OIDs available"
        );
        return true;
    }

    // Enqueue with any throttled domains that have untried URLs
    let throttled_domains = get_throttled_domains_with_untried_urls(
        ctx,
        identifier,
        &tried_urls,
        throttle_manager,
        git_naughty_list,
    )
    .await;

    for info in throttled_domains {
        debug!(
            identifier = %identifier,
            domain = %info.domain,
            "Enqueueing identifier with throttled domain"
        );
        throttle_manager.enqueue_identifier(
            &info.domain,
            identifier.to_string(),
            info.tried_urls_for_domain,
        );
    }

    // Return false - events remain, will retry after backoff
    // (throttled domains will process independently)
    debug!(
        identifier = %identifier,
        "Sync incomplete - returning false for backoff"
    );
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::purgatory::sync::MockSyncContext;

    #[tokio::test]
    async fn next_url_skips_throttled_domains() {
        // Set up mock with URLs from two domains
        let mock = MockSyncContext::new()
            .with_urls(&[
                "https://github.com/foo/bar.git",
                "https://gitlab.com/foo/bar.git",
            ])
            .with_needed_oids(&["abc123"])
            .with_pending_events(true);

        // Create throttle manager and throttle github.com
        let throttle_manager = ThrottleManager::new(1, 100);
        let naughty_list = NaughtyListTracker::with_defaults();

        // Saturate github.com by starting a request
        throttle_manager.start_request("github.com");

        // Should return gitlab.com URL since github.com is throttled
        let tried_urls = HashSet::new();
        let result = sync_identifier_next_url(
            &mock,
            "test-repo",
            None,
            &tried_urls,
            &throttle_manager,
            &naughty_list,
        )
        .await;

        assert!(result.is_some());
        let url = result.unwrap();
        assert!(
            url.contains("gitlab.com"),
            "Expected gitlab.com URL, got: {}",
            url
        );
    }

    #[tokio::test]
    async fn next_url_skips_tried_urls() {
        // Set up mock with two URLs from same domain
        let mock = MockSyncContext::new()
            .with_urls(&[
                "https://github.com/foo/bar.git",
                "https://github.com/foo/bar2.git",
            ])
            .with_needed_oids(&["abc123"])
            .with_pending_events(true);

        let throttle_manager = ThrottleManager::new(5, 100);
        let naughty_list = NaughtyListTracker::with_defaults();

        // Mark first URL as tried
        let mut tried_urls = HashSet::new();
        tried_urls.insert("https://github.com/foo/bar.git".to_string());

        // Should return the second URL
        let result = sync_identifier_next_url(
            &mock,
            "test-repo",
            None,
            &tried_urls,
            &throttle_manager,
            &naughty_list,
        )
        .await;

        assert!(result.is_some());
        let url = result.unwrap();
        assert_eq!(url, "https://github.com/foo/bar2.git");
    }

    #[tokio::test]
    async fn next_url_returns_none_when_no_pending_events() {
        let mock = MockSyncContext::new()
            .with_urls(&["https://github.com/foo/bar.git"])
            .with_needed_oids(&["abc123"])
            .with_pending_events(false); // No pending events

        let throttle_manager = ThrottleManager::new(5, 100);
        let naughty_list = NaughtyListTracker::with_defaults();
        let tried_urls = HashSet::new();

        let result = sync_identifier_next_url(
            &mock,
            "test-repo",
            None,
            &tried_urls,
            &throttle_manager,
            &naughty_list,
        )
        .await;

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn next_url_returns_none_when_no_oids_needed() {
        let mock = MockSyncContext::new()
            .with_urls(&["https://github.com/foo/bar.git"])
            .with_needed_oids(&[]) // No OIDs needed
            .with_pending_events(true);

        let throttle_manager = ThrottleManager::new(5, 100);
        let naughty_list = NaughtyListTracker::with_defaults();
        let tried_urls = HashSet::new();

        let result = sync_identifier_next_url(
            &mock,
            "test-repo",
            None,
            &tried_urls,
            &throttle_manager,
            &naughty_list,
        )
        .await;

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn next_url_filters_our_domain() {
        let mock = MockSyncContext::new()
            .with_urls(&[
                "https://our-relay.com/foo/bar.git",
                "https://github.com/foo/bar.git",
            ])
            .with_needed_oids(&["abc123"])
            .with_pending_events(true)
            .with_our_domain("our-relay.com");

        let throttle_manager = ThrottleManager::new(5, 100);
        let naughty_list = NaughtyListTracker::with_defaults();
        let tried_urls = HashSet::new();

        let result = sync_identifier_next_url(
            &mock,
            "test-repo",
            None,
            &tried_urls,
            &throttle_manager,
            &naughty_list,
        )
        .await;

        assert!(result.is_some());
        let url = result.unwrap();
        assert!(
            url.contains("github.com"),
            "Expected github.com URL (our domain filtered), got: {}",
            url
        );
    }

    #[tokio::test]
    async fn next_url_with_specific_domain() {
        let mock = MockSyncContext::new()
            .with_urls(&[
                "https://github.com/foo/bar.git",
                "https://gitlab.com/foo/bar.git",
            ])
            .with_needed_oids(&["abc123"])
            .with_pending_events(true);

        let throttle_manager = ThrottleManager::new(5, 100);
        let naughty_list = NaughtyListTracker::with_defaults();
        let tried_urls = HashSet::new();

        // Request specific domain
        let result = sync_identifier_next_url(
            &mock,
            "test-repo",
            Some("gitlab.com"),
            &tried_urls,
            &throttle_manager,
            &naughty_list,
        )
        .await;

        assert!(result.is_some());
        let url = result.unwrap();
        assert!(
            url.contains("gitlab.com"),
            "Expected gitlab.com URL, got: {}",
            url
        );
    }

    #[tokio::test]
    async fn from_url_fetches_and_processes_on_success() {
        // Set up mock that can provide the needed OID
        let mock = MockSyncContext::new()
            .with_urls(&["https://github.com/foo/bar.git"])
            .with_needed_oids(&["abc123"])
            .with_pending_events(true)
            .url_provides("https://github.com/foo/bar.git", &["abc123"]);

        let throttle_manager = Arc::new(ThrottleManager::new(5, 100));

        // Fetch from the URL
        let fetched = sync_identifier_from_url(
            &mock,
            "test-repo",
            "https://github.com/foo/bar.git",
            &throttle_manager,
        )
        .await;

        // Should have fetched 1 OID
        assert_eq!(fetched, 1);

        // Should have logged the fetch attempt
        let fetch_log = mock.fetch_log();
        assert_eq!(fetch_log.len(), 1);
        assert_eq!(fetch_log[0], "https://github.com/foo/bar.git");

        // OID should no longer be needed
        assert!(mock.current_needed_oids().is_empty());
    }

    #[tokio::test]
    async fn from_url_returns_zero_on_failure() {
        let mock = MockSyncContext::new()
            .with_urls(&["https://bad-server.com/repo.git"])
            .with_needed_oids(&["abc123"])
            .with_pending_events(true)
            .url_should_fail("https://bad-server.com/repo.git");

        let throttle_manager = Arc::new(ThrottleManager::new(5, 100));

        let fetched = sync_identifier_from_url(
            &mock,
            "test-repo",
            "https://bad-server.com/repo.git",
            &throttle_manager,
        )
        .await;

        // Should return 0 on failure
        assert_eq!(fetched, 0);

        // OID should still be needed
        assert!(mock.current_needed_oids().contains("abc123"));
    }

    #[tokio::test]
    async fn from_url_tracks_throttle_requests() {
        let mock = MockSyncContext::new()
            .with_urls(&["https://github.com/foo/bar.git"])
            .with_needed_oids(&["abc123"])
            .with_pending_events(true)
            .url_provides("https://github.com/foo/bar.git", &["abc123"]);

        let throttle_manager = Arc::new(ThrottleManager::new(1, 100));

        // First request should work
        let fetched = sync_identifier_from_url(
            &mock,
            "test-repo",
            "https://github.com/foo/bar.git",
            &throttle_manager,
        )
        .await;
        assert_eq!(fetched, 1);

        // After completion, domain should not be throttled
        assert!(!throttle_manager.is_throttled("github.com"));
    }

    #[tokio::test]
    async fn get_throttled_domains_returns_only_throttled_with_untried() {
        let mock = MockSyncContext::new()
            .with_urls(&[
                "https://github.com/foo/bar.git",
                "https://gitlab.com/foo/bar.git",
                "https://bitbucket.org/foo/bar.git",
            ])
            .with_needed_oids(&["abc123"])
            .with_pending_events(true);

        let throttle_manager = ThrottleManager::new(1, 100);
        let naughty_list = NaughtyListTracker::with_defaults();

        // Throttle github.com and gitlab.com
        throttle_manager.start_request("github.com");
        throttle_manager.start_request("gitlab.com");

        // Mark github.com URL as already tried
        let mut tried_urls = HashSet::new();
        tried_urls.insert("https://github.com/foo/bar.git".to_string());

        let throttled = get_throttled_domains_with_untried_urls(
            &mock,
            "test-repo",
            &tried_urls,
            &throttle_manager,
            &naughty_list,
        )
        .await;

        // Should only include gitlab.com (throttled with untried URLs)
        // github.com is throttled but URL was tried
        // bitbucket.org is not throttled
        assert_eq!(throttled.len(), 1);
        assert_eq!(throttled[0].domain, "gitlab.com");
        assert!(throttled[0].tried_urls_for_domain.is_empty());
    }

    // =========================================================================
    // Phase 6: sync_identifier tests
    // =========================================================================

    #[tokio::test]
    async fn sync_identifier_tries_multiple_urls_until_complete() {
        // Set up mock with 3 URLs, each providing partial OIDs
        // URL1 provides abc123, URL2 provides def456, URL3 provides ghi789
        let mock = MockSyncContext::new()
            .with_urls(&[
                "https://server1.com/repo.git",
                "https://server2.com/repo.git",
                "https://server3.com/repo.git",
            ])
            .with_needed_oids(&["abc123", "def456", "ghi789"])
            .with_pending_events(true)
            .url_provides("https://server1.com/repo.git", &["abc123"])
            .url_provides("https://server2.com/repo.git", &["def456"])
            .url_provides("https://server3.com/repo.git", &["ghi789"]);

        let throttle_manager = Arc::new(ThrottleManager::new(5, 100));
        let naughty_list = NaughtyListTracker::with_defaults();

        // Run sync_identifier
        let complete = sync_identifier(&mock, "test-repo", &throttle_manager, &naughty_list).await;

        // Should return true (sync complete)
        assert!(complete, "Expected sync to complete after trying all URLs");

        // Should have tried all 3 URLs
        let fetch_log = mock.fetch_log();
        assert_eq!(
            fetch_log.len(),
            3,
            "Expected 3 fetch attempts, got: {:?}",
            fetch_log
        );

        // All OIDs should now be fetched
        assert!(
            mock.current_needed_oids().is_empty(),
            "Expected all OIDs to be fetched"
        );
    }

    #[tokio::test]
    async fn sync_identifier_enqueues_throttled_domains_when_incomplete() {
        // Set up mock with URLs from two domains
        // Only github.com can provide the OID, but it will be throttled
        let mock = MockSyncContext::new()
            .with_urls(&[
                "https://github.com/foo/bar.git",
                "https://gitlab.com/foo/bar.git",
            ])
            .with_needed_oids(&["abc123"])
            .with_pending_events(true)
            .url_provides("https://github.com/foo/bar.git", &["abc123"]);
        // Note: gitlab.com doesn't provide any OIDs

        let throttle_manager = Arc::new(ThrottleManager::new(1, 100));
        let naughty_list = NaughtyListTracker::with_defaults();

        // Throttle github.com by starting a request
        throttle_manager.start_request("github.com");

        // Run sync_identifier
        let complete = sync_identifier(&mock, "test-repo", &throttle_manager, &naughty_list).await;

        // Should return false (sync incomplete - github.com is throttled)
        assert!(
            !complete,
            "Expected sync to be incomplete when required domain is throttled"
        );

        // Should have tried gitlab.com (not throttled) but it doesn't have the OID
        let fetch_log = mock.fetch_log();
        assert_eq!(
            fetch_log.len(),
            1,
            "Expected 1 fetch attempt (gitlab.com), got: {:?}",
            fetch_log
        );
        assert!(
            fetch_log[0].contains("gitlab.com"),
            "Expected gitlab.com to be tried first"
        );

        // OID should still be needed
        assert!(
            mock.current_needed_oids().contains("abc123"),
            "Expected OID to still be needed"
        );

        // github.com should have the identifier enqueued
        // We can verify this by checking if github.com is still throttled (it should be,
        // since the identifier was enqueued but not processed yet)
        assert!(
            throttle_manager.is_throttled("github.com"),
            "Expected github.com to still be throttled"
        );
    }

    // =========================================================================
    // PR Clone URL Tests
    // =========================================================================

    #[tokio::test]
    async fn test_collect_pr_clone_urls_returns_configured_urls() {
        // Test that MockSyncContext returns configured PR clone URLs
        let mock = MockSyncContext::new().with_pr_clone_urls(&[
            "https://pr-server.com/fork.git",
            "https://another-server.com/fork.git",
        ]);

        let pr_urls = mock.collect_pr_clone_urls("test-repo");

        assert_eq!(pr_urls.len(), 2);
        assert!(pr_urls.contains("https://pr-server.com/fork.git"));
        assert!(pr_urls.contains("https://another-server.com/fork.git"));
    }

    #[tokio::test]
    async fn test_sync_identifier_next_url_includes_pr_clone_urls() {
        // Set up mock with announcement URLs and PR clone URLs
        let mock = MockSyncContext::new()
            .with_urls(&["https://github.com/owner/repo.git"]) // From announcement
            .with_pr_clone_urls(&["https://pr-author.com/fork.git"]) // From PR event
            .with_needed_oids(&["abc123"])
            .with_pending_events(true);

        let throttle_manager = ThrottleManager::new(5, 100);
        let naughty_list = NaughtyListTracker::with_defaults();
        let tried_urls = HashSet::new();

        // Get first URL
        let first_url = sync_identifier_next_url(
            &mock,
            "test-repo",
            None,
            &tried_urls,
            &throttle_manager,
            &naughty_list,
        )
        .await
        .expect("Should return a URL");

        // Try the first URL
        let mut tried = HashSet::new();
        tried.insert(first_url.clone());

        // Get second URL
        let second_url = sync_identifier_next_url(
            &mock,
            "test-repo",
            None,
            &tried,
            &throttle_manager,
            &naughty_list,
        )
        .await
        .expect("Should return a second URL");

        // Both URLs should be available (one from announcement, one from PR)
        let both_urls = [first_url, second_url];
        assert!(
            both_urls.iter().any(|u| u.contains("github.com")),
            "Should include announcement URL"
        );
        assert!(
            both_urls.iter().any(|u| u.contains("pr-author.com")),
            "Should include PR clone URL"
        );
    }

    #[tokio::test]
    async fn test_pr_clone_urls_filtered_by_our_domain() {
        // Set up mock with PR clone URL pointing to our domain
        let mock = MockSyncContext::new()
            .with_urls(&["https://github.com/owner/repo.git"])
            .with_pr_clone_urls(&[
                "https://our-relay.com/fork.git", // Should be filtered
                "https://external.com/fork.git",  // Should be included
            ])
            .with_our_domain("our-relay.com")
            .with_needed_oids(&["abc123"])
            .with_pending_events(true);

        let throttle_manager = ThrottleManager::new(5, 100);
        let naughty_list = NaughtyListTracker::with_defaults();
        let mut tried_urls = HashSet::new();

        // Collect all available URLs
        let mut available_urls = Vec::new();
        while let Some(url) = sync_identifier_next_url(
            &mock,
            "test-repo",
            None,
            &tried_urls,
            &throttle_manager,
            &naughty_list,
        )
        .await
        {
            available_urls.push(url.clone());
            tried_urls.insert(url);
        }

        // Should have 2 URLs (github.com and external.com), not 3
        assert_eq!(
            available_urls.len(),
            2,
            "Expected 2 URLs after filtering our domain, got: {:?}",
            available_urls
        );

        // our-relay.com should be filtered out
        assert!(
            !available_urls.iter().any(|u| u.contains("our-relay.com")),
            "Our domain should be filtered out"
        );

        // github.com and external.com should be present
        assert!(
            available_urls.iter().any(|u| u.contains("github.com")),
            "github.com should be present"
        );
        assert!(
            available_urls.iter().any(|u| u.contains("external.com")),
            "external.com should be present"
        );
    }

    #[tokio::test]
    async fn test_get_throttled_domains_includes_pr_clone_urls() {
        // Set up mock with throttled PR clone URL domain
        let mock = MockSyncContext::new()
            .with_urls(&["https://github.com/owner/repo.git"])
            .with_pr_clone_urls(&["https://pr-server.com/fork.git"])
            .with_needed_oids(&["abc123"])
            .with_pending_events(true);

        let throttle_manager = ThrottleManager::new(1, 100);
        let naughty_list = NaughtyListTracker::with_defaults();

        // Throttle both domains
        throttle_manager.start_request("github.com");
        throttle_manager.start_request("pr-server.com");

        let tried_urls = HashSet::new();

        let throttled = get_throttled_domains_with_untried_urls(
            &mock,
            "test-repo",
            &tried_urls,
            &throttle_manager,
            &naughty_list,
        )
        .await;

        // Should include both throttled domains
        let domains: Vec<&str> = throttled.iter().map(|t| t.domain.as_str()).collect();
        assert!(domains.contains(&"github.com"), "Should include github.com");
        assert!(
            domains.contains(&"pr-server.com"),
            "Should include pr-server.com from PR clone URLs"
        );
    }

    #[tokio::test]
    async fn test_sync_identifier_uses_pr_clone_urls_when_announcement_urls_fail() {
        // Set up mock where only PR clone URL can provide the needed OID
        let mock = MockSyncContext::new()
            .with_urls(&["https://github.com/owner/repo.git"]) // Doesn't have the OID
            .with_pr_clone_urls(&["https://pr-author.com/fork.git"]) // Has the OID
            .with_needed_oids(&["pr-commit-123"])
            .with_pending_events(true)
            .url_provides("https://pr-author.com/fork.git", &["pr-commit-123"]);
        // Note: github.com doesn't provide any OIDs

        let throttle_manager = Arc::new(ThrottleManager::new(5, 100));
        let naughty_list = NaughtyListTracker::with_defaults();

        // Run sync_identifier
        let complete = sync_identifier(&mock, "test-repo", &throttle_manager, &naughty_list).await;

        // Should complete successfully using PR clone URL
        assert!(complete, "Sync should complete using PR clone URL");

        // Verify PR clone URL was tried
        let fetch_log = mock.fetch_log();
        assert!(
            fetch_log.iter().any(|u| u.contains("pr-author.com")),
            "PR clone URL should have been tried: {:?}",
            fetch_log
        );

        // OID should be fetched
        assert!(
            mock.current_needed_oids().is_empty(),
            "OID should be fetched from PR clone URL"
        );
    }
}
