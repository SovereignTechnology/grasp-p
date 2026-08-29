//! Test fixture management for dual-mode testing
//!
//! This module provides a TestContext abstraction that manages prerequisite events
//! differently based on the audit mode:
//!
//! - **Isolated Mode**: Creates fresh events for each test, ensuring complete isolation.
//!   Use this for `cargo test` where tests run in parallel and need isolation.
//! - **Shared Mode**: Reuses shared fixtures across tests to minimize event publication.
//!   Use this for CLI audit where tests run sequentially and build on each other.
//!
//! # Cache Sharing Strategy
//!
//! The caching behavior depends on the mode:
//!
//! - **Shared mode** (default for CLI): Uses the client's fixture cache, shared across
//!   all TestContext instances. Fixtures are created once and reused.
//! - **Isolated mode**: Each TestContext has its own local cache. Fixtures are created
//!   fresh for each TestContext, providing complete test isolation.
//!
//! # When to Use Each Mode
//!
//! - **CLI audit tool**: Use Shared mode (default). Tests run sequentially and fixtures
//!   build on each other efficiently.
//! - **cargo test**: Use Isolated mode. Tests run in parallel and need complete isolation.
//!
//! # What is a Fixture?
//! A fixture represents the state of a repository on a grasp server (events and git refs)
//! and/or nostr events to be sent to the server to change this state.
//!
//! Nearly all fixures include dependant fixtures so tests dont need to call every parent fixture.
//!
//! As entire tests are often fixtures to be built on by other fixtures / tests, some tests just take
//! the fixture Result and wrap it in pass fail using the error message.
//!
//! # Out of Scope
//!
//! local repo's used in tests are always cloned fresh and never part of a fixture
//!
//! # Example
//!
//! ```no_run
//! use grasp_audit::*;
//!
//! # async fn example() -> anyhow::Result<()> {
//! let config = AuditConfig::shared();  // Use shared() for CLI, isolated() for cargo test
//! let client = AuditClient::new("ws://localhost:7000", config).await?;
//! let ctx = TestContext::new(&client);
//!
//! // Request a fixture - behavior depends on mode
//! let repo = ctx.get_fixture(FixtureKind::ValidRepoSent).await?;
//! # Ok(())
//! # }
//! ```

use crate::{AuditClient, AuditMode};
use anyhow::{Context, Result};
use nostr_sdk::prelude::Event;
use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Deterministic commit hash used in RepoState fixtures (Owner variant)
/// This is the hash produced by creating a commit with:
/// - Message: "Initial commit"
/// - File: test.txt containing "Initial commit\n" (with trailing newline)
/// - Author date: 2024-01-01T00:00:00Z
/// - Committer date: 2024-01-01T00:00:00Z
/// - GPG signing: disabled
/// - User: "GRASP Audit Test <test@grasp-audit.local>"
/// - Parent: none (root commit)
pub const DETERMINISTIC_COMMIT_HASH: &str = "d6e4b26ccf9c268d18d60e6d09804313cc850821";

/// Deterministic commit hash for maintainer fixtures (Maintainer variant)
/// This is the hash produced by creating a commit with:
/// - Message: "Maintainer initial commit"
/// - File: test.txt containing "Maintainer initial commit\n" (with trailing newline)
/// - Author date: 2024-01-01T00:00:00Z
/// - Committer date: 2024-01-01T00:00:00Z
/// - GPG signing: disabled
/// - User: "GRASP Audit Test <test@grasp-audit.local>"
/// - Parent: none (root commit)
pub const MAINTAINER_DETERMINISTIC_COMMIT_HASH: &str = "d26703c007eff6d17fee3bb70ce8be5d1427d0e7";

/// Deterministic commit hash for recursive maintainer fixtures (RecursiveMaintainer variant)
/// This is the hash produced by creating a commit with:
/// - Message: "Recursive maintainer initial commit"
/// - File: test.txt containing "Recursive maintainer initial commit\n" (with trailing newline)
/// - Author date: 2024-01-01T00:00:00Z
/// - Committer date: 2024-01-01T00:00:00Z
/// - GPG signing: disabled
/// - User: "GRASP Audit Test <test@grasp-audit.local>"
/// - Parent: none (root commit)
pub const RECURSIVE_MAINTAINER_DETERMINISTIC_COMMIT_HASH: &str =
    "54a2b4b3cbc3373ad1438b8ffad1681d12bc6c4a";

/// Deterministic commit hash for PR test fixtures (PRTestCommit variant)
/// This is the hash produced by creating a commit with:
/// - Message: "PR test deterministic commit"
/// - File: test.txt containing "PR test deterministic commit\n" (with trailing newline)
/// - Author date: 2024-01-01T00:00:00Z
/// - Committer date: 2024-01-01T00:00:00Z
/// - GPG signing: disabled
/// - User: "GRASP Audit Test <test@grasp-audit.local>"
/// - Parent: none (root commit)
pub const PR_TEST_COMMIT_HASH: &str = "5a51b30e4615b572dcd5b9e487861b58605a5c21";

/// Deterministic commit hash for second PR test fixtures (PRTestCommit2 variant)
/// This is the hash produced by creating a commit with:
/// - Message: "PR test deterministic commit 2"
/// - File: test.txt containing "PR test deterministic commit 2\n" (with trailing newline)
/// - Author date: 2024-01-01T00:00:00Z
/// - Committer date: 2024-01-01T00:00:00Z
/// - GPG signing: disabled
/// - User: "GRASP Audit Test <test@grasp-audit.local>"
/// - Parent: none (root commit)
pub const PR_TEST_COMMIT_HASH_2: &str = "99420bc57835f5bc8ca20ab21a8d12850043920e";

// =============================================================================
// Generic `Fixture` trait (non-Event fixtures)
// =============================================================================

/// Type-erased cache for non-Event fixtures.
///
/// Keys are the `&'static str` returned by [`Fixture::cache_key`]. Two distinct
/// `Fixture` impls MUST NOT share a cache key unless they share an `Output`
/// type — the cache stores `Arc<dyn Any + Send + Sync>` and downcasts on read.
/// A key/type mismatch surfaces at runtime as a clear error from `TestContext::get`.
pub type TypedFixtureCache = Arc<Mutex<HashMap<&'static str, Arc<dyn Any + Send + Sync>>>>;

/// Generic fixture: a cached, possibly-asynchronously-built prerequisite that
/// is NOT a Nostr event.
///
/// Use this for things like the NIP-11 document, derived booleans, fetched
/// HTTP resources, etc. For Event-shaped fixtures with deep dependency chains
/// (repo announcements, state events, PRs, …) use [`FixtureKind`] and
/// [`TestContext::get_fixture`] — that system has dedicated dependency
/// resolution and is not going away.
///
/// # Caching
///
/// [`TestContext::get`] is mode-aware, matching the Event fixture system:
///
/// - **Shared mode**: cached on the [`AuditClient`] via
///   [`AuditClient::typed_fixture_cache`]. Reused across all `TestContext`
///   instances created from the same client.
/// - **Isolated mode**: cached per-`TestContext`. Fresh for each test.
///
/// # Implementing
///
/// ```no_run
/// use grasp_audit::*;
/// use anyhow::Result;
///
/// pub struct MyFixture;
///
/// impl Fixture for MyFixture {
///     type Output = String;
///     fn cache_key(&self) -> &'static str { "my_fixture" }
///     async fn build(&self, _ctx: &TestContext<'_>) -> Result<String> {
///         Ok("hello".to_string())
///     }
/// }
/// ```
///
/// # Cache-key contract
///
/// `cache_key` MUST be globally unique across all `Fixture` impls used in
/// this process, AND two impls sharing a key MUST share an `Output` type.
/// Violations surface as a clear anyhow error on the first cache hit of the
/// conflicting type. Convention: snake_case string derived from the impl's
/// module path, e.g. `"grasp06.nip11_document"`.
#[allow(async_fn_in_trait)]
pub trait Fixture: Send + Sync {
    /// The value this fixture produces. Must be `Clone` because each
    /// `TestContext::get` call clones the cached value out.
    type Output: Clone + Send + Sync + 'static;

    /// Stable, unique cache key. See the trait-level contract.
    fn cache_key(&self) -> &'static str;

    /// Build the value. Called at most once per cache scope (per-client in
    /// Shared mode, per-`TestContext` in Isolated mode).
    async fn build(&self, ctx: &TestContext<'_>) -> Result<Self::Output>;
}

/// Types of test fixtures available
///
/// ## Fixture Dependencies
///
/// Several fixtures depend on `ValidRepoSent` - they all use the SAME repo_id
/// within a single TestContext instance to ensure proper fixture relationships:
/// - `RepoState` → uses ValidRepoSent's repo_id
/// - `MaintainerAnnouncement` + `MaintainerState` → uses ValidRepoSent's repo_id
/// - `RecursiveMaintainerRepoAndState` → uses ValidRepoSent's repo_id
///
/// The legacy `RecursiveMaintainer` fixture name denotes a transitive case.
/// Its announcements are reciprocal, so it tests confirmed membership rather
/// than authority from unilateral recursive listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FixtureKind {
    /// Basic repository announcement (kind 30617)
    /// - Signed by owner keys (`client.keys()`)
    /// - Lists `client.maintainer_pubkey_hex()` in maintainers tag
    ValidRepoSent,

    /// Repository announcement that is queryable from the relay (served, not in purgatory)
    /// - Depends on OwnerStateDataPushed (git data pushed, announcement promoted)
    /// - Returns the same event as ValidRepoSent (now queryable)
    /// - Use this for tests that need to query the announcement back from the relay
    ValidRepoServed,

    /// Repository with one issue (kind 1621)
    /// - Requires ValidRepoServed (needs queryable repo for issue to reference)
    RepoWithIssue,

    /// Repository with issue and comment (kind 1111)
    /// - Requires RepoWithIssue (reuses same repo_id)
    RepoWithComment,

    /// Repository state announcement (kind 30618) for owner
    /// - Requires ValidRepoSent (uses same repo_id)
    /// - Signed by owner keys (`client.keys()`)
    /// - Points to DETERMINISTIC_COMMIT_HASH
    /// - Timestamp: 10 seconds in the past
    RepoState,

    /// Owner's repository state announcement (kind 30618) sent to relay and accepted into purgatory
    ///
    /// This is the "sent" stage: the state event has been published to the relay and
    /// accepted (OK response), but no git data has been pushed yet so it remains in
    /// purgatory and is not served to clients.
    ///
    /// Use this when you need the state event to exist on the relay but do not need
    /// the full push/serve cycle. For the complete cycle (git pushed + verified served),
    /// use `OwnerStateDataPushed`.
    ///
    /// - Requires ValidRepoSent (uses same repo_id)
    /// - Signed by owner keys (`client.keys()`)
    /// - Points to DETERMINISTIC_COMMIT_HASH
    /// - Timestamp: 10 seconds in the past
    OwnerRepoStateSent,

    /// PR (Pull Request) event for the SAME repo_id as ValidRepoServed
    /// - Requires ValidRepoServed (uses same repo_id, needs queryable repo)
    /// - Signed by `client.pr_author_keys()`
    /// - Kind 1618 (NIP-34 PR)
    /// - Includes `a` tag referencing the repo
    /// - Includes `c` tag pointing to PR_TEST_COMMIT_HASH
    /// - Timestamp: 1 second in the past
    PREvent,

    /// PR event generated (built) but NOT sent to relay
    ///
    /// This is a "Generated" stage fixture - the event is created but not published.
    /// Useful for tests that need the PR event ID before the event exists on the relay.
    ///
    /// - Requires ValidRepoServed (uses same repo_id, needs queryable repo)
    /// - Signed by `client.pr_author_keys()`
    /// - Kind 1618 (NIP-34 PR)
    /// - Includes `c` tag pointing to PR_TEST_COMMIT_HASH
    /// - NOT sent to relay (use `client.send_event()` to publish when ready)
    PREventGenerated,

    /// HEAD set to 'develop' branch via state event
    ///
    /// This fixture tests that HEAD is updated when a state event is published
    /// with HEAD pointing to a different branch that already has git data pushed.
    ///
    /// GRASP-01: "MUST set repository HEAD per repository state announcement
    /// as soon as the git data related to that branch has been received."
    ///
    /// Stages:
    /// 1. **Depends on**: RecursiveMaintainerStateDataPushed (all git data exists on main)
    /// 2. **Creates**: New state event with HEAD=refs/heads/develop pointing to existing commit
    /// 3. **Sends**: State event to relay
    /// 4. **Verifies**: Can be checked via get_default_branch_from_info_refs
    ///
    /// - Requires RecursiveMaintainerStateDataPushed (establishes full maintainer chain with git data)
    /// - Creates state event signed by maintainer keys (`client.maintainer_keys()`)
    /// - Points refs/heads/develop to RECURSIVE_MAINTAINER_DETERMINISTIC_COMMIT_HASH
    /// - Sets HEAD to refs/heads/develop
    HeadSetToDevelopBranch,

    /// Wrong commit pushed to refs/nostr/<pr-event-id> BEFORE PR event is sent
    ///
    /// This is a "DataPushed" stage fixture for testing pre-event ref behavior.
    /// The server has refs/nostr/<pr-event-id> pointing to DETERMINISTIC_COMMIT_HASH
    /// (the "wrong" commit), but no PR event exists yet on the relay.
    ///
    /// Server state after this fixture:
    /// - ValidRepoServed announcement on relay (repo is queryable)
    /// - refs/nostr/<pr-event-id> exists on git server with wrong commit
    /// - PR event is NOT on relay (but returned for tests to publish later)
    ///
    /// - Requires PREventGenerated (for the event ID)
    /// - Clones repo, creates wrong commit, pushes to refs/nostr/<event-id>
    /// - Returns: the unsent PR event (tests can publish it later)
    PRWrongCommitPushedBeforeEvent,

    /// PR event sent to relay AFTER wrong commit was pushed to refs/nostr/<pr-event-id>
    ///
    /// This is a compound fixture testing post-event behavior.
    /// The server had refs/nostr/<pr-event-id> pointing to wrong commit,
    /// then the PR event was published (which may trigger cleanup).
    ///
    /// Server state after this fixture:
    /// - ValidRepoServed announcement on relay
    /// - PR event is on relay
    /// - refs/nostr/<pr-event-id> may have been cleaned up (that's what tests verify)
    ///
    /// - Requires PRWrongCommitPushedBeforeEvent
    /// - Sends the PR event to relay
    /// - Returns: the sent PR event
    PREventSentAfterWrongPush,

    /// Second PR event generated (built) but NOT sent to relay
    ///
    /// Uses PR_TEST_COMMIT_HASH_2 (different from PR_TEST_COMMIT_HASH).
    /// This allows testing purgatory mechanism with a separate PR event
    /// that doesn't conflict with existing PR fixtures.
    ///
    /// - Requires ValidRepoServed (uses same repo_id, needs git data to exist)
    /// - Signed by `client.pr_author_keys()`
    /// - Kind 1618 (NIP-34 PR)
    /// - Includes `c` tag pointing to PR_TEST_COMMIT_HASH_2
    /// - NOT sent to relay
    PREvent2Generated,

    /// Second PR event sent to relay (enters purgatory)
    ///
    /// After this fixture:
    /// - PR event is on relay but NOT served (in purgatory)
    /// - No git data at refs/nostr/<pr-event-id>
    ///
    /// - Requires PREvent2Generated
    /// - Sends the PR event to relay
    /// - Returns: the sent PR event (in purgatory)
    PREvent2Sent,

    /// Git data pushed for second PR event AFTER event was sent
    ///
    /// After this fixture:
    /// - PR event was in purgatory
    /// - Correct commit pushed to refs/nostr/<pr-event-id>
    /// - PR event should be released from purgatory
    ///
    /// - Requires PREvent2Sent
    /// - Pushes correct commit (PR_TEST_COMMIT_HASH_2) to refs/nostr/<pr-event-id>
    /// - Returns: the PR event (should now be served)
    PREvent2GitDataPushed,

    /// Full fixture: second PR event sent, git pushed, event served
    ///
    /// Combines PREvent2Sent + PREvent2GitDataPushed for convenience.
    ///
    /// - Requires PREvent2GitDataPushed
    /// - Returns: the served PR event
    PREvent2Served,

    /// Independent repo announcement, used exclusively by purgatory tests.
    ///
    /// Creates its own fresh repo announcement (unique repo_id) that is NOT shared with
    /// the main ValidRepoSent chain. The shared ValidRepoSent may already be promoted
    /// (served) by the time purgatory tests run if earlier specs triggered OwnerStateDataPushed.
    /// This fixture is never promoted by any other test, so the announcement stays in purgatory.
    ///
    /// - No dependencies
    /// - Sends its own announcement to the relay
    /// - Returns the repo announcement event (kind 30617)
    PurgatoryValidRepoSent,

    /// Independent owner state data pushed, used exclusively by purgatory tests.
    ///
    /// This fixture creates its own completely independent repo (fresh UUID, own announcement,
    /// own state event, own git push) that is NOT shared with the main OwnerStateDataPushed
    /// chain. It exists so that purgatory tests which mutate relay state (sending replacement
    /// announcements, new state events pointing to non-existent commits, etc.) do not corrupt
    /// the shared repo that push-authorization tests depend on.
    ///
    /// Stages (self-contained, no external dependencies):
    /// 1. Creates a fresh repo announcement with a unique repo_id
    /// 2. Creates and sends an owner state event (purgatory)
    /// 3. Pushes git data (DETERMINISTIC_COMMIT_HASH) to release from purgatory
    /// 4. Verifies state event is served
    ///
    /// - No dependencies (creates its own ValidRepoSent + OwnerStateDataPushed internally)
    /// - Returns the owner state event (kind 30618) after git data is pushed
    PurgatoryOwnerStateDataPushed,

    /// Owner's state event with git data successfully pushed (full 4-stage fixture)
    ///
    /// This fixture represents the complete flow for testing state push authorization:
    /// 1. **Generated**: Creates RepoState (repo announcement + state event)
    /// 2. **Sent**: Sends events to relay (returns OK, accepted but 'purgatory:...' message)
    /// 3. **Verify Not Served**: Confirms event is not served by relays
    /// 4. **DataPushed**: Clones repo, creates deterministic commit, pushes to relay
    /// 5. **Verified**: Confirms event is served by relay
    ///
    /// - Requires ValidRepoSent (uses same repo_id)
    /// - State event signed by owner keys (`client.keys()`)
    /// - Points to DETERMINISTIC_COMMIT_HASH
    /// - Git push verified to succeed (state matches pushed commit)
    OwnerStateDataPushed,

    /// Maintainer's state event with git data successfully pushed (full 5-stage fixture)
    ///
    /// This fixture tests that a reciprocally confirmed maintainer can
    /// authorize pushes. It publishes the maintainer's acknowledgment
    /// announcement before the State event.
    ///
    /// This fixture represents the complete flow for testing maintainer push authorization:
    /// 1. **OwnerStateDataPushed dependency**: Owner's repo and state event already on relay, git data pushed
    /// 2. **Sent**: Sends the reciprocal announcement, then the maintainer State event
    /// 3. **Verify Not Served**: Confirms event is not served by relays
    /// 4. **DataPushed**: Clones repo, creates maintainer deterministic commit, force-pushes to relay
    /// 5. **Verified**: Confirms event is served by relay
    ///
    /// - Requires OwnerStateDataPushed (owner's data already pushed to git)
    /// - State event signed by maintainer keys (`client.maintainer_keys()`)
    /// - Points to MAINTAINER_DETERMINISTIC_COMMIT_HASH
    /// - Git push verified to succeed (force push with maintainer's state event authorizes the commit)
    MaintainerStateDataPushed,

    /// Transitively confirmed maintainer's state event with git data pushed.
    ///
    /// The legacy fixture name says “recursive maintainer”; authority actually
    /// comes from reciprocal confirmation through the selected component. The
    /// additional maintainer is listed by the direct maintainer, not by the
    /// selected coordinate's author.
    ///
    /// This fixture represents the complete transitive-confirmation flow:
    /// 1. **Generated**: (MaintainerStateDataPushed dependency includes ValidRepoSent + OwnerStateDataPushed)
    ///    Creates the additional maintainer's reciprocal announcement and State event
    /// 2. **Sent**: Sends events to relay (returns OK, accepted but 'purgatory:...' message)
    /// 3. **Verify Not Served**: Confirms event is not served by relays
    /// 4. **DataPushed**: Clones repo, creates the additional maintainer's deterministic commit, pushes to relay
    /// 5. **Verified**: Confirms event is served by relay
    ///
    /// Component: selected author ↔ direct maintainer ↔ additional maintainer
    ///
    /// - Requires MaintainerStateDataPushed (establishes Owner -> Maintainer chain with git data)
    /// - State event signed by the legacy-named recursive maintainer keys (`client.recursive_maintainer_keys()`)
    /// - Points to RECURSIVE_MAINTAINER_DETERMINISTIC_COMMIT_HASH
    /// - Git push verified to succeed through transitively confirmed membership
    RecursiveMaintainerStateDataPushed,
}

impl FixtureKind {
    /// Get the fixture dependencies that must be ensured before this one
    ///
    /// Dependencies are processed in order and cached, so if a fixture
    /// depends on another that's already been created, it won't be recreated.
    pub fn dependencies(&self) -> Vec<FixtureKind> {
        match self {
            // Base fixtures - no dependencies
            Self::ValidRepoSent => vec![],

            // ValidRepoServed depends on OwnerStateDataPushed (announcement promoted after git push)
            Self::ValidRepoServed => vec![Self::OwnerStateDataPushed],

            // Fixtures that depend on ValidRepoServed (need queryable announcement)
            Self::RepoWithIssue => vec![Self::ValidRepoServed],
            Self::RepoState => vec![Self::ValidRepoSent],
            // OwnerRepoStateSent depends on ValidRepoSent: state event sent, sitting in purgatory
            Self::OwnerRepoStateSent => vec![Self::ValidRepoSent],
            Self::PREvent => vec![Self::ValidRepoServed],
            Self::PREventGenerated => vec![Self::ValidRepoServed],
            Self::PRWrongCommitPushedBeforeEvent => vec![Self::PREventGenerated],
            Self::PREventSentAfterWrongPush => vec![Self::PRWrongCommitPushedBeforeEvent],

            // Second PR event fixtures (for purgatory testing)
            Self::PREvent2Generated => vec![Self::ValidRepoServed],
            Self::PREvent2Sent => vec![Self::PREvent2Generated],
            Self::PREvent2GitDataPushed => vec![Self::PREvent2Sent],
            Self::PREvent2Served => vec![Self::PREvent2GitDataPushed],

            // PurgatoryValidRepoSent has no dependencies — creates its own fresh repo
            Self::PurgatoryValidRepoSent => vec![],

            // PurgatoryOwnerStateDataPushed depends on PurgatoryValidRepoSent
            Self::PurgatoryOwnerStateDataPushed => vec![Self::PurgatoryValidRepoSent],

            // OwnerStateDataPushed depends on OwnerRepoStateSent (git push + purgatory release)
            Self::OwnerStateDataPushed => vec![Self::OwnerRepoStateSent],

            // Fixtures that depend on RepoWithIssue
            Self::RepoWithComment => vec![Self::RepoWithIssue],

            // MaintainerStateDataPushed depends on OwnerStateDataPushed
            // (maintainer force-pushes over owner's data)
            Self::MaintainerStateDataPushed => vec![Self::OwnerStateDataPushed],

            // RecursiveMaintainerStateDataPushed depends on MaintainerStateDataPushed
            // (recursive maintainer force-pushes over maintainer's data)
            Self::RecursiveMaintainerStateDataPushed => vec![Self::MaintainerStateDataPushed],

            // HeadSetToDevelopBranch depends on RecursiveMaintainerStateDataPushed
            // (all git data already exists, we just publish a new state event)
            Self::HeadSetToDevelopBranch => vec![Self::RecursiveMaintainerStateDataPushed],
        }
    }

    /// Whether this fixture sends its own events to the relay
    ///
    /// Some fixtures (like DataPushed variants) handle event sending internally
    /// as part of their build process. For these, the generic ensure_fixture
    /// should NOT send the event again.
    pub fn sends_own_events(&self) -> bool {
        match self {
            // These fixtures send events and push git data internally
            Self::OwnerStateDataPushed => true,
            Self::MaintainerStateDataPushed => true,
            Self::RecursiveMaintainerStateDataPushed => true,
            // PREventGenerated builds but does NOT send the PR event (that's the point)
            Self::PREventGenerated => true,
            // PRWrongCommitPushedBeforeEvent pushes git data but doesn't send event
            Self::PRWrongCommitPushedBeforeEvent => true,
            // PREventSentAfterWrongPush sends the PR event internally
            Self::PREventSentAfterWrongPush => true,
            // Second PR event fixtures handle their own events/git data
            Self::PREvent2Generated => true,
            Self::PREvent2Sent => true,
            Self::PREvent2GitDataPushed => true,
            Self::PREvent2Served => true,
            // HeadSetToDevelopBranch sends its state event internally
            Self::HeadSetToDevelopBranch => true,
            // PurgatoryValidRepoSent sends its own announcement internally
            Self::PurgatoryValidRepoSent => true,
            // PurgatoryOwnerStateDataPushed sends its own state event and git push internally
            Self::PurgatoryOwnerStateDataPushed => true,
            // ValidRepoServed doesn't send anything itself, just returns cached event
            Self::ValidRepoServed => true,
            // OwnerRepoStateSent sends its state event and notes purgatory internally
            Self::OwnerRepoStateSent => true,
            // All other fixtures return a single event for the caller to send
            _ => false,
        }
    }
}

/// Context mode for fixture management
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextMode {
    /// Create fresh fixtures for each request (test isolation)
    Isolated,

    /// Reuse shared fixtures across requests (minimal events)
    Shared,
}

impl From<AuditMode> for ContextMode {
    fn from(mode: AuditMode) -> Self {
        match mode {
            AuditMode::Isolated => ContextMode::Isolated,
            AuditMode::Shared => ContextMode::Shared,
        }
    }
}

/// Test context for managing prerequisite events
///
/// The TestContext provides mode-aware fixture management:
/// - In **Isolated mode**: Each TestContext has its own local cache, creating fresh
///   fixtures for each test. Use this for `cargo test` where tests run in parallel.
/// - In **Shared mode**: Uses the client's fixture cache, shared across all TestContexts.
///   Use this for CLI audit where tests run sequentially and build on each other.
///
/// # Mode Selection
///
/// The mode is determined by `AuditConfig::mode`:
/// - `AuditConfig::isolated()` → Creates fresh fixtures per TestContext
/// - `AuditConfig::shared()` → Reuses fixtures across all TestContexts (default for CLI)
///
/// # Example
///
/// ```no_run
/// # use grasp_audit::*;
/// # async fn example() -> anyhow::Result<()> {
/// // For CLI audit (shared fixtures - default)
/// let config = AuditConfig::shared();
/// let client = AuditClient::new("ws://localhost:7000", config).await?;
/// let ctx = TestContext::new(&client);
///
/// // Get a repository fixture - will be reused by subsequent TestContexts
/// let repo = ctx.get_fixture(FixtureKind::ValidRepoSent).await?;
///
/// // For cargo test (isolated fixtures)
/// let config = AuditConfig::isolated();
/// let client = AuditClient::new("ws://localhost:7000", config).await?;
/// let ctx = TestContext::new(&client);
///
/// // Get a repository fixture - fresh for this TestContext only
/// let repo = ctx.get_fixture(FixtureKind::ValidRepoSent).await?;
/// # Ok(())
/// # }
/// ```
pub struct TestContext<'a> {
    client: &'a AuditClient,
    mode: ContextMode,
    /// Per-TestContext cache for Isolated mode
    /// This cache ensures fixture dependencies work within a single test
    /// while maintaining isolation between tests.
    /// In Shared mode, this cache is not used - we use the client's cache instead.
    local_cache: Arc<Mutex<HashMap<FixtureKind, Event>>>,
    /// Per-TestContext typed cache for non-Event fixtures (Isolated mode only).
    /// In Shared mode this is unused; the client's `typed_fixture_cache` holds values.
    typed_local_cache: TypedFixtureCache,
}

impl<'a> TestContext<'a> {
    /// Create a new test context
    ///
    /// The context mode is automatically determined from the client's audit config.
    /// In Isolated mode, fixtures are cached per-TestContext to maintain fixture
    /// dependencies within a test while ensuring isolation between tests.
    /// In Shared mode, the client's cache is used for cross-test fixture sharing.
    pub fn new(client: &'a AuditClient) -> Self {
        let mode = ContextMode::from(client.config.mode);
        Self {
            client,
            mode,
            local_cache: Arc::new(Mutex::new(HashMap::new())),
            typed_local_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Create a test context with explicit mode override
    ///
    /// This is useful for testing the context itself or for advanced use cases
    /// where you want to override the default mode behavior.
    pub fn with_mode(client: &'a AuditClient, mode: ContextMode) -> Self {
        Self {
            client,
            mode,
            local_cache: Arc::new(Mutex::new(HashMap::new())),
            typed_local_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Get a fixture, creating it if needed based on mode
    ///
    /// This is an alias for `ensure_fixture` - the core method for fixture management.
    /// It automatically handles:
    /// - Mode-aware caching (Isolated vs Shared)
    /// - Dependency resolution
    /// - Event sending
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use grasp_audit::*;
    /// # async fn example(ctx: &TestContext<'_>) -> anyhow::Result<()> {
    /// let repo = ctx.get_fixture(FixtureKind::ValidRepoSent).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get_fixture(&self, kind: FixtureKind) -> Result<Event> {
        self.ensure_fixture(kind).await
    }

    /// Get a non-Event fixture via the generic [`Fixture`] trait.
    ///
    /// Mode-aware caching: reads/writes the client's `typed_fixture_cache` in
    /// Shared mode, or this context's `typed_local_cache` in Isolated mode.
    /// On cache miss, calls `fixture.build(self).await` exactly once and
    /// stores the result.
    ///
    /// # Errors
    ///
    /// - Propagates errors from `Fixture::build`.
    /// - Returns an error (does not panic) if two different `Fixture` impls
    ///   share a `cache_key` but produce different `Output` types and the
    ///   second hits the cache.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use grasp_audit::*;
    /// # use anyhow::Result;
    /// # struct MyFixture;
    /// # impl Fixture for MyFixture {
    /// #     type Output = String;
    /// #     fn cache_key(&self) -> &'static str { "my_fixture" }
    /// #     async fn build(&self, _ctx: &TestContext<'_>) -> Result<String> { Ok(String::new()) }
    /// # }
    /// # async fn example(ctx: &TestContext<'_>) -> Result<()> {
    /// let value = ctx.get(&MyFixture).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn get<F: Fixture>(&self, fixture: &F) -> Result<F::Output> {
        let key = fixture.cache_key();

        // 1. Read cache.
        let cached: Option<Arc<dyn Any + Send + Sync>> = match self.mode {
            ContextMode::Isolated => self.typed_local_cache.lock().unwrap().get(key).cloned(),
            ContextMode::Shared => self
                .client
                .typed_fixture_cache()
                .lock()
                .unwrap()
                .get(key)
                .cloned(),
        };

        if let Some(any_arc) = cached {
            let typed: Arc<F::Output> = any_arc.downcast::<F::Output>().map_err(|_| {
                anyhow::anyhow!(
                    "fixture cache type mismatch for key '{}' — two Fixture impls \
                     using the same cache_key with different Output types?",
                    key
                )
            })?;
            tracing::debug!("get(<Fixture key='{}'>) found in cache", key);
            return Ok((*typed).clone());
        }

        // 2. Build.
        let value = fixture.build(self).await?;

        // 3. Store. Note: we don't hold the lock across `await`.
        let any_arc: Arc<dyn Any + Send + Sync> = Arc::new(value.clone());
        match self.mode {
            ContextMode::Isolated => {
                self.typed_local_cache.lock().unwrap().insert(key, any_arc);
                tracing::debug!("get(<Fixture key='{}'>) stored in local cache", key);
            }
            ContextMode::Shared => {
                self.client
                    .typed_fixture_cache()
                    .lock()
                    .unwrap()
                    .insert(key, any_arc);
                tracing::debug!("get(<Fixture key='{}'>) stored in client cache", key);
            }
        }

        Ok(value)
    }

    /// Get the underlying client for direct access
    ///
    /// This allows tests to use the client directly when needed while still
    /// benefiting from the TestContext for fixture management.
    pub fn client(&self) -> &'a AuditClient {
        self.client
    }

    /// Get the current context mode
    pub fn mode(&self) -> ContextMode {
        self.mode
    }

    // ============================================================
    // Cache Helper Methods
    // ============================================================

    /// Get a cached fixture if it exists
    fn get_cached(&self, kind: FixtureKind) -> Option<Event> {
        match self.mode {
            ContextMode::Isolated => {
                let cache = self.local_cache.lock().unwrap();
                cache.get(&kind).cloned()
            }
            ContextMode::Shared => {
                let cache = self.client.fixture_cache().lock().unwrap();
                cache.get(&kind).cloned()
            }
        }
    }

    /// Store a fixture in the cache
    fn store_cached(&self, kind: FixtureKind, event: Event) {
        match self.mode {
            ContextMode::Isolated => {
                let mut cache = self.local_cache.lock().unwrap();
                cache.insert(kind, event);
                tracing::debug!(
                    "store_cached({:?}) stored in local cache ({} entries)",
                    kind,
                    cache.len()
                );
            }
            ContextMode::Shared => {
                let mut cache = self.client.fixture_cache().lock().unwrap();
                cache.insert(kind, event);
                tracing::debug!(
                    "store_cached({:?}) stored in client cache ({} entries)",
                    kind,
                    cache.len()
                );
            }
        }
    }

    // ============================================================
    // Core Fixture Methods
    // ============================================================

    /// Ensure a fixture exists (with all dependencies)
    ///
    /// This is the core method for fixture management. It:
    /// 1. Checks the cache, returning immediately if found
    /// 2. Ensures all dependencies are met (recursively)
    /// 3. Builds the fixture
    /// 4. Sends to relay (unless fixture handles this internally)
    /// 5. Caches and returns the result
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use grasp_audit::*;
    /// # async fn example(ctx: &TestContext<'_>) -> anyhow::Result<()> {
    /// // This ensures ValidRepoSent exists first, then creates RepoState
    /// let state = ctx.ensure_fixture(FixtureKind::RepoState).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn ensure_fixture(
        &self,
        kind: FixtureKind,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Event>> + Send + '_>> {
        Box::pin(async move {
            // Check cache first
            if let Some(cached) = self.get_cached(kind) {
                tracing::debug!("ensure_fixture({:?}) found in cache", kind);
                return Ok(cached);
            }

            // Check relay connection before proceeding
            if !self.client.is_connected().await {
                return Err(anyhow::anyhow!(
                    "Relay connection lost before creating {:?} fixture",
                    kind
                ));
            }

            // Ensure all dependencies are met first
            for dep in kind.dependencies() {
                tracing::debug!("ensure_fixture({:?}) ensuring dependency {:?}", kind, dep);
                self.ensure_fixture(dep).await.with_context(|| {
                    format!("Failed to ensure dependency {:?} for {:?}", dep, kind)
                })?;
            }

            // Build the fixture
            let event = self
                .build_fixture_inner(kind)
                .await
                .with_context(|| format!("Failed to build {:?} fixture", kind))?;

            // Send to relay if this fixture doesn't handle it internally
            if !kind.sends_own_events() {
                self.client
                    .send_event(event.clone())
                    .await
                    .with_context(|| format!("Failed to send {:?} fixture event to relay", kind))?;
            }

            // Cache and return
            self.store_cached(kind, event.clone());
            Ok(event)
        })
    }

    /// Build a fixture event WITHOUT publishing it to the relay.
    ///
    /// This is useful for tests that need to get a fixture's event ID before
    /// actually publishing it. For example, testing refs/nostr/<event-id>
    /// behavior before the corresponding event exists on the relay.
    ///
    /// Note: This ensures dependencies are created/published first, but the
    /// requested fixture itself will NOT be published.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use grasp_audit::*;
    /// # async fn example(ctx: &TestContext<'_>) -> anyhow::Result<()> {
    /// // Build PR event to get its ID without publishing
    /// let pr_event = ctx.build_fixture_only(FixtureKind::PREvent).await?;
    /// let pr_event_id = pr_event.id.to_hex();
    ///
    /// // Now push to refs/nostr/<pr_event_id> before event exists
    /// // ... git push ...
    ///
    /// // Later, publish the PR event when ready
    /// ctx.client().send_event(pr_event).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn build_fixture_only(&self, kind: FixtureKind) -> Result<Event> {
        // Ensure dependencies are met first
        for dep in kind.dependencies() {
            self.ensure_fixture(dep).await?;
        }
        // Build but don't send/cache
        self.build_fixture_inner(kind).await
    }

    /// Get a cached dependency (assumes ensure_fixture processed dependencies first)
    ///
    /// This is a convenience helper for build_fixture_inner to retrieve dependencies
    /// that were already ensured by ensure_fixture before calling build_fixture_inner.
    fn get_cached_dependency(&self, kind: FixtureKind) -> Result<Event> {
        self.get_cached(kind).ok_or_else(|| {
            anyhow::anyhow!(
                "Dependency {:?} not found in cache - this is a bug in fixture dependencies",
                kind
            )
        })
    }

    /// Build a fixture event (internal - assumes dependencies are cached)
    ///
    /// This method is called by `ensure_fixture` after all dependencies have been
    /// ensured and cached. It should NOT call `ensure_fixture` or it will cause
    /// infinite recursion. Instead, use `get_cached_dependency` to retrieve
    /// already-cached dependencies.
    async fn build_fixture_inner(&self, kind: FixtureKind) -> Result<Event> {
        match kind {
            FixtureKind::ValidRepoSent => {
                // ValidRepoSent has no dependencies - create a new repo announcement
                let test_name = format!(
                    "fixture-ValidRepoSent-{}",
                    &uuid::Uuid::new_v4().to_string()[..8]
                );

                self.client
                    .create_repo_announcement(&test_name)
                    .await
                    .with_context(|| format!("create_repo_announcement failed for {}", test_name))
            }

            FixtureKind::ValidRepoServed => {
                // OwnerStateDataPushed is already ensured as a dependency.
                // The announcement is now promoted (served). Return the cached ValidRepoSent event.
                self.get_cached_dependency(FixtureKind::ValidRepoSent)
            }

            FixtureKind::RepoWithIssue => {
                // ValidRepoServed is ensured by ensure_fixture before this is called
                let repo = self.get_cached_dependency(FixtureKind::ValidRepoServed)?;

                // Build issue referencing it - caller will send it
                self.client
                    .create_issue(&repo, "Test Issue", "Issue content for testing", vec![])
            }

            FixtureKind::RepoWithComment => {
                // RepoWithIssue is ensured by ensure_fixture before this is called
                let issue = self.get_cached_dependency(FixtureKind::RepoWithIssue)?;

                // Build comment on issue - caller will send it
                self.client.create_comment(&issue, "Test comment", vec![])
            }

            FixtureKind::RepoState => {
                use nostr_sdk::prelude::*;

                // ValidRepoSent is ensured by ensure_fixture before this is called
                let repo = self.get_cached_dependency(FixtureKind::ValidRepoSent)?;

                // Extract repo_id from repo announcement
                let repo_id = repo
                    .tags
                    .iter()
                    .find(|t| t.kind() == "d")
                    .and_then(|t| t.content())
                    .ok_or_else(|| anyhow::anyhow!("Missing d tag in repo announcement"))?
                    .to_string();

                // Create state announcement with deterministic commit hash
                let base_time = Timestamp::now().as_secs();
                let older_timestamp = Timestamp::from(base_time - 10); // 10 seconds ago

                // Tag format: ["refs/heads/main", "<commit_hash>"]
                // Note: We build the state but DON'T send it here - the caller will send it
                self.client
                    .event_builder(Kind::RepoState, "")
                    .tag(Tag::identifier(&repo_id))
                    .tag(Tag::custom(
                        "refs/heads/main",
                        vec![DETERMINISTIC_COMMIT_HASH.to_string()],
                    ))
                    .tag(Tag::custom(
                        "HEAD",
                        vec!["ref: refs/heads/main".to_string()],
                    ))
                    .custom_time(older_timestamp)
                    .build(self.client.keys())
                    .map_err(|e| anyhow::anyhow!("Failed to build state announcement: {}", e))
            }

            FixtureKind::OwnerRepoStateSent => {
                use nostr_sdk::prelude::*;

                // ValidRepoSent is ensured by ensure_fixture before this is called
                let repo = self.get_cached_dependency(FixtureKind::ValidRepoSent)?;
                let repo_id = self.extract_repo_id(&repo)?;

                let base_time = Timestamp::now().as_secs();
                let older_timestamp = Timestamp::from(base_time - 10);

                let state_event = self
                    .client
                    .event_builder(Kind::RepoState, "")
                    .tag(Tag::identifier(&repo_id))
                    .tag(Tag::custom(
                        "refs/heads/main",
                        vec![DETERMINISTIC_COMMIT_HASH.to_string()],
                    ))
                    .tag(Tag::custom(
                        "HEAD",
                        vec!["ref: refs/heads/main".to_string()],
                    ))
                    .custom_time(older_timestamp)
                    .build(self.client.keys())
                    .map_err(|e| anyhow::anyhow!("Failed to build state announcement: {}", e))?;

                // Send to relay - event will be accepted but held in purgatory (no git data yet)
                self.client
                    .send_event_and_note_purgatory(state_event.clone())
                    .await?;

                Ok(state_event)
            }

            FixtureKind::PREvent => {
                use nostr_sdk::prelude::*;

                // ValidRepoServed is ensured by ensure_fixture before this is called
                let repo = self.get_cached_dependency(FixtureKind::ValidRepoServed)?;

                let repo_id = repo
                    .tags
                    .iter()
                    .find(|t| t.kind() == "d")
                    .and_then(|t| t.content())
                    .ok_or_else(|| anyhow::anyhow!("Missing repo_id in ValidRepoServed fixture"))?
                    .to_string();

                // Create PR event 1 second in the past
                let base_time = Timestamp::now().as_secs();
                let pr_timestamp = Timestamp::from(base_time - 1);

                // Build NIP-34 PR event (kind 1618)
                self.client
                    .event_builder(
                        Kind::GitPullRequest, // NIP-34 PR kind (has 'c' tag for commit)
                        "Test PR for GRASP validation",
                    )
                    .tag(Tag::custom(
                        "a",
                        vec![format!(
                            "30617:{}:{}",
                            self.client.public_key().to_hex(), // Owner pubkey
                            repo_id
                        )],
                    ))
                    .tag(Tag::custom("c", vec![PR_TEST_COMMIT_HASH.to_string()]))
                    .custom_time(pr_timestamp)
                    .build(self.client.pr_author_keys())
                    .map_err(|e| anyhow::anyhow!("Failed to build PR event: {}", e))
            }

            FixtureKind::PREventGenerated => {
                // Same as PREvent but will NOT be sent to relay (caller may send it later)
                // This fixture is for "Generated" stage only
                use nostr_sdk::prelude::*;

                // ValidRepoServed is ensured by ensure_fixture before this is called
                let repo = self.get_cached_dependency(FixtureKind::ValidRepoServed)?;

                let repo_id = repo
                    .tags
                    .iter()
                    .find(|t| t.kind() == "d")
                    .and_then(|t| t.content())
                    .ok_or_else(|| anyhow::anyhow!("Missing repo_id in ValidRepoServed fixture"))?
                    .to_string();

                // Create PR event 1 second in the past
                let base_time = Timestamp::now().as_secs();
                let pr_timestamp = Timestamp::from(base_time - 1);

                // Build NIP-34 PR event (kind 1618)
                self.client
                    .event_builder(
                        Kind::GitPullRequest, // NIP-34 PR kind (has 'c' tag for commit)
                        "Test PR for GRASP validation",
                    )
                    .tag(Tag::custom(
                        "a",
                        vec![format!(
                            "30617:{}:{}",
                            self.client.public_key().to_hex(), // Owner pubkey
                            repo_id
                        )],
                    ))
                    .tag(Tag::custom("c", vec![PR_TEST_COMMIT_HASH.to_string()]))
                    .custom_time(pr_timestamp)
                    .build(self.client.pr_author_keys())
                    .map_err(|e| anyhow::anyhow!("Failed to build PR event: {}", e))
            }

            FixtureKind::PRWrongCommitPushedBeforeEvent => {
                self.build_pr_wrong_commit_pushed_before_event().await
            }

            FixtureKind::PREventSentAfterWrongPush => {
                self.build_pr_event_sent_after_wrong_push().await
            }

            FixtureKind::PREvent2Generated => self.build_pr_event_2_generated().await,
            FixtureKind::PREvent2Sent => self.build_pr_event_2_sent().await,
            FixtureKind::PREvent2GitDataPushed => self.build_pr_event_2_git_data_pushed().await,
            FixtureKind::PREvent2Served => self.build_pr_event_2_served().await,

            FixtureKind::PurgatoryValidRepoSent => self.build_purgatory_valid_repo_sent().await,
            FixtureKind::PurgatoryOwnerStateDataPushed => {
                self.build_purgatory_owner_state_data_pushed().await
            }

            FixtureKind::OwnerStateDataPushed => self.build_owner_state_data_pushed().await,

            FixtureKind::MaintainerStateDataPushed => {
                self.build_maintainer_state_data_pushed().await
            }

            FixtureKind::RecursiveMaintainerStateDataPushed => {
                self.build_recursive_maintainer_state_data_pushed().await
            }

            FixtureKind::HeadSetToDevelopBranch => self.build_head_set_to_develop_branch().await,
        }
    }

    /// Build maintainer announcement event for the given repo_id
    async fn build_maintainer_announcement(&self, repo_id: &str) -> Result<Event> {
        use nostr_sdk::prelude::*;

        // Get relay URL for clone tag
        let relay_url = self
            .client
            .client()
            .relays()
            .await
            .keys()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No relay connected"))?
            .to_string();
        let http_url = relay_url
            .replace("ws://", "http://")
            .replace("wss://", "https://");

        // Create maintainer's repo announcement for the SAME repo_id
        let maintainer_npub = self
            .client
            .maintainer_keys()
            .public_key()
            .to_bech32()
            .map_err(|e| anyhow::anyhow!("Failed to convert maintainer pubkey: {}", e))?;

        self.client
            .event_builder(
                Kind::GitRepoAnnouncement,
                format!("Maintainer announcement for {}", repo_id),
            )
            .tag(Tag::identifier(repo_id))
            .tag(Tag::custom(
                "name",
                vec![format!("{} (maintainer)", repo_id)],
            ))
            .tag(Tag::custom(
                "clone",
                vec![format!("{}/{}/{}.git", http_url, maintainer_npub, repo_id)],
            ))
            .tag(Tag::custom("relays", vec![relay_url]))
            // List the owner back (reciprocal acknowledgment: NIP-34 treats a
            // listed pubkey as invited until their own announcement assigns a
            // role to an existing member) and assign the recursive maintainer.
            .tag(Tag::custom(
                "maintainers",
                vec![
                    self.client.keys().public_key().to_hex(),
                    self.client.recursive_maintainer_pubkey_hex(),
                ],
            ))
            .build(self.client.maintainer_keys())
            .map_err(|e| anyhow::anyhow!("Failed to build maintainer repo announcement: {}", e))
    }

    /// Build the recursive maintainer's reciprocal announcement for the given repo_id
    ///
    /// NIP-34 requires an assigned pubkey to acknowledge the role and assign a
    /// role to an existing member before their events become authoritative.
    /// The recursive maintainer lists the maintainer (who assigned them) back.
    ///
    /// The announcement deliberately points at another host: it is accepted via
    /// the maintainer exception, confirms membership, and leaves this relay
    /// free of a hosted repo view for the recursive maintainer. Later specs
    /// replace it with other external announcements, which would be treated as
    /// a de-list request if this one listed the service.
    async fn build_recursive_maintainer_reciprocal_announcement(
        &self,
        repo_id: &str,
    ) -> Result<Event> {
        use nostr_sdk::prelude::*;

        let recursive_maintainer_npub = self
            .client
            .recursive_maintainer_keys()
            .public_key()
            .to_bech32()
            .map_err(|e| anyhow::anyhow!("Failed to convert recursive maintainer pubkey: {}", e))?;

        self.client
            .event_builder(
                Kind::GitRepoAnnouncement,
                format!("Recursive maintainer announcement for {}", repo_id),
            )
            .tag(Tag::identifier(repo_id))
            .tag(Tag::custom(
                "name",
                vec![format!("{} (recursive maintainer)", repo_id)],
            ))
            .tag(Tag::custom(
                "clone",
                vec![format!(
                    "https://another-grasp-server.com/{}/{}.git",
                    recursive_maintainer_npub, repo_id
                )],
            ))
            .tag(Tag::custom("relays", vec!["wss://relay.damus.io"]))
            .tag(Tag::custom(
                "maintainers",
                vec![self.client.maintainer_pubkey_hex()],
            ))
            .build(self.client.recursive_maintainer_keys())
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to build recursive maintainer reciprocal announcement: {}",
                    e
                )
            })
    }

    /// Extract repo_id from a repo announcement event
    fn extract_repo_id(&self, repo: &Event) -> Result<String> {
        repo.tags
            .iter()
            .find(|t| t.kind() == "d")
            .and_then(|t| t.content())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("Missing d tag in repo announcement"))
    }

    /// Build PurgatoryValidRepoSent fixture: independent repo announcement for purgatory tests.
    ///
    /// Creates a fresh repo announcement with a unique repo_id, sends it to the relay,
    /// and returns it. Never promoted by any other test so the announcement stays in purgatory.
    async fn build_purgatory_valid_repo_sent(&self) -> Result<Event> {
        use nostr_sdk::prelude::*;

        let repo_id = format!(
            "fixture-PurgatoryValidRepoSent-{}",
            &uuid::Uuid::new_v4().to_string()[..8]
        );

        let relay_domain = self.get_relay_domain().await?;
        let relay_url = format!("ws://{}", relay_domain);
        let http_url = format!("http://{}", relay_domain);

        let npub = self
            .client
            .public_key()
            .to_bech32()
            .map_err(|e| anyhow::anyhow!("Failed to convert pubkey to bech32: {}", e))?;

        let announcement = self
            .client
            .event_builder(Kind::GitRepoAnnouncement, "")
            .tag(Tag::identifier(&repo_id))
            .tag(Tag::custom("name", vec![repo_id.clone()]))
            .tag(Tag::custom(
                "clone",
                vec![format!("{}/{}/{}.git", http_url, npub, repo_id)],
            ))
            .tag(Tag::custom("relays", vec![relay_url]))
            .build(self.client.keys())
            .map_err(|e| anyhow::anyhow!("Failed to build repo announcement: {}", e))?;

        self.client.send_event(announcement.clone()).await?;

        Ok(announcement)
    }

    /// Build PurgatoryOwnerStateDataPushed fixture: a self-contained independent repo for purgatory tests.
    ///
    /// Creates its own fresh repo announcement (unique repo_id), state event, and git push
    /// without touching the shared OwnerStateDataPushed chain. This ensures that purgatory
    /// tests which mutate relay state (replacement announcements, new state events, deletions)
    /// do not corrupt the repo that push-authorization tests depend on.
    async fn build_purgatory_owner_state_data_pushed(&self) -> Result<Event> {
        use nostr_sdk::prelude::*;

        // ============================================================
        // Step 1: Get the cached PurgatoryValidRepoSent announcement
        // (ensured as a dependency before this is called)
        // ============================================================
        let announcement = self.get_cached_dependency(FixtureKind::PurgatoryValidRepoSent)?;
        let repo_id = self.extract_repo_id(&announcement)?;

        let relay_domain = self.get_relay_domain().await?;

        let npub = self
            .client
            .public_key()
            .to_bech32()
            .map_err(|e| anyhow::anyhow!("Failed to convert pubkey to bech32: {}", e))?;

        // ============================================================
        // Step 2: Create and send owner state event (enters purgatory)
        // ============================================================
        let base_time = Timestamp::now().as_secs();
        let older_timestamp = Timestamp::from(base_time - 10);

        let state_event = self
            .client
            .event_builder(Kind::RepoState, "")
            .tag(Tag::identifier(&repo_id))
            .tag(Tag::custom(
                "refs/heads/main",
                vec![DETERMINISTIC_COMMIT_HASH.to_string()],
            ))
            .tag(Tag::custom(
                "HEAD",
                vec!["ref: refs/heads/main".to_string()],
            ))
            .custom_time(older_timestamp)
            .build(self.client.keys())
            .map_err(|e| anyhow::anyhow!("Failed to build state event: {}", e))?;

        self.client
            .send_event_and_note_purgatory(state_event.clone())
            .await?;

        // ============================================================
        // Step 3: Clone repo, create deterministic commit, push
        // ============================================================
        let clone_path = clone_repo(&relay_domain, &npub, &repo_id)
            .map_err(|e| anyhow::anyhow!("Failed to clone repo: {}", e))?;

        let cleanup = |path: &PathBuf| {
            let _ = fs::remove_dir_all(path);
        };

        let commit_hash = match create_deterministic_commit(&clone_path, "Initial commit") {
            Ok(h) => h,
            Err(e) => {
                cleanup(&clone_path);
                return Err(anyhow::anyhow!(
                    "Failed to create deterministic commit: {}",
                    e
                ));
            }
        };

        if commit_hash != DETERMINISTIC_COMMIT_HASH {
            cleanup(&clone_path);
            return Err(anyhow::anyhow!(
                "Commit hash mismatch: got {}, expected {}",
                commit_hash,
                DETERMINISTIC_COMMIT_HASH
            ));
        }

        // -B creates or resets main at HEAD, tolerating a pre-existing local
        // main (the clone's initial branch follows the server's advertised HEAD)
        if let Err(e) = run_fixture_git(&clone_path, &["checkout", "-B", "main"]) {
            cleanup(&clone_path);
            return Err(anyhow::anyhow!("Failed to create/checkout main: {}", e));
        }

        let push_result = try_push(&clone_path);
        cleanup(&clone_path);

        match push_result {
            Ok(true) => {}
            Ok(false) => {
                return Err(anyhow::anyhow!(
                    "PurgatoryOwnerStateDataPushed git push rejected (state event points to {})",
                    DETERMINISTIC_COMMIT_HASH
                ));
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "PurgatoryOwnerStateDataPushed push error: {}",
                    e
                ))
            }
        }

        // ============================================================
        // Step 4: Verify state event released from purgatory
        // ============================================================
        tokio::time::sleep(Duration::from_millis(200)).await;

        if !self.client.is_event_on_relay(state_event.id).await? {
            return Err(anyhow::anyhow!(
                "PurgatoryOwnerStateDataPushed state event not released from purgatory"
            ));
        }

        Ok(state_event)
    }

    /// Build OwnerStateDataPushed fixture: git push + purgatory release for owner's state event
    ///
    /// `OwnerRepoStateSent` is ensured as a dependency before this is called — the state event
    /// is already on the relay in purgatory. This fixture completes the cycle:
    /// 1. **DataPushed**: Clones repo, creates deterministic commit, pushes to relay
    /// 2. **Verified**: Confirms state event is released from purgatory and served
    ///
    /// # Returns
    /// The state event (kind 30618) after git data is pushed and purgatory is released
    async fn build_owner_state_data_pushed(&self) -> Result<Event> {
        use nostr_sdk::prelude::*;

        // OwnerRepoStateSent is ensured by ensure_fixture before this is called.
        // The state event is already on the relay in purgatory - retrieve it from cache.
        let state_event = self.get_cached_dependency(FixtureKind::OwnerRepoStateSent)?;
        let repo = self.get_cached_dependency(FixtureKind::ValidRepoSent)?;
        let repo_id = self.extract_repo_id(&repo)?;

        // ============================================================
        // Stage 1: DataPushed - Clone repo, create commit, push
        // ============================================================

        // Get relay domain from connected relay
        let relay_domain = self.get_relay_domain().await?;

        let npub = state_event
            .pubkey
            .to_bech32()
            .map_err(|e| anyhow::anyhow!("Failed to convert pubkey to bech32: {}", e))?;

        // Clone the repository
        let clone_path = clone_repo(&relay_domain, &npub, &repo_id)
            .map_err(|e| anyhow::anyhow!("Failed to clone repo: {}", e))?;

        // Cleanup helper (always clean up on error or success)
        let cleanup = |path: &PathBuf| {
            let _ = fs::remove_dir_all(path);
        };

        // Create deterministic commit locally
        let commit_hash = match create_deterministic_commit(&clone_path, "Initial commit") {
            Ok(h) => h,
            Err(e) => {
                cleanup(&clone_path);
                return Err(anyhow::anyhow!(
                    "Failed to create deterministic commit: {}",
                    e
                ));
            }
        };

        // Verify commit hash matches expected
        if commit_hash != DETERMINISTIC_COMMIT_HASH {
            cleanup(&clone_path);
            return Err(anyhow::anyhow!(
                "Commit hash mismatch: got {}, expected {}",
                commit_hash,
                DETERMINISTIC_COMMIT_HASH
            ));
        }

        // Create or reset main at our deterministic commit and check it out.
        // -B tolerates a pre-existing local main (the clone's initial branch
        // follows the server's advertised HEAD)
        let checkout_output = git_command()
            .args(["checkout", "-B", "main"])
            .current_dir(&clone_path)
            .output();

        match checkout_output {
            Err(e) => {
                cleanup(&clone_path);
                return Err(anyhow::anyhow!(
                    "Failed to create/checkout main branch: {}",
                    e
                ));
            }
            Ok(output) if !output.status.success() => {
                cleanup(&clone_path);
                return Err(anyhow::anyhow!(
                    "Failed to create/checkout main branch: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            _ => {}
        }

        // Push to relay
        let push_result = try_push(&clone_path);
        cleanup(&clone_path);

        match push_result {
            Ok(res) => {
                if !res {
                    return Err(anyhow::anyhow!(
                        "Push was rejected but should have been accepted. \
                The state event points to commit {} which matches the pushed commit.",
                        DETERMINISTIC_COMMIT_HASH
                    ));
                }
            }
            Err(e) => return Err(anyhow::anyhow!("Push error: {}", e)),
        }

        // ============================================================
        // Stage 2: Verify state event is released from purgatory
        // ============================================================

        tokio::time::sleep(Duration::from_millis(200)).await;

        if !self.client.is_event_on_relay(state_event.id).await? {
            return Err(anyhow::anyhow!("state event not released from purgatory"));
        }

        Ok(state_event)
    }

    /// Build MaintainerStateDataPushed fixture: full 5-stage fixture for maintainer push authorization
    ///
    /// This tests that a confirmed maintainer can authorize pushes with a state
    /// event. Per NIP-34 a listed pubkey is only *invited* until their own
    /// announcement acknowledges the role and lists back an existing member, so
    /// the maintainer's reciprocal announcement is published before their state
    /// event becomes authoritative.
    ///
    /// Depends on OwnerStateDataPushed - the owner's data has already been pushed.
    /// The maintainer force-pushes their commit on top.
    ///
    /// This handles all stages of the fixture:
    /// 1. **OwnerStateDataPushed dependency**: Owner's repo and state event already on relay, git data pushed
    /// 2. **Sent**: Sends maintainer reciprocal announcement + state event to relay
    /// 3. **Verify Not Served**: Confirms event is not served by relays
    /// 4. **DataPushed**: Clones repo, creates maintainer deterministic commit, force-pushes to relay
    /// 5. **Verified**: Confirms event is served by relay
    ///
    /// # Returns
    /// The maintainer's state event (kind 30618) after all stages complete successfully
    async fn build_maintainer_state_data_pushed(&self) -> Result<Event> {
        use nostr_sdk::prelude::*;

        // ============================================================
        // Stage 1: OwnerStateDataPushed is ensured by ensure_fixture before this is called
        // ============================================================
        let owner_state = self.get_cached_dependency(FixtureKind::OwnerStateDataPushed)?;

        // Extract repo_id from owner's state event (same d-tag structure)
        let repo_id = self.extract_repo_id(&owner_state)?;

        // Get the repo (ValidRepoSent, also cached) for the owner's npub
        let repo = self.get_cached_dependency(FixtureKind::ValidRepoSent)?;

        // Publish the maintainer's reciprocal announcement first: without it
        // the maintainer is merely invited and their state event would be
        // rejected as unauthorized.
        let maintainer_announcement = self.build_maintainer_announcement(&repo_id).await?;
        self.client.send_event(maintainer_announcement).await?;

        // Build maintainer's state event
        let base_time = Timestamp::now().as_secs();
        let maintainer_timestamp = Timestamp::from(base_time - 5); // 5 seconds ago (more recent than owner's state)

        let maintainer_state_event = self
            .client
            .event_builder(Kind::RepoState, "")
            .tag(Tag::identifier(&repo_id))
            .tag(Tag::custom(
                "refs/heads/main",
                vec![MAINTAINER_DETERMINISTIC_COMMIT_HASH.to_string()],
            ))
            .tag(Tag::custom(
                "HEAD",
                vec!["ref: refs/heads/main".to_string()],
            ))
            .custom_time(maintainer_timestamp)
            .build(self.client.maintainer_keys())
            .map_err(|e| anyhow::anyhow!("Failed to build maintainer state event: {}", e))?;

        // ============================================================
        // Stage 2 & 3: Send to Relay, get Accepted response and Verify its Not Served
        // ============================================================
        let (_, _in_purgatory) = self
            .client
            .send_event_and_note_purgatory(maintainer_state_event.clone())
            .await?;
        // Note: We don't fail if purgatory wasn't observed - the fixture proceeds regardless

        // ============================================================
        // Stage 4: DataPushed - Clone repo, create maintainer commit, push
        // ============================================================

        // Get relay domain from connected relay
        let relay_domain = self.get_relay_domain().await?;

        // Use owner's npub for cloning (repo belongs to owner)
        let npub = repo
            .pubkey
            .to_bech32()
            .map_err(|e| anyhow::anyhow!("Failed to convert pubkey to bech32: {}", e))?;

        // Clone the repository
        let clone_path = clone_repo(&relay_domain, &npub, &repo_id)
            .map_err(|e| anyhow::anyhow!("Failed to clone repo: {}", e))?;

        // Cleanup helper (always clean up on error or success)
        let cleanup = |path: &PathBuf| {
            let _ = fs::remove_dir_all(path);
        };

        // Reset to orphan state and create deterministic root commit
        // Step 1: Create orphan branch (removes all history)
        if let Err(e) = run_fixture_git(&clone_path, &["checkout", "--orphan", "main-new"]) {
            cleanup(&clone_path);
            return Err(anyhow::anyhow!("Failed to create orphan branch: {}", e));
        }

        // Step 2: Clear staged files (orphan keeps files staged from previous branch)
        if let Err(e) = run_fixture_git(&clone_path, &["rm", "-rf", "--cached", "."]) {
            cleanup(&clone_path);
            return Err(anyhow::anyhow!("Failed to clear staged files: {}", e));
        }

        // Step 3: Create deterministic commit using maintainer variant
        let commit_hash = match create_deterministic_commit_with_variant(
            &clone_path,
            CommitVariant::Maintainer,
        ) {
            Ok(h) => h,
            Err(e) => {
                cleanup(&clone_path);
                return Err(anyhow::anyhow!("Failed to create maintainer commit: {}", e));
            }
        };

        // Step 4: Replace main branch with our new orphan branch. Deleting the
        // old main is best-effort (the clone may not have had one); the rename
        // must succeed for the push below to target refs/heads/main.
        let _ = git_command()
            .args(["branch", "-D", "main"])
            .current_dir(&clone_path)
            .output();

        if let Err(e) = run_fixture_git(&clone_path, &["branch", "-m", "main"]) {
            cleanup(&clone_path);
            return Err(anyhow::anyhow!(
                "Failed to rename orphan branch to main: {}",
                e
            ));
        }

        // Verify commit hash matches expected
        if commit_hash != MAINTAINER_DETERMINISTIC_COMMIT_HASH {
            cleanup(&clone_path);
            return Err(anyhow::anyhow!(
                "Maintainer commit hash mismatch: got {}, expected {}",
                commit_hash,
                MAINTAINER_DETERMINISTIC_COMMIT_HASH
            ));
        }

        // Push to relay
        let push_result = try_push(&clone_path);
        cleanup(&clone_path);

        match push_result {
            Ok(res) => {
                if !res {
                    return Err(anyhow::anyhow!(
                        "Push was rejected but should have been accepted. \
                The maintainer published a reciprocal announcement and a state \
                event with commit {}; as a confirmed member of the owner's \
                maintainer set the relay should authorize pushes matching this \
                state event.",
                        MAINTAINER_DETERMINISTIC_COMMIT_HASH
                    ));
                }
            }
            Err(e) => return Err(anyhow::anyhow!("Push error: {}", e)),
        }

        // ============================================================
        // Stage 5: Verify state event is on relay
        // ============================================================

        tokio::time::sleep(Duration::from_millis(200)).await;

        if !self
            .client
            .is_event_on_relay(maintainer_state_event.id)
            .await?
        {
            return Err(anyhow::anyhow!("state event not released from purgatory"));
        }

        Ok(maintainer_state_event)
    }

    /// Build the legacy-named recursive fixture for transitive confirmed authorization.
    ///
    /// The additional maintainer is listed in the direct maintainer's
    /// announcement rather than the selected author's announcement, and
    /// publishes a reciprocal announcement before gaining authority.
    ///
    /// Depends on MaintainerStateDataPushed - the maintainer's data has already been
    /// pushed and the maintainer's announcement (which assigns the recursive
    /// maintainer) is on the relay. We then send the recursive maintainer's
    /// reciprocal announcement (confirming them as a member), and the recursive
    /// maintainer force-pushes their commit on top.
    ///
    /// This handles all stages of the fixture:
    /// 1. **Generated**: (MaintainerStateDataPushed dependency includes ValidRepoSent + OwnerStateDataPushed)
    ///    Creates the additional maintainer's reciprocal announcement and State event
    /// 2. **Sent**: Sends events to relay (returns OK, accepted but 'purgatory:...' message)
    /// 3. **Verify Not Served**: Confirms event is not served by relays
    /// 4. **DataPushed**: Clones repo, creates the additional maintainer's deterministic commit, pushes to relay
    /// 5. **Verified**: Confirms event is served by relay
    ///
    /// # Returns
    /// The transitively confirmed maintainer's State event after all stages complete
    async fn build_recursive_maintainer_state_data_pushed(&self) -> Result<Event> {
        use nostr_sdk::prelude::*;

        // ============================================================
        // Stage 1: MaintainerStateDataPushed is ensured by ensure_fixture before this is called
        // ============================================================
        let maintainer_state =
            self.get_cached_dependency(FixtureKind::MaintainerStateDataPushed)?;

        // Extract repo_id from maintainer's state event (same d-tag structure)
        let repo_id = self.extract_repo_id(&maintainer_state)?;

        // Get the repo (ValidRepoSent, also cached) for the owner's npub
        let repo = self.get_cached_dependency(FixtureKind::ValidRepoSent)?;

        // ============================================================
        // Stage 1 (continued): Generate the recursive maintainer's reciprocal
        // announcement and their state event. The maintainer's announcement
        // (which assigns the recursive maintainer) was already published by the
        // MaintainerStateDataPushed dependency; the reciprocal announcement
        // confirms the recursive maintainer as a member so their state event
        // becomes authoritative.
        // ============================================================
        let reciprocal_announcement = self
            .build_recursive_maintainer_reciprocal_announcement(&repo_id)
            .await?;
        self.client.send_event(reciprocal_announcement).await?;

        // Build recursive maintainer's state event
        let base_time = Timestamp::now().as_secs();
        let recursive_maintainer_timestamp = Timestamp::from(base_time - 2); // 2 seconds ago (most recent)

        let recursive_maintainer_state_event = self
            .client
            .event_builder(Kind::RepoState, "")
            .tag(Tag::identifier(&repo_id))
            .tag(Tag::custom(
                "refs/heads/main",
                vec![RECURSIVE_MAINTAINER_DETERMINISTIC_COMMIT_HASH.to_string()],
            ))
            .tag(Tag::custom(
                "HEAD",
                vec!["ref: refs/heads/main".to_string()],
            ))
            .custom_time(recursive_maintainer_timestamp)
            .build(self.client.recursive_maintainer_keys())
            .map_err(|e| {
                anyhow::anyhow!("Failed to build recursive maintainer state event: {}", e)
            })?;

        // ============================================================
        // Stage 2 & 3: Send to Relay, get Accepted response and Verify its Not Served
        // ============================================================
        let (_, _in_purgatory) = self
            .client
            .send_event_and_note_purgatory(recursive_maintainer_state_event.clone())
            .await?;
        // Note: We don't fail if purgatory wasn't observed - the fixture proceeds regardless

        // ============================================================
        // Stage 4: DataPushed - Clone repo, create recursive maintainer commit, push
        // ============================================================

        // Get relay domain from connected relay
        let relay_domain = self.get_relay_domain().await?;

        // Use owner's npub for cloning (repo belongs to owner)
        let npub = repo
            .pubkey
            .to_bech32()
            .map_err(|e| anyhow::anyhow!("Failed to convert pubkey to bech32: {}", e))?;

        // Clone the repository
        let clone_path = clone_repo(&relay_domain, &npub, &repo_id)
            .map_err(|e| anyhow::anyhow!("Failed to clone repo: {}", e))?;

        // Cleanup helper (always clean up on error or success)
        let cleanup = |path: &PathBuf| {
            let _ = fs::remove_dir_all(path);
        };

        // Reset to orphan state and create deterministic root commit
        // Step 1: Create orphan branch (removes all history)
        if let Err(e) = run_fixture_git(&clone_path, &["checkout", "--orphan", "main-new"]) {
            cleanup(&clone_path);
            return Err(anyhow::anyhow!("Failed to create orphan branch: {}", e));
        }

        // Step 2: Clear staged files (orphan keeps files staged from previous branch)
        if let Err(e) = run_fixture_git(&clone_path, &["rm", "-rf", "--cached", "."]) {
            cleanup(&clone_path);
            return Err(anyhow::anyhow!("Failed to clear staged files: {}", e));
        }

        // Step 3: Create deterministic commit using recursive maintainer variant
        let commit_hash = match create_deterministic_commit_with_variant(
            &clone_path,
            CommitVariant::RecursiveMaintainer,
        ) {
            Ok(h) => h,
            Err(e) => {
                cleanup(&clone_path);
                return Err(anyhow::anyhow!(
                    "Failed to create recursive maintainer commit: {}",
                    e
                ));
            }
        };

        // Step 4: Replace main branch with our new orphan branch. Deleting the
        // old main is best-effort (the clone may not have had one); the rename
        // must succeed for the push below to target refs/heads/main.
        let _ = git_command()
            .args(["branch", "-D", "main"])
            .current_dir(&clone_path)
            .output();

        if let Err(e) = run_fixture_git(&clone_path, &["branch", "-m", "main"]) {
            cleanup(&clone_path);
            return Err(anyhow::anyhow!(
                "Failed to rename orphan branch to main: {}",
                e
            ));
        }

        // Verify commit hash matches expected
        if commit_hash != RECURSIVE_MAINTAINER_DETERMINISTIC_COMMIT_HASH {
            cleanup(&clone_path);
            return Err(anyhow::anyhow!(
                "Recursive maintainer commit hash mismatch: got {}, expected {}",
                commit_hash,
                RECURSIVE_MAINTAINER_DETERMINISTIC_COMMIT_HASH
            ));
        }

        // Push to relay
        let push_result = try_push(&clone_path);
        cleanup(&clone_path);

        match push_result {
            Ok(res) => {
                if !res {
                    return Err(anyhow::anyhow!(
                        "Push was rejected but should have been accepted. \
                The recursive maintainer published a state event with commit {}, \
                and the relay should authorize pushes matching this state event \
                through the transitively confirmed reciprocal component.",
                        RECURSIVE_MAINTAINER_DETERMINISTIC_COMMIT_HASH
                    ));
                }
            }
            Err(e) => return Err(anyhow::anyhow!("Push error: {}", e)),
        }

        // ============================================================
        // Stage 5: Verify state event is on relay
        // ============================================================

        tokio::time::sleep(Duration::from_millis(200)).await;

        if !self
            .client
            .is_event_on_relay(recursive_maintainer_state_event.id)
            .await?
        {
            return Err(anyhow::anyhow!("state event not released from purgatory"));
        }

        Ok(recursive_maintainer_state_event)
    }

    /// Build HeadSetToDevelopBranch fixture: creates state event with HEAD=develop
    ///
    /// This tests that HEAD is updated when a state event is published with HEAD
    /// pointing to a different branch that already has git data pushed.
    ///
    /// GRASP-01: "MUST set repository HEAD per repository state announcement
    /// as soon as the git data related to that branch has been received."
    ///
    /// Depends on RecursiveMaintainerStateDataPushed - all git data already exists.
    /// We just create a new state event with HEAD=refs/heads/develop pointing to
    /// the already-pushed commit.
    ///
    /// # Returns
    /// The state event (kind 30618) with HEAD=refs/heads/develop after it's sent
    async fn build_head_set_to_develop_branch(&self) -> Result<Event> {
        use nostr_sdk::prelude::*;

        // ============================================================
        // Stage 1: RecursiveMaintainerStateDataPushed is ensured by ensure_fixture before this is called
        // All git data already exists on the relay (main branch with RECURSIVE_MAINTAINER_DETERMINISTIC_COMMIT_HASH)
        // ============================================================
        let recursive_state =
            self.get_cached_dependency(FixtureKind::RecursiveMaintainerStateDataPushed)?;

        // Extract repo_id from the recursive maintainer's state event
        let repo_id = self.extract_repo_id(&recursive_state)?;

        // ============================================================
        // Stage 2: Create state event with HEAD=refs/heads/develop
        // ============================================================
        // Use the same commit hash that's already pushed to the relay
        // but point HEAD to develop branch instead of main
        let base_time = Timestamp::now().as_secs();
        let develop_timestamp = Timestamp::from(base_time - 1); // 1 second ago (most recent)

        let develop_state_event = self
            .client
            .event_builder(Kind::RepoState, "")
            .tag(Tag::identifier(&repo_id))
            .tag(Tag::custom("HEAD", vec!["refs/heads/develop".to_string()]))
            .tag(Tag::custom(
                "refs/heads/develop",
                vec![RECURSIVE_MAINTAINER_DETERMINISTIC_COMMIT_HASH.to_string()],
            ))
            .custom_time(develop_timestamp)
            .build(self.client.maintainer_keys())
            .map_err(|e| anyhow::anyhow!("Failed to build develop state event: {}", e))?;

        // Send state event to relay
        self.client.send_event(develop_state_event.clone()).await?;

        // Wait for relay to process the state event
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        Ok(develop_state_event)
    }

    /// Build PRWrongCommitPushedBeforeEvent fixture
    ///
    /// This fixture sets up a scenario where:
    /// 1. A repo exists on the relay
    /// 2. A PR event is generated (but NOT sent to relay)
    /// 3. A wrong commit is pushed to refs/nostr/<pr-event-id>
    ///
    /// Server state after:
    /// - ValidRepoSent announcement on relay
    /// - refs/nostr/<pr-event-id> on git server pointing to DETERMINISTIC_COMMIT_HASH (wrong)
    /// - NO PR event on relay
    ///
    /// Returns: the unsent PR event (tests can publish it later)
    async fn build_pr_wrong_commit_pushed_before_event(&self) -> Result<Event> {
        use nostr_sdk::prelude::*;

        // Get the cached PREventGenerated (the unsent PR event)
        let pr_event = self.get_cached_dependency(FixtureKind::PREventGenerated)?;
        let pr_event_id = pr_event.id.to_hex();

        // Get the ValidRepoServed to extract repo info
        let repo = self.get_cached_dependency(FixtureKind::ValidRepoServed)?;
        let repo_id = self.extract_repo_id(&repo)?;

        // Get relay domain for cloning
        let relay_domain = self.get_relay_domain().await?;

        // Owner npub for clone URL
        let npub = repo
            .pubkey
            .to_bech32()
            .map_err(|e| anyhow::anyhow!("Failed to convert pubkey to bech32: {}", e))?;

        // Clone the repository (fresh clone - local repos are never cached)
        let clone_path = clone_repo(&relay_domain, &npub, &repo_id)
            .map_err(|e| anyhow::anyhow!("Failed to clone repo: {}", e))?;

        // Cleanup helper
        let cleanup = |path: &PathBuf| {
            let _ = fs::remove_dir_all(path);
        };

        // Create a WRONG commit using a unique file (not PRTestCommit)
        // We use create_commit (non-deterministic) so it always succeeds even if the
        // repo already has a commit (e.g. from OwnerStateDataPushed) with the same
        // deterministic content. The only requirement is that the hash differs from
        // PR_TEST_COMMIT_HASH, which is guaranteed since PR_TEST_COMMIT_HASH is a
        // deterministic root-commit with specific content and dates.
        let wrong_commit_hash =
            match create_commit(&clone_path, "wrong commit - not the PR test commit") {
                Ok(h) => h,
                Err(e) => {
                    cleanup(&clone_path);
                    return Err(anyhow::anyhow!("Failed to create wrong commit: {}", e));
                }
            };

        // Verify it's actually different from expected PR commit
        if wrong_commit_hash == PR_TEST_COMMIT_HASH {
            cleanup(&clone_path);
            return Err(anyhow::anyhow!(
                "Test setup error: wrong_commit_hash {} equals PR_TEST_COMMIT_HASH",
                wrong_commit_hash
            ));
        }

        // Force-rename the current branch to master; the push below targets it.
        if let Err(e) = run_fixture_git(&clone_path, &["branch", "-M", "master"]) {
            cleanup(&clone_path);
            return Err(anyhow::anyhow!("Failed to create master branch: {}", e));
        }

        let push_output = git_command()
            .args([
                "push",
                "origin",
                &format!("master:refs/nostr/{}", pr_event_id),
            ])
            .current_dir(&clone_path)
            .output()
            .map_err(|e| {
                cleanup(&clone_path);
                anyhow::anyhow!("Failed to execute git push: {}", e)
            })?;

        cleanup(&clone_path);

        if !push_output.status.success() {
            let stderr = String::from_utf8_lossy(&push_output.stderr);
            return Err(anyhow::anyhow!(
                "Initial push to refs/nostr/{} failed (expected success before PR event exists): {}",
                pr_event_id,
                stderr
            ));
        }

        // Return the unsent PR event (tests can publish it later)
        Ok(pr_event)
    }

    /// Build PREventSentAfterWrongPush fixture
    ///
    /// This fixture builds on PRWrongCommitPushedBeforeEvent by sending the PR event.
    /// After this fixture, the relay has:
    /// - ValidRepoServed announcement
    /// - PR event
    /// - refs/nostr/<pr-event-id> may have been cleaned up (that's what tests verify)
    ///
    /// Returns: the sent PR event
    async fn build_pr_event_sent_after_wrong_push(&self) -> Result<Event> {
        // Get the PR event that was cached by PRWrongCommitPushedBeforeEvent
        let pr_event = self.get_cached_dependency(FixtureKind::PRWrongCommitPushedBeforeEvent)?;

        // Send the PR event to relay
        self.client.send_event(pr_event.clone()).await?;

        // Wait for relay to process
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Return the now-sent PR event
        Ok(pr_event)
    }

    /// Build PREvent2Generated fixture
    ///
    /// Creates a PR event with `c` tag pointing to PR_TEST_COMMIT_HASH_2.
    /// The event is NOT sent to the relay.
    async fn build_pr_event_2_generated(&self) -> Result<Event> {
        use nostr_sdk::prelude::*;

        let repo = self.get_cached_dependency(FixtureKind::ValidRepoServed)?;
        let repo_id = self.extract_repo_id(&repo)?;

        let base_time = Timestamp::now().as_secs();
        let pr_timestamp = Timestamp::from(base_time - 1);

        self.client
            .event_builder(Kind::GitPullRequest, "Test PR 2 for GRASP validation")
            .tag(Tag::custom(
                "a",
                vec![format!(
                    "30617:{}:{}",
                    self.client.public_key().to_hex(),
                    repo_id
                )],
            ))
            .tag(Tag::custom("c", vec![PR_TEST_COMMIT_HASH_2.to_string()]))
            .custom_time(pr_timestamp)
            .build(self.client.pr_author_keys())
            .map_err(|e| anyhow::anyhow!("Failed to build PR event 2: {}", e))
    }

    /// Build PREvent2Sent fixture
    ///
    /// Sends the PR event to relay. Event should enter purgatory.
    async fn build_pr_event_2_sent(&self) -> Result<Event> {
        let pr_event = self.get_cached_dependency(FixtureKind::PREvent2Generated)?;

        let (_, in_purgatory) = self
            .client
            .send_event_and_note_purgatory(pr_event.clone())
            .await?;

        if !in_purgatory {
            return Err(anyhow::anyhow!(
                "PR event 2 was served immediately - purgatory not implemented"
            ));
        }

        Ok(pr_event)
    }

    /// Build PREvent2GitDataPushed fixture
    ///
    /// Pushes correct commit to refs/nostr/<pr-event-id> after event was sent.
    async fn build_pr_event_2_git_data_pushed(&self) -> Result<Event> {
        use nostr_sdk::prelude::*;

        let pr_event = self.get_cached_dependency(FixtureKind::PREvent2Sent)?;
        let pr_event_id = pr_event.id.to_hex();

        let repo = self.get_cached_dependency(FixtureKind::ValidRepoServed)?;
        let repo_id = self.extract_repo_id(&repo)?;

        let relay_domain = self.get_relay_domain().await?;

        let npub = repo
            .pubkey
            .to_bech32()
            .map_err(|e| anyhow::anyhow!("Failed to convert pubkey: {}", e))?;

        let clone_path = clone_repo(&relay_domain, &npub, &repo_id)
            .map_err(|e| anyhow::anyhow!("Failed to clone repo: {}", e))?;

        let cleanup = |path: &PathBuf| {
            let _ = fs::remove_dir_all(path);
        };

        // Reset to orphan state and create deterministic root commit
        // Step 1: Create orphan branch (removes all history)
        if let Err(e) = run_fixture_git(&clone_path, &["checkout", "--orphan", "pr-branch"]) {
            cleanup(&clone_path);
            return Err(anyhow::anyhow!("Failed to create orphan branch: {}", e));
        }

        // Step 2: Clear staged files (orphan keeps files staged from previous branch)
        if let Err(e) = run_fixture_git(&clone_path, &["rm", "-rf", "--cached", "."]) {
            cleanup(&clone_path);
            return Err(anyhow::anyhow!("Failed to clear staged files: {}", e));
        }

        // Step 3: Remove all working directory files for clean state (except .git)
        for entry in fs::read_dir(&clone_path)
            .map_err(|e| anyhow::anyhow!("Failed to read dir: {}", e))?
            .flatten()
        {
            let path = entry.path();
            if path.file_name() != Some(std::ffi::OsStr::new(".git")) {
                let _ = fs::remove_file(&path).or_else(|_| fs::remove_dir_all(&path));
            }
        }

        let commit_hash = match create_deterministic_commit_with_variant(
            &clone_path,
            CommitVariant::PRTestCommit2,
        ) {
            Ok(h) => h,
            Err(e) => {
                cleanup(&clone_path);
                return Err(anyhow::anyhow!("Failed to create PR test commit 2: {}", e));
            }
        };

        if commit_hash != PR_TEST_COMMIT_HASH_2 {
            cleanup(&clone_path);
            return Err(anyhow::anyhow!(
                "PR test commit 2 hash mismatch: got {}, expected {}",
                commit_hash,
                PR_TEST_COMMIT_HASH_2
            ));
        }

        let push_output = git_command()
            .args([
                "push",
                "origin",
                &format!("pr-branch:refs/nostr/{}", pr_event_id),
            ])
            .current_dir(&clone_path)
            .output()
            .map_err(|e| {
                cleanup(&clone_path);
                anyhow::anyhow!("Failed to execute git push: {}", e)
            })?;

        cleanup(&clone_path);

        if !push_output.status.success() {
            let stderr = String::from_utf8_lossy(&push_output.stderr);
            return Err(anyhow::anyhow!(
                "Push to refs/nostr/{} failed: {}",
                pr_event_id,
                stderr
            ));
        }

        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        Ok(pr_event)
    }

    /// Build PREvent2Served fixture
    ///
    /// Full fixture: event sent, git pushed, event now served.
    async fn build_pr_event_2_served(&self) -> Result<Event> {
        let pr_event = self.get_cached_dependency(FixtureKind::PREvent2GitDataPushed)?;

        if !self.client.is_event_on_relay(pr_event.id).await? {
            return Err(anyhow::anyhow!(
                "PR event 2 not released from purgatory after git push"
            ));
        }

        Ok(pr_event)
    }

    /// Get relay domain (host:port) from the connected relay
    ///
    /// Extracts the domain from the relay URL for git HTTP operations.
    /// Example: ws://localhost:7000 -> localhost:7000
    async fn get_relay_domain(&self) -> Result<String> {
        let relay_url = self
            .client
            .client()
            .relays()
            .await
            .keys()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No relay connected"))?
            .to_string();

        // Extract domain from URL (ws://host:port -> host:port)
        let domain = relay_url
            .replace("ws://", "")
            .replace("wss://", "")
            .trim_end_matches('/')
            .to_string();

        Ok(domain)
    }

    /// Clear the fixture cache
    ///
    /// This clears the client's fixture cache, affecting all TestContext
    /// instances using the same client.
    pub fn clear_cache(&self) {
        let mut cache = self.client.fixture_cache().lock().unwrap();
        cache.clear();
    }
}

// ============================================================
// Verification Helpers
// ============================================================

/// Send event and verify it was accepted (stored by relay)
///
/// This is a common test pattern helper that:
/// 1. Sends an event to the relay via the client
/// 2. Waits for propagation (100ms)
/// 3. Queries the relay to verify the event was stored
///
/// # Arguments
/// * `client` - The AuditClient to use for sending and querying
/// * `event` - The event to send
/// * `description` - Human-readable description for error messages
///
/// # Returns
/// * `Ok(())` if the event was accepted and stored
/// * `Err(String)` with descriptive error if event was not stored
///
/// # Example
/// ```no_run
/// # use grasp_audit::*;
/// # async fn example(client: &AuditClient, event: nostr_sdk::prelude::Event) -> Result<(), String> {
/// send_and_verify_accepted(client, event, "issue referencing repo via 'a' tag").await?;
/// # Ok(())
/// # }
/// ```
pub async fn send_and_verify_accepted(
    client: &crate::AuditClient,
    event: Event,
    description: &str,
) -> Result<(), String> {
    use nostr_sdk::prelude::Filter;
    use std::time::Duration;

    let event_id = event.id;

    client
        .send_event(event)
        .await
        .map_err(|e| format!("Failed to send event to relay: {}", e))?;

    tokio::time::sleep(Duration::from_millis(100)).await;

    let filter = Filter::new().id(event_id);
    let events = client
        .query(filter)
        .await
        .map_err(|e| format!("Failed to query relay for verification: {}", e))?;

    if events.is_empty() {
        return Err(format!("Event should be accepted: {}", description));
    }

    Ok(())
}

/// Send event and verify it was rejected (NOT stored by relay)
///
/// This is a common test pattern helper that:
/// 1. Sends an event to the relay via the client
/// 2. Handles both explicit rejection errors and silent rejection
/// 3. Verifies the event was NOT stored in the relay
///
/// # Arguments
/// * `client` - The AuditClient to use for sending and querying
/// * `event` - The event to send (expected to be rejected)
/// * `description` - Human-readable description for error messages
///
/// # Returns
/// * `Ok(())` if the event was rejected (not stored)
/// * `Err(String)` if the event was unexpectedly accepted
///
/// # Example
/// ```no_run
/// # use grasp_audit::*;
/// # async fn example(client: &AuditClient, event: nostr_sdk::prelude::Event) -> Result<(), String> {
/// send_and_verify_rejected(client, event, "orphan issue with no repo connection").await?;
/// # Ok(())
/// # }
/// ```
pub async fn send_and_verify_rejected(
    client: &crate::AuditClient,
    event: Event,
    description: &str,
) -> Result<(), String> {
    use nostr_sdk::prelude::Filter;
    use std::time::Duration;

    let event_id = event.id;

    // Try to send event - rejection may cause send_event to fail with an error
    let send_result = client.send_event(event).await;

    // If send succeeded, the relay might have accepted it (we'll verify below)
    // If send failed, check if it's a rejection error (expected)
    if let Err(e) = send_result {
        let err_msg = e.to_string().to_lowercase();
        // Check if error message indicates rejection (not network/other errors)
        if err_msg.contains("rejected") || err_msg.contains("blocked") {
            // Expected rejection - verify event is NOT in database
            tokio::time::sleep(Duration::from_millis(100)).await;

            let filter = Filter::new().id(event_id);
            let events = client
                .query(filter)
                .await
                .map_err(|e| format!("Failed to query relay for verification: {}", e))?;

            if !events.is_empty() {
                return Err(format!(
                    "Event was rejected but still stored: {}",
                    description
                ));
            }

            return Ok(()); // Rejected as expected
        } else {
            // Unexpected error (network, etc.)
            return Err(format!("Failed to send event to relay: {}", e));
        }
    }

    // Send succeeded, verify event was NOT stored (relay should have rejected)
    tokio::time::sleep(Duration::from_millis(100)).await;

    let filter = Filter::new().id(event_id);
    let events = client
        .query(filter)
        .await
        .map_err(|e| format!("Failed to query relay for verification: {}", e))?;

    if !events.is_empty() {
        return Err(format!("Event should be rejected: {}", description));
    }

    Ok(())
}

// ============================================================
// Git Operation Helpers
// ============================================================

use crate::git_command;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Run a git command in `repo_path` and fail on a non-zero exit.
///
/// Fixture steps whose success later pushes and hash assertions depend on
/// must not fail silently.
fn run_fixture_git(repo_path: &Path, args: &[&str]) -> Result<(), String> {
    let output = git_command()
        .args(args)
        .current_dir(repo_path)
        .output()
        .map_err(|e| format!("git {} failed to spawn: {}", args.join(" "), e))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

/// Clone a repository from the relay and return the path
///
/// # Arguments
/// * `relay_domain` - The domain of the relay (e.g., "localhost:7000")
/// * `npub` - The bech32 public key of the repository owner
/// * `repo_id` - The repository identifier (d-tag value)
///
/// # Returns
/// * `Ok(PathBuf)` - Path to the cloned repository
/// * `Err(String)` - Error message if clone failed
///
/// # Example
/// ```no_run
/// # use grasp_audit::*;
/// # fn example() -> Result<(), String> {
/// let clone_path = clone_repo("localhost:7000", "npub1...", "my-repo")?;
/// // Use the cloned repo...
/// std::fs::remove_dir_all(&clone_path).ok(); // Cleanup
/// # Ok(())
/// # }
/// ```
pub fn clone_repo(relay_domain: &str, npub: &str, repo_id: &str) -> Result<PathBuf, String> {
    let temp_base = std::env::temp_dir();
    let clone_dir_name = format!("grasp-push-test-{}", uuid::Uuid::new_v4());
    let clone_path = temp_base.join(&clone_dir_name);
    let _ = fs::remove_dir_all(&clone_path);

    let clone_url = format!("http://{}/{}/{}.git", relay_domain, npub, repo_id);
    let output = git_command()
        .args(["clone", &clone_url, clone_path.to_str().unwrap()])
        .output()
        .map_err(|e| format!("Failed to execute git clone: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Git clone failed: {}", stderr));
    }

    // Configure the committer identity the deterministic hashes are pinned to.
    run_fixture_git(
        &clone_path,
        &["config", "user.email", "test@grasp-audit.local"],
    )?;
    run_fixture_git(&clone_path, &["config", "user.name", "GRASP Audit Test"])?;

    Ok(clone_path)
}

/// Create a commit with a unique file and return the commit hash
///
/// # Arguments
/// * `clone_path` - Path to the git repository
/// * `message` - Commit message
///
/// # Returns
/// * `Ok(String)` - The commit hash
/// * `Err(String)` - Error message if commit failed
///
/// # Example
/// ```no_run
/// # use grasp_audit::*;
/// # use std::path::Path;
/// # fn example() -> Result<(), String> {
/// let commit_hash = create_commit(Path::new("/tmp/my-repo"), "My commit message")?;
/// println!("Created commit: {}", commit_hash);
/// # Ok(())
/// # }
/// ```
pub fn create_commit(clone_path: &Path, message: &str) -> Result<String, String> {
    let test_file = clone_path.join(format!("test-{}.txt", uuid::Uuid::new_v4()));
    fs::write(&test_file, message).map_err(|e| format!("Failed to write file: {}", e))?;

    let filename = test_file.file_name().unwrap().to_str().unwrap();
    let output = git_command()
        .args(["add", filename])
        .current_dir(clone_path)
        .output()
        .map_err(|e| format!("Git add failed: {}", e))?;

    if !output.status.success() {
        return Err("Git add failed".to_string());
    }

    let output = git_command()
        .args(["-c", "commit.gpgsign=false", "commit", "-m", message])
        .current_dir(clone_path)
        .output()
        .map_err(|e| format!("Git commit failed: {}", e))?;

    if !output.status.success() {
        return Err("Git commit failed".to_string());
    }

    let output = git_command()
        .args(["rev-parse", "HEAD"])
        .current_dir(clone_path)
        .output()
        .map_err(|e| format!("Git rev-parse failed: {}", e))?;

    if !output.status.success() {
        return Err("Failed to get commit hash".to_string());
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Variant of deterministic commit for different pubkey types
/// Each variant produces a different but reproducible commit hash
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitVariant {
    /// Main pubkey variant - uses "Initial commit" content
    Owner,
    /// Maintainer pubkey variant - uses "Maintainer initial commit" content
    Maintainer,
    /// Recursive maintainer pubkey variant - uses "Recursive maintainer initial commit" content
    RecursiveMaintainer,
    /// PR test commit variant - for PR event tests
    PRTestCommit,
    /// Second PR test commit variant - for second PR event tests
    PRTestCommit2,
}

impl CommitVariant {
    /// Get the file content for this variant
    pub fn file_content(&self) -> &'static str {
        match self {
            CommitVariant::Owner => "Initial commit\n",
            CommitVariant::Maintainer => "Maintainer initial commit\n",
            CommitVariant::RecursiveMaintainer => "Recursive maintainer initial commit\n",
            CommitVariant::PRTestCommit => "PR test deterministic commit\n",
            CommitVariant::PRTestCommit2 => "PR test deterministic commit 2\n",
        }
    }

    /// Get the commit message for this variant
    pub fn commit_message(&self) -> &'static str {
        match self {
            CommitVariant::Owner => "Initial commit",
            CommitVariant::Maintainer => "Maintainer initial commit",
            CommitVariant::RecursiveMaintainer => "Recursive maintainer initial commit",
            CommitVariant::PRTestCommit => "PR test deterministic commit",
            CommitVariant::PRTestCommit2 => "PR test deterministic commit 2",
        }
    }
}

/// Create a deterministic commit with fixed dates and GPG disabled
///
/// The variant parameter allows different commit hashes for different pubkey types:
/// - Owner: uses DETERMINISTIC_COMMIT_HASH
/// - Maintainer: uses MAINTAINER_DETERMINISTIC_COMMIT_HASH
/// - RecursiveMaintainer: uses RECURSIVE_MAINTAINER_DETERMINISTIC_COMMIT_HASH
///
/// # Arguments
/// * `clone_path` - Path to the git repository
/// * `variant` - The commit variant to create
///
/// # Returns
/// * `Ok(String)` - The deterministic commit hash
/// * `Err(String)` - Error message if commit failed
pub fn create_deterministic_commit_with_variant(
    clone_path: &Path,
    variant: CommitVariant,
) -> Result<String, String> {
    let test_file = clone_path.join("test.txt");
    let content = variant.file_content();
    let message = variant.commit_message();

    fs::write(&test_file, content).map_err(|e| format!("Failed to write file: {}", e))?;

    let output = git_command()
        .args(["add", "test.txt"])
        .current_dir(clone_path)
        .output()
        .map_err(|e| format!("Git add failed: {}", e))?;

    if !output.status.success() {
        return Err("Git add failed".to_string());
    }

    // Create deterministic commit with fixed dates and GPG disabled
    let output = git_command()
        .args(["-c", "commit.gpgsign=false", "commit", "-m", message])
        .env("GIT_AUTHOR_DATE", "2024-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2024-01-01T00:00:00Z")
        .current_dir(clone_path)
        .output()
        .map_err(|e| format!("Git commit failed: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Git commit failed: {}", stderr));
    }

    let output = git_command()
        .args(["rev-parse", "HEAD"])
        .current_dir(clone_path)
        .output()
        .map_err(|e| format!("Git rev-parse failed: {}", e))?;

    if !output.status.success() {
        return Err("Failed to get commit hash".to_string());
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Create a deterministic commit (Owner variant)
///
/// This is a convenience wrapper around `create_deterministic_commit_with_variant`
/// that uses the Owner variant for backwards compatibility.
///
/// # Arguments
/// * `clone_path` - Path to the git repository
/// * `_message` - Ignored for compatibility (Owner variant always uses "Initial commit")
///
/// # Returns
/// * `Ok(String)` - The deterministic commit hash
/// * `Err(String)` - Error message if commit failed
pub fn create_deterministic_commit(clone_path: &Path, _message: &str) -> Result<String, String> {
    // Note: message parameter is ignored for backwards compatibility
    // The Owner variant always uses "Initial commit"
    create_deterministic_commit_with_variant(clone_path, CommitVariant::Owner)
}

/// Attempt a git push and return success/failure
///
/// # Arguments
/// * `clone_path` - Path to the git repository
///
/// # Returns
/// * `Ok(true)` - Push succeeded
/// * `Ok(false)` - Push was rejected
/// * `Err(String)` - Error executing git push
///
/// # Example
/// ```no_run
/// # use grasp_audit::*;
/// # use std::path::Path;
/// # fn example() -> Result<(), String> {
/// let success = try_push(Path::new("/tmp/my-repo"))?;
/// if success {
///     println!("Push succeeded");
/// } else {
///     println!("Push was rejected");
/// }
/// # Ok(())
/// # }
/// ```
pub fn try_push(clone_path: &Path) -> Result<bool, String> {
    let output = git_command()
        .args(["push", "origin", "main", "--force"])
        .current_dir(clone_path)
        .output()
        .map_err(|e| format!("Failed to execute git push: {}", e))?;

    Ok(output.status.success())
}

/// Attempt a git push to a specific ref and return success/failure
///
/// This is used for testing refs/nostr/<event-id> push validation.
///
/// # Arguments
/// * `clone_path` - Path to the git repository
/// * `ref_name` - The ref to push to (e.g., "refs/nostr/<event-id>")
///
/// # Returns
/// * `Ok(true)` - Push succeeded
/// * `Ok(false)` - Push was rejected
/// * `Err(String)` - Error executing git push
///
/// # Example
/// ```no_run
/// # use grasp_audit::*;
/// # use std::path::Path;
/// # fn example() -> Result<(), String> {
/// let success = try_push_to_ref(Path::new("/tmp/my-repo"), "refs/nostr/abc123")?;
/// if success {
///     println!("Push to refs/nostr/abc123 succeeded");
/// } else {
///     println!("Push was rejected");
/// }
/// # Ok(())
/// # }
/// ```
pub fn try_push_to_ref(clone_path: &Path, ref_name: &str) -> Result<bool, String> {
    let output = git_command()
        .args(["push", "origin", &format!("HEAD:{}", ref_name)])
        .current_dir(clone_path)
        .output()
        .map_err(|e| format!("Failed to execute git push: {}", e))?;

    Ok(output.status.success())
}

/// Initialise a fresh local git repo with a remote URL configured, ready for push.
///
/// Creates a new git repository at `path`, configures user identity,
/// sets the default branch to `main`, and adds `remote_url` as the `origin` remote.
/// After calling this, use `create_commit()` then `try_push()`.
///
/// # Arguments
/// * `path` - Directory to initialise (must not already exist as a git repo)
/// * `remote_url` - The remote URL to add as `origin`
pub fn init_local_repo(path: &Path, remote_url: &str) -> Result<(), String> {
    // Step 1: git init <path>
    let output = git_command()
        .args(["init", path.to_str().unwrap_or(".")])
        .output()
        .map_err(|e| format!("Failed to execute git init: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git init failed: {}", stderr));
    }

    // Step 2: git config user.email
    let output = git_command()
        .args(["config", "user.email", "probe@grasp-audit.local"])
        .current_dir(path)
        .output()
        .map_err(|e| format!("Failed to set git user.email: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git config user.email failed: {}", stderr));
    }

    // Step 3: git config user.name
    let output = git_command()
        .args(["config", "user.name", "GRASP Probe"])
        .current_dir(path)
        .output()
        .map_err(|e| format!("Failed to set git user.name: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git config user.name failed: {}", stderr));
    }

    // Step 4: git symbolic-ref HEAD refs/heads/main (sets default branch to main)
    let output = git_command()
        .args(["symbolic-ref", "HEAD", "refs/heads/main"])
        .current_dir(path)
        .output()
        .map_err(|e| format!("Failed to set default branch: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git symbolic-ref HEAD failed: {}", stderr));
    }

    // Step 5: git remote add origin <remote_url>
    let output = git_command()
        .args(["remote", "add", "origin", remote_url])
        .current_dir(path)
        .output()
        .map_err(|e| format!("Failed to add remote: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git remote add origin failed: {}", stderr));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AuditConfig;

    #[test]
    fn test_context_mode_from_audit_mode() {
        assert_eq!(
            ContextMode::from(AuditMode::Isolated),
            ContextMode::Isolated
        );
        assert_eq!(ContextMode::from(AuditMode::Shared), ContextMode::Shared);
    }

    #[test]
    fn test_fixture_kind_hash() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(FixtureKind::ValidRepoSent);
        set.insert(FixtureKind::RepoWithIssue);

        assert!(set.contains(&FixtureKind::ValidRepoSent));
        assert!(!set.contains(&FixtureKind::RepoWithComment));
    }

    #[tokio::test]
    async fn test_context_creation() {
        let config = AuditConfig::isolated();
        let client = crate::AuditClient::new_test(config);

        let ctx = TestContext::new(&client);
        assert_eq!(ctx.mode(), ContextMode::Isolated);

        let ctx = TestContext::with_mode(&client, ContextMode::Shared);
        assert_eq!(ctx.mode(), ContextMode::Shared);
    }
}
