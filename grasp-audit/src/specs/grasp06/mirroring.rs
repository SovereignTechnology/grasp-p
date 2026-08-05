//! GRASP-06 cross-service mirror tests
//!
//! Spec source: design doc at
//! `docs/explanation/grasp-06-contributor-pr-submission.md`, "Cross-service
//! mirror" section. The contract is derived from the design — the 06.md spec
//! itself does not name this behaviour — but the design decision is settled
//! and the tests below pin it down so a regression would be visible.
//!
//! Two tests, complementary directions:
//!
//! - [`MirroringTests::test_prs_push_mirrors_to_announced_repo`]
//!   A `refs/nostr/<event-id>` push received at `/prs/<contributor>/<id>.git`,
//!   when paired with a PR event whose `a` tag references an accepted
//!   announcement on this relay, MUST appear at the announced repo too. The
//!   announced repo is the natural location for clients browsing the project.
//!
//! - [`MirroringTests::test_standard_push_does_not_mirror_to_prs`]
//!   The reverse direction MUST NOT mirror: a push to the standard
//!   `/<npub>/<id>.git` endpoint must not appear under `/prs/`. The /prs/
//!   namespace is a contributor-submission side-channel; conflating
//!   maintainer pushes into it would invent hosting locations the maintainer
//!   never declared.
//!
//! ## Fixture reuse
//!
//! Test 7 reuses [`FixtureKind::ValidRepoServed`] (which transitively triggers
//! `OwnerStateDataPushed` — see `src/fixtures.rs` deps map) to obtain an
//! accepted, served repo announcement to mirror INTO. Test 8 reuses
//! [`FixtureKind::PREvent2Served`] which already pushes a PR ref to the
//! standard endpoint; that is exactly the "push to standard, assert absent
//! from /prs/" precondition for the reverse-mirror check.
//!
//! ## Timing
//!
//! Mirroring is kicked off asynchronously from
//! `process_newly_available_git_data` after the /prs/ receive-pack completes.
//! The same receive-pack also releases the PR event from purgatory, so two
//! observable post-conditions follow the push:
//!
//! 1. The PR event becomes queryable (purgatory → served).
//! 2. The mirrored ref + objects appear at the announced repo.
//!
//! We sanity-check (1) first — if the event is never released, asserting
//! (2) is meaningless and would surface as a confusing "ref not found"
//! instead of the true root cause. The pattern mirrors the existing
//! fixtures (short fixed sleep + single `is_event_on_relay` check, e.g.
//! [`FixturesContext::build_pr_event_2_served`]). Then a second fixed
//! sleep before the ref-mirror probe — keeps the total wait close to
//! the original 2 s while making the two failure modes attributable.

use crate::git_command;
use crate::specs::grasp06::SpecRef;
use crate::{
    create_commit, init_local_repo, try_push_to_ref, AuditClient, FixtureKind, TestContext,
    TestResult,
};
use nostr_sdk::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub struct MirroringTests;

impl MirroringTests {
    /// Test 7: a `refs/nostr/<event-id>` push to `/prs/<contributor>/<id>.git`
    /// MUST be mirrored into the announced repo on this relay.
    ///
    /// Spec ref: [`SpecRef::Grasp06MirrorToAnnouncedRepo`] (design-doc derived).
    ///
    /// ## Setup
    ///
    /// 1. Ensure an accepted, served announcement at `<owner-npub>/<repo-id>.git`
    ///    via `FixtureKind::ValidRepoServed` (transitively pushes owner git data).
    /// 2. Materialise a throwaway commit locally and capture its hash. We
    ///    intentionally do NOT depend on the deterministic-commit helper
    ///    here — the spec contract is "c tag equals pushed commit", not
    ///    "commit equals some constant". Tying the test to
    ///    `PR_TEST_COMMIT_HASH` would couple it to commit-machinery
    ///    invariants this test doesn't care about; any hash will do as long
    ///    as we use the same one in both places.
    /// 3. Build a kind-1618 PR event signed by `pr_author_keys`:
    ///    - `a` tag references the owner's coord (`30617:<owner-hex>:<repo-id>`).
    ///    - `c` tag = the hash from step 2.
    ///    - `clone` tag = this relay's `/prs/<pr-author-npub>/<repo-id>.git`.
    /// 4. Publish the PR event. Acceptance via the standard GRASP-01 path is
    ///    expected (the coord IS announced); purgatory is fine too — the spec
    ///    contract under test is the mirror, not the acceptance path.
    /// 5. Push `HEAD:refs/nostr/<pr-event-id>` from the local repo to the
    ///    /prs/ URL.
    /// 6. Short wait, then verify the PR event has been released from
    ///    purgatory via `is_event_on_relay`. The same receive-pack that
    ///    triggers the mirror also releases the event, so this is the
    ///    first observable post-condition and the cleanest gate before
    ///    asserting the mirror itself. Pattern matches existing fixtures
    ///    (e.g. `build_pr_event_2_served`).
    /// 7. Short wait, then fetch `refs/nostr/<pr-event-id>` from the
    ///    standard `<owner>/<repo-id>.git` URL.
    /// 8. Verify the mirror: `git cat-file -e` on the expected commit hash
    ///    plus a `rev-parse` cross-check — proves both that the ref is
    ///    present AND that its commit object is reachable (the user's
    ///    verification choice — "clone the maintainer repo and verify
    ///    commit reachable").
    ///
    /// ## TDD posture
    ///
    /// Pre-implementation this fails: there is no /prs/ route at all, so the
    /// push gets 404. Once Phase 4 (receive-pack) and Phase 7 (mirror hook)
    /// land, the test turns green.
    pub async fn test_prs_push_mirrors_to_announced_repo(client: &AuditClient) -> TestResult {
        TestResult::new(
            super::test_ids::MIRROR_PRS_PUSH,
            SpecRef::Grasp06MirrorToAnnouncedRepo,
            "refs accepted via /prs/ MUST be mirrored into any matching accepted-announcement \
             repos on this relay",
        )
        .run(|| async {
            let ctx = TestContext::new(client);

            // 1. Ensure an accepted, served announcement on the standard
            //    endpoint. ValidRepoServed transitively triggers
            //    OwnerStateDataPushed so the maintainer's git data is also
            //    present — that's the "destination" the mirror copies into.
            let repo = ctx
                .get_fixture(FixtureKind::ValidRepoServed)
                .await
                .map_err(|e| format!("Failed to build ValidRepoServed fixture: {}", e))?;

            // 2. Resolve the coordinates needed for the test:
            //    - owner identity (signer of the announcement)
            //    - repo identifier (`d` tag of the announcement)
            //    - this relay's HTTP base for building URLs.
            let owner_pubkey_hex = repo.pubkey.to_hex();
            let owner_npub = repo
                .pubkey
                .to_bech32()
                .map_err(|e| format!("Failed to bech32-encode owner npub: {}", e))?;
            let repo_id = extract_repo_id(&repo)?;

            let ws_url = client
                .relay_url()
                .await
                .map_err(|e| format!("Failed to get relay URL: {}", e))?;
            let http_base = AuditClient::ws_to_http_url(&ws_url)
                .map_err(|e| format!("Failed to convert WebSocket URL to HTTP: {}", e))?;
            let http_base = http_base.trim_end_matches('/').to_string();

            let pr_author_npub = client
                .pr_author_keys()
                .public_key()
                .to_bech32()
                .map_err(|e| format!("Failed to bech32-encode pr_author npub: {}", e))?;

            let prs_url = format!("{}/prs/{}/{}.git", http_base, pr_author_npub, repo_id);
            let standard_url = format!("{}/{}/{}.git", http_base, owner_npub, repo_id);

            // 3. Local commit first. Materialising the commit BEFORE the PR
            //    event lets us pin the event's `c` tag to the exact hash we
            //    are about to push, decoupling this test from any
            //    deterministic-commit invariants. The commit content is
            //    arbitrary — only the hash matters.
            let workspace = TempPath::new("grasp06-mirror-fwd-");
            init_local_repo(&workspace.path, &prs_url)
                .map_err(|e| format!("Failed to init local workspace: {}", e))?;

            let commit_hash =
                create_commit(&workspace.path, "grasp-06 audit: PR commit for mirror test")
                    .map_err(|e| format!("Failed to create local commit: {}", e))?;

            // 4. Build & publish the PR event. The c tag pins the commit
            //    hash we materialised in step 3 — purgatory release for
            //    the matching push requires this match.
            let pr_event = client
                .event_builder(
                    Kind::GitPullRequest,
                    "grasp-06 audit: PR via /prs/ should mirror to announced repo",
                )
                .tag(Tag::custom(
                    "a",
                    vec![format!("30617:{}:{}", owner_pubkey_hex, repo_id)],
                ))
                .tag(Tag::custom("c", vec![commit_hash.clone()]))
                .tag(Tag::custom("clone", vec![prs_url.clone()]))
                .build(client.pr_author_keys())
                .map_err(|e| format!("Failed to build PR event: {}", e))?;
            let pr_event_id_typed = pr_event.id;
            let pr_event_id = pr_event_id_typed.to_hex();

            // send_event_and_note_purgatory is OK both for served and
            // purgatory acceptance — it only Errs on relay rejection, which
            // would be a setup failure for this test.
            client
                .send_event_and_note_purgatory(pr_event)
                .await
                .map_err(|e| format!("Relay rejected the PR event during test setup: {}", e))?;

            // 5. Push HEAD:refs/nostr/<pr-event-id> to the /prs/ URL.
            let refname = format!("refs/nostr/{}", pr_event_id);
            let push_ok = try_push_to_ref(&workspace.path, &refname).map_err(|e| {
                format!(
                    "git push HEAD:{} to {} failed to execute: {}",
                    refname, prs_url, e
                )
            })?;
            if !push_ok {
                return Err(format!(
                    "git push HEAD:{} to {} was rejected by the relay",
                    refname, prs_url
                ));
            }

            // 6. Verify the PR event has been released from purgatory.
            //    The receive-pack on /prs/ releases the event and kicks off
            //    the mirror; observing the release first gives a clear,
            //    separately-attributable error if the relay accepted-into-
            //    purgatory but never released, versus released-but-didn't-
            //    mirror. Pattern matches existing fixtures (short fixed
            //    sleep + single is_event_on_relay check).
            tokio::time::sleep(Duration::from_millis(300)).await;
            if !client
                .is_event_on_relay(pr_event_id_typed)
                .await
                .map_err(|e| format!("Failed to query relay for PR event served-status: {}", e))?
            {
                return Err(format!(
                    "PR event {} was accepted but not released from purgatory after pushing \
                     to {} — mirror precondition (purgatory release) did not hold",
                    pr_event_id, prs_url
                ));
            }

            // 7. Wait for the async mirror, then fetch the expected ref
            //    from the standard endpoint. `is_event_on_relay` already
            //    did a 1 s query, plus the 300 ms above, so the mirror has
            //    had >1 s of runway; an extra 1 s here keeps total wait
            //    around the previous 2 s budget while making the served
            //    check a distinct gate.
            tokio::time::sleep(Duration::from_secs(1)).await;

            let verify = TempPath::new("grasp06-mirror-fwd-verify-");
            init_local_repo(&verify.path, &standard_url)
                .map_err(|e| format!("Failed to init verify workspace: {}", e))?;

            let fetch_refspec = format!("{}:{}", refname, refname);
            let fetch_out = run_git(&verify.path, &["fetch", "origin", &fetch_refspec])
                .map_err(|e| format!("Failed to execute git fetch: {}", e))?;
            if !fetch_out.status.success() {
                let stderr = String::from_utf8_lossy(&fetch_out.stderr);
                return Err(format!(
                    "PR event {} was served but ref {} did not appear at {}: {} — mirror does \
                     not appear to have run",
                    pr_event_id,
                    refname,
                    standard_url,
                    stderr.trim()
                ));
            }

            // 8. Object-reachability: cat-file -e exits 0 iff the object exists
            // in the local object store (which now includes whatever the
            // mirror copied over).
            let cat_out = run_git(&verify.path, &["cat-file", "-e", &commit_hash])
                .map_err(|e| format!("Failed to execute git cat-file: {}", e))?;
            if !cat_out.status.success() {
                let stderr = String::from_utf8_lossy(&cat_out.stderr);
                return Err(format!(
                    "Mirror's commit object {} is not reachable in {}: {}",
                    commit_hash,
                    standard_url,
                    stderr.trim()
                ));
            }

            // Also sanity-check that the local ref now points at the same
            // commit — guards against a (currently hypothetical) bug where
            // the relay mirrors objects but writes a stale ref value.
            let rev_out = run_git(&verify.path, &["rev-parse", &refname])
                .map_err(|e| format!("Failed to execute git rev-parse: {}", e))?;
            if !rev_out.status.success() {
                let stderr = String::from_utf8_lossy(&rev_out.stderr);
                return Err(format!(
                    "git rev-parse {} failed after fetch: {}",
                    refname,
                    stderr.trim()
                ));
            }
            let mirrored_hash = String::from_utf8_lossy(&rev_out.stdout).trim().to_string();
            if mirrored_hash != commit_hash {
                return Err(format!(
                    "Mirrored ref {} points at {} but expected {}",
                    refname, mirrored_hash, commit_hash
                ));
            }

            Ok(())
        })
        .await
    }

    /// Test 7b: git-first ordering — when the push to `/prs/` arrives
    /// BEFORE the matching PR event, the event MUST still be promoted out
    /// of purgatory on arrival and the mirror MUST still fire.
    ///
    /// Spec ref: [`SpecRef::Grasp06MirrorToAnnouncedRepo`]. The mirror
    /// contract is order-independent — the design doc's "Git-first" flow
    /// (`docs/explanation/grasp-06-contributor-pr-submission.md` lines
    /// 204–218) says: "Event arrives: ... ref locked; event promoted."
    /// Promotion + mirror must fire in this ordering too, not only in
    /// event-first.
    ///
    /// ## Why this is distinct from test 7
    ///
    /// Test 7 publishes the PR event first, then pushes. That exercises
    /// the path where `process_newly_available_git_data` (called from the
    /// `/prs/` receive handler) finds a full PR entry waiting in
    /// purgatory and releases it. The git-first ordering hits a different
    /// code path: the `/prs/` push creates a *scoped placeholder*; when
    /// the event arrives later, the PR-event policy is responsible for
    /// matching the placeholder, validating the (signer, identifier,
    /// commit) tuple, saving the event to the DB, and triggering the
    /// mirror. A green test 7 does not imply this path works.
    ///
    /// ## Timing
    ///
    /// No long wait is required — promotion is supposed to happen
    /// immediately on the event's arrival. We reuse the same short fixed
    /// sleeps as test 7 (300 ms before the served check, then 1 s before
    /// the mirror probe) so timing-flake behaviour stays comparable
    /// across the two ordering variants.
    ///
    /// ## TDD posture
    ///
    /// Pre-implementation this fails: the policy in
    /// `src/nostr/policy/pr_event.rs::git_data_check` matches the scoped
    /// placeholder, removes it, then falls through to
    /// `find_relevant_repo_paths`, which only returns DB-resident
    /// announcement paths. For un-announced coords that list is empty
    /// and the function returns `Ok(false)` — the builder then re-adds
    /// the event to purgatory as a *scopeless* full entry, where it sits
    /// until 30-minute expiry. The event is never saved to the DB, the
    /// mirror never fires, and the orphan ref at `/prs/` survives until
    /// the next startup scan picks up a zero-ref repo.
    pub async fn test_prs_push_then_pr_event_promotes_and_mirrors(
        client: &AuditClient,
    ) -> TestResult {
        TestResult::new(
            super::test_ids::PROMOTE_AND_MIRROR_GIT_FIRST,
            SpecRef::Grasp06MirrorToAnnouncedRepo,
            "git-first ordering: when a /prs/ push arrives before the PR event, the event MUST \
             still be promoted out of purgatory on arrival and the mirror MUST still fire",
        )
        .run(|| async {
            let ctx = TestContext::new(client);

            // 1. Same destination setup as test 7 — an accepted, served
            //    announcement on the standard endpoint to mirror INTO. Built
            //    via ValidRepoServed which transitively pushes the owner's
            //    git data.
            let repo = ctx
                .get_fixture(FixtureKind::ValidRepoServed)
                .await
                .map_err(|e| format!("Failed to build ValidRepoServed fixture: {}", e))?;

            // 2. Resolve coords / URLs. Same shape as test 7.
            let owner_pubkey_hex = repo.pubkey.to_hex();
            let owner_npub = repo
                .pubkey
                .to_bech32()
                .map_err(|e| format!("Failed to bech32-encode owner npub: {}", e))?;
            let repo_id = extract_repo_id(&repo)?;

            let ws_url = client
                .relay_url()
                .await
                .map_err(|e| format!("Failed to get relay URL: {}", e))?;
            let http_base = AuditClient::ws_to_http_url(&ws_url)
                .map_err(|e| format!("Failed to convert WebSocket URL to HTTP: {}", e))?;
            let http_base = http_base.trim_end_matches('/').to_string();

            let pr_author_npub = client
                .pr_author_keys()
                .public_key()
                .to_bech32()
                .map_err(|e| format!("Failed to bech32-encode pr_author npub: {}", e))?;

            let prs_url = format!("{}/prs/{}/{}.git", http_base, pr_author_npub, repo_id);
            let standard_url = format!("{}/{}/{}.git", http_base, owner_npub, repo_id);

            // 3. Materialise the commit locally first — we need its hash for
            //    the PR event's `c` tag, and we need the event built (but
            //    NOT yet published) so we can pin the push refname to the
            //    event id before the relay ever sees the event.
            let workspace = TempPath::new("grasp06-mirror-git-first-");
            init_local_repo(&workspace.path, &prs_url)
                .map_err(|e| format!("Failed to init local workspace: {}", e))?;

            let commit_hash = create_commit(
                &workspace.path,
                "grasp-06 audit: PR commit for git-first mirror test",
            )
            .map_err(|e| format!("Failed to create local commit: {}", e))?;

            // 4. Build & sign the PR event but DO NOT publish it yet. The
            //    event-id we use to build the push refname must come from
            //    the same event we will later publish, so building here
            //    (without sending) is the cleanest way to bind the two.
            let pr_event = client
                .event_builder(
                    Kind::GitPullRequest,
                    "grasp-06 audit: git-first PR via /prs/ should still promote + mirror",
                )
                .tag(Tag::custom(
                    "a",
                    vec![format!("30617:{}:{}", owner_pubkey_hex, repo_id)],
                ))
                .tag(Tag::custom("c", vec![commit_hash.clone()]))
                .tag(Tag::custom("clone", vec![prs_url.clone()]))
                .build(client.pr_author_keys())
                .map_err(|e| format!("Failed to build PR event: {}", e))?;
            let pr_event_id_typed = pr_event.id;
            let pr_event_id = pr_event_id_typed.to_hex();

            // 5. PUSH FIRST. The relay sees no matching event in DB or
            //    purgatory, so per the spec's git-first flow it creates a
            //    scoped placeholder keyed by event-id, with submitter +
            //    identifier from the URL. Asserting the push is accepted
            //    here is a precondition check — if the push itself is
            //    rejected the rest of the test is meaningless and we want
            //    a clear error pointing at the receive-pack contract
            //    rather than the promotion contract.
            let refname = format!("refs/nostr/{}", pr_event_id);
            let push_ok = try_push_to_ref(&workspace.path, &refname).map_err(|e| {
                format!(
                    "git push HEAD:{} to {} failed to execute: {}",
                    refname, prs_url, e
                )
            })?;
            if !push_ok {
                return Err(format!(
                    "git push HEAD:{} to {} was rejected by the relay — git-first ordering \
                     precondition (push acceptance into a scoped placeholder) did not hold",
                    refname, prs_url
                ));
            }

            // 6. NOW publish the PR event. Per the design doc's "Git-first"
            //    flow: the relay finds the matching scoped placeholder by
            //    event-id, validates (signer, identifier, commit) — all
            //    match by construction — and MUST promote the event:
            //    save to DB, remove placeholder, broadcast to subscribers,
            //    and trigger the cross-service mirror into any matching
            //    announced repo.
            client
                .send_event_and_note_purgatory(pr_event)
                .await
                .map_err(|e| format!("Relay rejected the PR event after the /prs/ push: {}", e))?;

            // 7. Verify the PR event is served. Same gating as test 7 —
            //    if the event never leaves purgatory the mirror assertion
            //    below is meaningless and the failure mode would be
            //    confusing.
            tokio::time::sleep(Duration::from_millis(300)).await;
            if !client
                .is_event_on_relay(pr_event_id_typed)
                .await
                .map_err(|e| format!("Failed to query relay for PR event served-status: {}", e))?
            {
                return Err(format!(
                    "PR event {} arrived after a matching /prs/ push but was NOT promoted out \
                     of purgatory — git-first promotion contract (design doc lines 204–218: \
                     \"ref locked; event promoted\") did not hold. The event-driven policy \
                     branch that matches scoped placeholders is not saving the event to the \
                     DB.",
                    pr_event_id
                ));
            }

            // 8. Same mirror probe as test 7. The ref + commit must be
            //    fetchable from the announced repo on the standard
            //    endpoint, proving the cross-service mirror fired in this
            //    ordering too.
            tokio::time::sleep(Duration::from_secs(1)).await;

            let verify = TempPath::new("grasp06-mirror-git-first-verify-");
            init_local_repo(&verify.path, &standard_url)
                .map_err(|e| format!("Failed to init verify workspace: {}", e))?;

            let fetch_refspec = format!("{}:{}", refname, refname);
            let fetch_out = run_git(&verify.path, &["fetch", "origin", &fetch_refspec])
                .map_err(|e| format!("Failed to execute git fetch: {}", e))?;
            if !fetch_out.status.success() {
                let stderr = String::from_utf8_lossy(&fetch_out.stderr);
                return Err(format!(
                    "PR event {} was served but ref {} did not appear at {}: {} — git-first \
                     mirror does not appear to have run. The placeholder match in \
                     `src/nostr/policy/pr_event.rs::git_data_check` removes the placeholder \
                     but does not run the mirror branch that `process_newly_available_git_data` \
                     runs for event-first ordering.",
                    pr_event_id,
                    refname,
                    standard_url,
                    stderr.trim()
                ));
            }

            let cat_out = run_git(&verify.path, &["cat-file", "-e", &commit_hash])
                .map_err(|e| format!("Failed to execute git cat-file: {}", e))?;
            if !cat_out.status.success() {
                let stderr = String::from_utf8_lossy(&cat_out.stderr);
                return Err(format!(
                    "Mirror's commit object {} is not reachable in {}: {}",
                    commit_hash,
                    standard_url,
                    stderr.trim()
                ));
            }

            let rev_out = run_git(&verify.path, &["rev-parse", &refname])
                .map_err(|e| format!("Failed to execute git rev-parse: {}", e))?;
            if !rev_out.status.success() {
                let stderr = String::from_utf8_lossy(&rev_out.stderr);
                return Err(format!(
                    "git rev-parse {} failed after fetch: {}",
                    refname,
                    stderr.trim()
                ));
            }
            let mirrored_hash = String::from_utf8_lossy(&rev_out.stdout).trim().to_string();
            if mirrored_hash != commit_hash {
                return Err(format!(
                    "Mirrored ref {} points at {} but expected {}",
                    refname, mirrored_hash, commit_hash
                ));
            }

            Ok(())
        })
        .await
    }

    /// Test 8: a `refs/nostr/<event-id>` push to the standard
    /// `<npub>/<id>.git` endpoint MUST NOT appear under `/prs/`.
    ///
    /// Spec ref: [`SpecRef::Grasp06NoReverseMirror`] (design-doc derived).
    ///
    /// ## Setup
    ///
    /// 1. Use [`FixtureKind::PREvent2Served`] which:
    ///    - publishes a kind-1618 PR event signed by `pr_author_keys`,
    ///    - pushes a matching `refs/nostr/<pr-event-id>` to the standard
    ///      `<owner>/<repo-id>.git` endpoint,
    ///    - confirms the event is served (i.e. released from purgatory).
    ///
    ///    No /prs/ activity is involved.
    /// 2. Probe `/prs/<pr-author-npub>/<repo-id>.git` with `git ls-remote`
    ///    filtered to `refs/nostr/<pr-event-id>`.
    ///
    /// ## Pass condition
    ///
    /// `ls-remote` exits 0 with empty stdout for the filtered refname.
    /// Per 06.md line 11 the endpoint MUST respond as an empty bare repo
    /// when nothing was pushed to it; an absent ref + clean exit is exactly
    /// the "empty repo" shape. A non-empty stdout for the filter means the
    /// reverse-mirror fired — that's the regression this test guards.
    ///
    /// ## TDD posture
    ///
    /// Pre-implementation this fails: `/prs/` doesn't route, so `ls-remote`
    /// errors with 404 and the test reports the failure as a setup error.
    /// Once Phase 3 (routing) and the empty-repo synthesis land, the
    /// endpoint becomes reachable and this test goes green — and stays
    /// green as long as the relay never adds a reverse-mirror branch.
    pub async fn test_standard_push_does_not_mirror_to_prs(client: &AuditClient) -> TestResult {
        TestResult::new(
            super::test_ids::NO_REVERSE_MIRROR,
            SpecRef::Grasp06NoReverseMirror,
            "the reverse direction MUST NOT mirror: a push to /<npub>/<id>.git must not appear \
             under /prs/",
        )
        .run(|| async {
            let ctx = TestContext::new(client);

            // 1. Ensure a PR ref is present at the standard endpoint. The
            //    fixture asserts the event is served, so the standard push
            //    has unambiguously happened by the time we get here.
            let pr_event = ctx
                .get_fixture(FixtureKind::PREvent2Served)
                .await
                .map_err(|e| format!("Failed to build PREvent2Served fixture: {}", e))?;
            let pr_event_id = pr_event.id.to_hex();

            // 2. The fixture's PR event is keyed against the owner's
            //    coord. Extract the d-tag from the underlying repo
            //    announcement (ValidRepoServed) so we can build the matching
            //    /prs/<pr-author>/<repo-id>.git URL.
            let repo = ctx
                .get_fixture(FixtureKind::ValidRepoServed)
                .await
                .map_err(|e| format!("Failed to build ValidRepoServed fixture: {}", e))?;
            let repo_id = extract_repo_id(&repo)?;

            // 3. Build the /prs/ URL for the contributor (pr_author).
            let ws_url = client
                .relay_url()
                .await
                .map_err(|e| format!("Failed to get relay URL: {}", e))?;
            let http_base = AuditClient::ws_to_http_url(&ws_url)
                .map_err(|e| format!("Failed to convert WebSocket URL to HTTP: {}", e))?;
            let http_base = http_base.trim_end_matches('/').to_string();
            let pr_author_npub = client
                .pr_author_keys()
                .public_key()
                .to_bech32()
                .map_err(|e| format!("Failed to bech32-encode pr_author npub: {}", e))?;
            let prs_url = format!("{}/prs/{}/{}.git", http_base, pr_author_npub, repo_id);

            // 4. ls-remote with a refname filter. We do NOT introduce a
            //    test-local wait here — the standard push completed before
            //    PREvent2Served returned, so any reverse-mirror would have
            //    had ample time to run. A negative result here is a real
            //    "didn't happen, won't happen" signal.
            let refname = format!("refs/nostr/{}", pr_event_id);
            let out = git_command()
                .args(["ls-remote", &prs_url, &refname])
                .output()
                .map_err(|e| format!("Failed to execute git ls-remote {}: {}", prs_url, e))?;

            if !out.status.success() {
                // A failed ls-remote almost certainly means the /prs/
                // endpoint doesn't exist (pre-implementation 404) or the
                // relay refused. Either way this test can't make its
                // assertion meaningfully, so surface it as a clear setup
                // failure rather than passing trivially.
                let stderr = String::from_utf8_lossy(&out.stderr);
                return Err(format!(
                    "git ls-remote {} {} failed (exit {}): {} — /prs/ endpoint must be reachable \
                     for this test to assert the reverse-mirror contract (06.md line 11 requires \
                     an empty-bare-repo response for any well-formed /prs/ path)",
                    prs_url,
                    refname,
                    out.status.code().unwrap_or(-1),
                    stderr.trim()
                ));
            }

            // 5. Pass condition: empty stdout. With the refname filter set,
            //    any non-empty line is exactly the reverse-mirror regression
            //    we are guarding against.
            let stdout = String::from_utf8_lossy(&out.stdout);
            let lines: Vec<&str> = stdout
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .collect();
            if !lines.is_empty() {
                return Err(format!(
                    "Reverse mirror appears to have fired: standard endpoint push for PR event \
                     {} is also visible at {} — `git ls-remote ... {}` returned:\n  {}",
                    pr_event_id,
                    prs_url,
                    refname,
                    lines.join("\n  ")
                ));
            }

            Ok(())
        })
        .await
    }
}

// =============================================================================
// Helpers — kept module-local; promote to the audit lib if a second consumer
// wants them.
// =============================================================================

/// Extract the `d` tag (repo identifier) from a kind-30617 repo announcement.
fn extract_repo_id(repo: &Event) -> Result<String, String> {
    repo.tags
        .iter()
        .find(|t| t.kind() == "d")
        .and_then(|t| t.content())
        .map(str::to_string)
        .ok_or_else(|| "Missing `d` tag in repo announcement".to_string())
}

/// A temp directory that wipes itself on drop. Used here to keep the verify
/// and push workspaces from leaking on test failure paths.
struct TempPath {
    path: PathBuf,
}

impl TempPath {
    fn new(prefix: &str) -> Self {
        let path = std::env::temp_dir().join(format!("{}{}", prefix, uuid::Uuid::new_v4()));
        let _ = fs::remove_dir_all(&path);
        Self { path }
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Run a `git` command in `cwd` and return the [`std::process::Output`]
/// unchanged. The caller decides whether non-zero exit is failure.
fn run_git(cwd: &Path, args: &[&str]) -> std::io::Result<std::process::Output> {
    git_command().args(args).current_dir(cwd).output()
}
