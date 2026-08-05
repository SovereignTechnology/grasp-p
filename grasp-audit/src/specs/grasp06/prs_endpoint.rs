//! GRASP-06 /prs/ endpoint tests
//!
//! Spec: <https://github.com/DanConwayDev/grasp/blob/main/06.md>
//!
//! Each test here maps 1:1 to a MUST in the spec, or to an audit-derived
//! invariant that follows directly from NIP-11 discovery semantics.

use crate::git_command;
use crate::specs::grasp06::fixtures::advertises_grasp;
use crate::specs::grasp06::SpecRef;
use crate::{
    create_commit, init_local_repo, try_push_to_ref, AuditClient, TestContext, TestResult,
};
use nostr_sdk::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub struct PrsEndpointTests;

impl PrsEndpointTests {
    /// Test: if NIP-11 does not advertise GRASP-06, the `/prs/<npub>/<id>.git`
    /// namespace MUST return 404.
    ///
    /// This is the discovery gate: clients use NIP-11 `supported_grasps` to
    /// decide whether a relay implements GRASP-06. If a relay serves `/prs/`
    /// but does not advertise it, capability discovery is broken.
    ///
    /// Branches:
    /// - NIP-11 lists `GRASP-06`  -> test trivially passes (precondition not met).
    /// - NIP-11 does not list it -> `GET /prs/<valid-npub>/anything.git/info/refs?service=git-upload-pack`
    ///   MUST return HTTP 404.
    pub async fn test_prs_namespace_404_when_grasp06_not_advertised(
        client: &AuditClient,
    ) -> TestResult {
        TestResult::new(
            super::test_ids::NAMESPACE_404_WHEN_NOT_ADVERTISED,
            SpecRef::Grasp06NotAdvertised404,
            "MUST return 404 on /prs/ when GRASP-06 is not advertised in NIP-11",
        )
        .run(|| async {
            let ctx = TestContext::new(client);

            // 1. Capability check via the shared NIP-11 fixture.
            let advertised = advertises_grasp(&ctx, "GRASP-06")
                .await
                .map_err(|e| format!("Failed to determine GRASP-06 advertisement: {}", e))?;

            if advertised {
                // Precondition not met — the gate doesn't apply. Pass trivially;
                // the "what /prs/ must do when advertised" behaviour is covered
                // by other tests in this module.
                return Ok(());
            }

            // 2. Resolve the HTTP base URL for the probe.
            let ws_url = client
                .relay_url()
                .await
                .map_err(|e| format!("Failed to get relay URL: {}", e))?;
            let http_url = AuditClient::ws_to_http_url(&ws_url)
                .map_err(|e| format!("Failed to convert WebSocket URL to HTTP: {}", e))?;

            // 3. Build a /prs/<valid-npub>/<id>.git/info/refs URL with a known-valid
            //    npub. Using a fresh random npub guarantees no implementation could
            //    have a repo there by accident.
            let probe_keys = nostr_sdk::prelude::Keys::generate();
            let probe_npub = probe_keys
                .public_key()
                .to_bech32()
                .map_err(|e| format!("Failed to bech32-encode probe npub: {}", e))?;

            let probe_url = format!(
                "{}/prs/{}/audit-probe.git/info/refs?service=git-upload-pack",
                http_url.trim_end_matches('/'),
                probe_npub
            );

            let http_client = reqwest::Client::new();
            let response = http_client
                .get(&probe_url)
                .send()
                .await
                .map_err(|e| format!("Failed to GET {}: {}", probe_url, e))?;

            // 4. The spec gate: must be 404 (not 200, not 401, not 403, not 503).
            if response.status() != reqwest::StatusCode::NOT_FOUND {
                return Err(format!(
                    "Expected 404 on /prs/ when GRASP-06 not advertised in NIP-11, \
                     got {} from {}",
                    response.status(),
                    probe_url
                ));
            }

            Ok(())
        })
        .await
    }

    /// Test: fetching any well-formed `/prs/<npub>/<id>.git` path that has no
    /// accepted `refs/nostr/<event-id>` MUST respond as if serving an empty
    /// bare repository.
    ///
    /// Spec: 06.md line 11 — "MUST respond to upload-pack requests for any
    /// well-formed path as if serving an empty bare repository until at least
    /// one `refs/nostr/<event-id>` has been accepted for that path."
    ///
    /// The test asserts the spec invariant unconditionally — `git clone` of a
    /// fresh random `/prs/<npub>/<id>.git` MUST succeed and produce a
    /// repository with zero refs. Pre-implementation this fails as a TDD red:
    /// the relay has no `/prs/` route, so the clone gets 404 and the test
    /// reports the failure.
    ///
    /// Gating on NIP-11 advertisement is a caller concern, not part of the
    /// assertion: this test is wired into `isolated_test_with_grasp_06!` only,
    /// so the harness already encodes the expectation that GRASP-06 is
    /// enabled on the target relay. For CLI use against an arbitrary relay
    /// the caller would either skip this test when NIP-11 doesn't advertise
    /// GRASP-06, or rely on the discovery-gate test
    /// (`test_prs_namespace_404_when_grasp06_not_advertised`) to cover the
    /// "off" case.
    pub async fn test_prs_fetch_unknown_path_serves_empty_repo(client: &AuditClient) -> TestResult {
        TestResult::new(
            super::test_ids::FETCH_UNKNOWN_PATH,
            SpecRef::Grasp06FetchEmptyRepo,
            "MUST serve empty bare repo on fetch for any well-formed /prs/ path \
             until refs/nostr/<event-id> has been accepted",
        )
        .run(|| async {
            // 1. Resolve the HTTP base URL.
            let ws_url = client
                .relay_url()
                .await
                .map_err(|e| format!("Failed to get relay URL: {}", e))?;
            let http_url = AuditClient::ws_to_http_url(&ws_url)
                .map_err(|e| format!("Failed to convert WebSocket URL to HTTP: {}", e))?;

            // 2. Build a /prs/<valid-npub>/<random-id>.git URL. Using fresh
            //    random keys and a UUID identifier guarantees no implementation
            //    could have prior state for this path.
            let probe_keys = nostr_sdk::prelude::Keys::generate();
            let probe_npub = probe_keys
                .public_key()
                .to_bech32()
                .map_err(|e| format!("Failed to bech32-encode probe npub: {}", e))?;
            let probe_id = format!("audit-probe-{}", uuid::Uuid::new_v4());

            let clone_url = format!(
                "{}/prs/{}/{}.git",
                http_url.trim_end_matches('/'),
                probe_npub,
                probe_id
            );

            // 3. Clone into a fresh temp dir. Existing GitCloneTests follows
            //    the same temp_dir + UUID pattern; reused here for consistency.
            let temp_base = std::env::temp_dir();
            let clone_path =
                temp_base.join(format!("grasp06-empty-clone-{}", uuid::Uuid::new_v4()));
            let _ = fs::remove_dir_all(&clone_path);

            let cleanup = || {
                let _ = fs::remove_dir_all(&clone_path);
            };

            let clone_output = git_command()
                .args(["clone", &clone_url, clone_path.to_str().unwrap()])
                .output();

            let clone_output = match clone_output {
                Ok(o) => o,
                Err(e) => {
                    cleanup();
                    return Err(format!("Failed to execute git clone: {}", e));
                }
            };

            if !clone_output.status.success() {
                let stderr = String::from_utf8_lossy(&clone_output.stderr).to_string();
                cleanup();
                return Err(format!("git clone {} failed: {}", clone_url, stderr.trim()));
            }

            // 4. Verify the cloned repo has zero refs. `for-each-ref` lists
            //    every ref one-per-line; empty stdout means no refs at all,
            //    which is the spec's "empty bare repository" invariant.
            let refs_output = git_command()
                .args(["-C", clone_path.to_str().unwrap(), "for-each-ref"])
                .output();

            let refs_output = match refs_output {
                Ok(o) => o,
                Err(e) => {
                    cleanup();
                    return Err(format!("Failed to execute git for-each-ref: {}", e));
                }
            };

            if !refs_output.status.success() {
                let stderr = String::from_utf8_lossy(&refs_output.stderr).to_string();
                cleanup();
                return Err(format!(
                    "git for-each-ref failed in cloned repo: {}",
                    stderr.trim()
                ));
            }

            let refs_stdout = String::from_utf8_lossy(&refs_output.stdout).to_string();
            if !refs_stdout.trim().is_empty() {
                cleanup();
                return Err(format!(
                    "Expected empty bare repo, but clone of {} contained refs:\n{}",
                    clone_url,
                    refs_stdout.trim()
                ));
            }

            cleanup();
            Ok(())
        })
        .await
    }

    /// Test: a `git push` of `refs/nostr/<event-id>` to a fresh
    /// `/prs/<npub>/<id>.git` path MUST succeed.
    ///
    /// Spec: 06.md line 13 — "MUST accept pushes to `refs/nostr/<event-id>`."
    ///
    /// Setup is intentionally minimal:
    /// - Fresh contributor keys → `<npub>` for the URL.
    /// - Random UUID `<id>` for the URL (guarantees a path with no prior state).
    /// - Random 64-hex string for `<event-id>` (event-id shape — no matching
    ///   event is required for the push itself to be accepted; the spec's
    ///   20-minute "delete if no matching event" rule is a separate SHOULD and
    ///   is out of scope for this audit).
    /// - A throwaway local git repo with a single commit to push.
    ///
    /// Pre-implementation this test FAILS (TDD red) — the relay has no /prs/
    /// route, so the push gets 404. Once Phase 3+4 land (routing + receive
    /// handler with the ref-name validator), this turns green.
    pub async fn test_prs_push_refs_nostr_event_id_accepted(client: &AuditClient) -> TestResult {
        TestResult::new(
            super::test_ids::PUSH_NOSTR_REF,
            SpecRef::Grasp06AcceptRefsNostrPush,
            "MUST accept pushes to refs/nostr/<event-id> on /prs/<npub>/<id>.git",
        )
        .run(|| async {
            // 1. Resolve the HTTP base URL.
            let ws_url = client
                .relay_url()
                .await
                .map_err(|e| format!("Failed to get relay URL: {}", e))?;
            let http_url = AuditClient::ws_to_http_url(&ws_url)
                .map_err(|e| format!("Failed to convert WebSocket URL to HTTP: {}", e))?;

            // 2. Build the /prs/ URL. Fresh random keys + UUID guarantee an
            //    empty path on the relay.
            let prs_url = build_fresh_prs_url(&http_url)?;

            // 3. Build a local repo with one commit to push. The commit's
            //    content doesn't matter — only the ref name being pushed to.
            let workspace = LocalWorkspace::init()?;

            // 4. Synthesize an event-id-shaped string: 64-char lower hex.
            //    Using a fresh pubkey's hex form is a convenient way to get
            //    64-hex without pulling in a `rand` dep. No matching event
            //    will ever exist; that's fine — the spec's contract here is
            //    push acceptance, not purgatory release.
            let event_id_hex = nostr_sdk::prelude::Keys::generate().public_key().to_hex();
            let refname = format!("refs/nostr/{}", event_id_hex);

            // 5. Push. Success means: relay routes /prs/, accepts our ref
            //    name, runs git-receive-pack, and writes the ref.
            let push_output = git_push(&workspace.path, &prs_url, &refname);

            // Workspace cleans itself on drop, but we want to format any
            // error before the drop runs to keep messages readable.
            match push_output {
                Ok(out) if out.status.success() => Ok(()),
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    Err(format!(
                        "git push HEAD:{} to {} failed (exit {}): {}",
                        refname,
                        prs_url,
                        out.status.code().unwrap_or(-1),
                        stderr.trim()
                    ))
                }
                Err(e) => Err(format!("Failed to execute git push: {}", e)),
            }
        })
        .await
    }

    /// Test: pushes to ref namespaces other than `refs/nostr/<64-hex-event-id>`
    /// MUST be rejected.
    ///
    /// Spec: 06.md line 13 — "MUST reject pushes to any other ref namespace."
    /// Implementation plan Phase 4 clarifies that the validator requires
    /// `refs/nostr/<64-hex>`, so non-hex values under `refs/nostr/*` are also
    /// "other ref namespace" for the purposes of this contract.
    ///
    /// Two sub-assertions exercised against fresh /prs/ paths each (so a
    /// rejected push to one URL can't possibly affect the other):
    /// - `refs/heads/main` — wrong top-level namespace.
    /// - `refs/nostr/<not-64-hex>` — right top-level namespace but invalid
    ///   event-id shape (clearly non-hex, clearly wrong length).
    ///
    /// ## Why a "not found" stderr is treated as a test failure
    ///
    /// Spec line 11 requires that any well-formed `/prs/<npub>/<id>.git` path
    /// respond as an empty bare repo (i.e. the endpoint must be reachable).
    /// If a push gets a 404, the endpoint doesn't exist — the rejection is
    /// trivial and tells us nothing about the ref-name validator. To stay
    /// useful as TDD red pre-implementation AND as a regression guard
    /// post-implementation, the test distinguishes:
    /// - push fails with HTTP 404 ("repository ... not found") → **test
    ///   fails** with "endpoint not implemented".
    /// - push fails any other way (typically ERR pkt-line from
    ///   git-receive-pack) → **test passes**: rejection is from the
    ///   validator, which is what the spec requires.
    pub async fn test_prs_push_other_refs_rejected(client: &AuditClient) -> TestResult {
        TestResult::new(
            super::test_ids::REJECT_OTHER_REFS,
            SpecRef::Grasp06RejectNonNostrRefs,
            "MUST reject pushes to anything other than refs/nostr/<64-hex-event-id> \
             on /prs/<npub>/<id>.git",
        )
        .run(|| async {
            // 1. Resolve the HTTP base URL once — reused for both sub-pushes.
            let ws_url = client
                .relay_url()
                .await
                .map_err(|e| format!("Failed to get relay URL: {}", e))?;
            let http_url = AuditClient::ws_to_http_url(&ws_url)
                .map_err(|e| format!("Failed to convert WebSocket URL to HTTP: {}", e))?;

            // 2. One local repo with one commit is enough — `git push`
            //    accepts the destination URL per invocation, so we can drive
            //    both sub-cases from the same workspace.
            let workspace = LocalWorkspace::init()?;

            // Sub-case (a): refs/heads/main — wrong top-level namespace.
            //   Fresh /prs/ URL so the path can't have any prior state from
            //   earlier tests in the same run.
            let prs_url_a = build_fresh_prs_url(&http_url)?;
            let refname_a = "refs/heads/main".to_string();
            check_push_rejected_not_404(&workspace.path, &prs_url_a, &refname_a)?;

            // Sub-case (b): refs/nostr/<not-hex> — right top-level prefix,
            //   wrong event-id shape. Non-hex characters and wrong length.
            let prs_url_b = build_fresh_prs_url(&http_url)?;
            let refname_b = "refs/nostr/not-a-valid-event-id".to_string();
            check_push_rejected_not_404(&workspace.path, &prs_url_b, &refname_b)?;

            Ok(())
        })
        .await
    }
}

// =============================================================================
// Push validation tests
// =============================================================================

pub struct PushValidationTests;

impl PushValidationTests {
    /// Test: when a push arrives at `/prs/` and the matching PR event's `c` tag
    /// does not equal the pushed commit, the ref MUST be deleted and the event
    /// MUST NOT be promoted out of purgatory.
    ///
    /// Spec ref: [`SpecRef::Grasp06CommitMismatchDeletesRef`] (design-doc push
    /// semantics table, line 96: "commit ≠ event's c tag → delete ref").
    ///
    /// ## Why this matters
    ///
    /// The `c` tag is the binding between a signed PR event and the git objects
    /// it claims to represent. If the relay accepted a mismatched push, a
    /// contributor could push arbitrary commits under a foreign event-id, or an
    /// attacker could substitute a different commit for a signed PR. The delete
    /// path is the correctness invariant that makes `refs/nostr/<event-id>`
    /// self-verifying.
    ///
    /// ## Setup
    ///
    /// 1. Materialise commit A locally (the "wrong" commit — will be pushed).
    /// 2. Build and publish a PR event whose `c` tag names commit B (a
    ///    different, synthetic 64-hex hash that does not exist anywhere). The
    ///    event is accepted into purgatory via the GRASP-06 relaxation (no
    ///    announced coord, clone tag names our /prs/ endpoint).
    /// 3. Push commit A to `refs/nostr/<pr-event-id>` at the /prs/ URL.
    ///    The relay finds the event in purgatory, compares the pushed commit
    ///    against the event's `c` tag, detects a mismatch, and MUST delete
    ///    the ref.
    ///
    /// ## Pass conditions
    ///
    /// - After a short wait, `git ls-remote` for `refs/nostr/<pr-event-id>`
    ///   at the /prs/ URL returns empty (ref was deleted).
    /// - The PR event is still NOT served (not promoted out of purgatory).
    ///
    /// ## TDD posture
    ///
    /// Pre-implementation this FAILS in one of two ways:
    /// - If the receive handler doesn't exist yet (404), the push fails and
    ///   the ls-remote check trivially passes (no ref to find) — but the
    ///   test surfaces this as a setup failure rather than a false pass.
    /// - If the handler exists but the mismatch check is missing, the ref
    ///   survives and the ls-remote check fails.
    ///
    /// Once the mismatch branch is implemented correctly, the test goes green
    /// and stays green as the regression guard for the delete path.
    pub async fn test_commit_mismatch_deletes_ref_and_blocks_promotion(
        client: &AuditClient,
    ) -> TestResult {
        TestResult::new(
            super::test_ids::DELETE_COMMIT_MISMATCH,
            SpecRef::Grasp06CommitMismatchDeletesRef,
            "when the pushed commit does not match the PR event's `c` tag, the ref MUST be \
             deleted and the event MUST NOT be promoted out of purgatory",
        )
        .run(|| async {
            // 1. Resolve the relay's HTTP base URL.
            let ws_url = client
                .relay_url()
                .await
                .map_err(|e| format!("Failed to get relay URL: {}", e))?;
            let http_base = AuditClient::ws_to_http_url(&ws_url)
                .map_err(|e| format!("Failed to convert WebSocket URL to HTTP: {}", e))?;
            let http_base = http_base.trim_end_matches('/').to_string();

            // 2. Build a fresh, never-announced coordinate so the event goes
            //    through the GRASP-06 relaxation path (not GRASP-01). Using a
            //    random pubkey + UUID identifier guarantees no accepted
            //    announcement for this coord.
            let target_pubkey_hex = Keys::generate().public_key().to_hex();
            let identifier = format!("audit-grasp06-mismatch-{}", uuid::Uuid::new_v4());
            let a_tag_value = format!("30617:{}:{}", target_pubkey_hex, identifier);

            let pr_author_npub = client
                .pr_author_keys()
                .public_key()
                .to_bech32()
                .map_err(|e| format!("Failed to bech32-encode pr_author npub: {}", e))?;
            let prs_url = format!("{}/prs/{}/{}.git", http_base, pr_author_npub, identifier);

            // 3. Materialise commit A locally — this is the commit we will
            //    push. The PR event's `c` tag will name a DIFFERENT hash.
            let workspace = LocalWorkspace2::init("grasp06-mismatch-")?;
            init_local_repo(&workspace.path, &prs_url)
                .map_err(|e| format!("Failed to init local workspace: {}", e))?;

            let commit_a = create_commit(
                &workspace.path,
                "grasp-06 audit: commit A (the pushed commit)",
            )
            .map_err(|e| format!("Failed to create local commit: {}", e))?;

            // 4. Commit B is a synthetic 64-hex hash that does not correspond
            //    to any real git object. Using a fresh pubkey's hex is a
            //    convenient source of 64-hex without pulling in extra deps.
            let commit_b = Keys::generate().public_key().to_hex();

            // 5. Build and publish the PR event with `c` tag = commit B.
            //    The clone tag names our /prs/ endpoint so the GRASP-06
            //    relaxation accepts it into purgatory.
            let pr_event = client
                .event_builder(
                    Kind::GitPullRequest,
                    "grasp-06 audit: PR with c tag pointing at commit B (not the pushed commit A)",
                )
                .tag(Tag::custom("a", vec![a_tag_value]))
                .tag(Tag::custom("c", vec![commit_b.clone()]))
                .tag(Tag::custom("clone", vec![prs_url.clone()]))
                .build(client.pr_author_keys())
                .map_err(|e| format!("Failed to build PR event: {}", e))?;
            let pr_event_id_typed = pr_event.id;
            let pr_event_id = pr_event_id_typed.to_hex();

            // Acceptance is a precondition — if the relaxation isn't wired
            // yet, this test can't make its assertion. Surface the cause.
            client
                .send_event_and_note_purgatory(pr_event)
                .await
                .map_err(|e| {
                    format!(
                        "Relay rejected the PR event during test setup (GRASP-06 relaxation \
                         must accept it into purgatory before the mismatch check can fire): {}",
                        e
                    )
                })?;

            // 6. Push commit A to refs/nostr/<pr-event-id>. The relay finds
            //    the event in purgatory, compares the pushed commit (A) against
            //    the event's `c` tag (B), detects a mismatch, and MUST delete
            //    the ref. The push itself may succeed at the transport level
            //    (git-receive-pack accepts the pack) — the delete happens
            //    post-receive, so a non-zero push exit is not required here.
            let refname = format!("refs/nostr/{}", pr_event_id);
            try_push_to_ref(&workspace.path, &refname).map_err(|e| {
                format!(
                    "git push HEAD:{} to {} failed to execute: {}",
                    refname, prs_url, e
                )
            })?;
            // Note: we do NOT assert push_ok here. The relay may accept the
            // pack and then delete the ref post-receive (push exit 0, ref
            // gone), or it may reject at receive time (push exit non-zero).
            // Either is spec-compliant; what matters is the ref is absent
            // afterwards.

            // 7. Short wait for the post-receive processing to complete.
            tokio::time::sleep(Duration::from_millis(500)).await;

            // 8. Assert the ref is absent. ls-remote with a refname filter:
            //    empty stdout means the ref was deleted (or never written).
            //    A failed ls-remote (404 / connection error) is a setup
            //    failure — the /prs/ endpoint must be reachable.
            let ls_out = git_command()
                .args(["ls-remote", &prs_url, &refname])
                .output()
                .map_err(|e| format!("Failed to execute git ls-remote {}: {}", prs_url, e))?;

            if !ls_out.status.success() {
                let stderr = String::from_utf8_lossy(&ls_out.stderr);
                return Err(format!(
                    "git ls-remote {} {} failed (exit {}): {} — /prs/ endpoint must be \
                     reachable for this test to assert the mismatch-delete contract",
                    prs_url,
                    refname,
                    ls_out.status.code().unwrap_or(-1),
                    stderr.trim()
                ));
            }

            let stdout = String::from_utf8_lossy(&ls_out.stdout);
            let lines: Vec<&str> = stdout
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .collect();
            if !lines.is_empty() {
                return Err(format!(
                    "Commit-mismatch ref was NOT deleted: {} is still present at {} after \
                     pushing commit {} against a PR event whose `c` tag names {}. The \
                     receive handler must delete the ref when commit ≠ c tag \
                     (design-doc push semantics line 96).",
                    refname, prs_url, commit_a, commit_b
                ));
            }

            // 9. Assert the event was NOT promoted. If the relay incorrectly
            //    promoted the event despite the mismatch, is_event_on_relay
            //    returns true — that's the second half of the invariant.
            if client
                .is_event_on_relay(pr_event_id_typed)
                .await
                .map_err(|e| format!("Failed to query relay for PR event served-status: {}", e))?
            {
                return Err(format!(
                    "PR event {} was promoted out of purgatory despite a commit mismatch \
                     (pushed commit {} ≠ c tag {}). The relay MUST NOT promote the event \
                     when the pushed commit does not match the event's `c` tag.",
                    pr_event_id, commit_a, commit_b
                ));
            }

            Ok(())
        })
        .await
    }
}

// =============================================================================
// Helpers (test-local — kept here rather than promoted to the audit lib until
// a second consumer wants them).
// =============================================================================

/// Build a fresh, guaranteed-unused `/prs/<npub>/<id>.git` URL on `http_url`.
///
/// Fresh random keys + UUID ensure the path has no prior state and no
/// implementation could have a repo there by accident.
fn build_fresh_prs_url(http_url: &str) -> Result<String, String> {
    let probe_keys = nostr_sdk::prelude::Keys::generate();
    let probe_npub = probe_keys
        .public_key()
        .to_bech32()
        .map_err(|e| format!("Failed to bech32-encode probe npub: {}", e))?;
    let probe_id = format!("audit-probe-{}", uuid::Uuid::new_v4());
    Ok(format!(
        "{}/prs/{}/{}.git",
        http_url.trim_end_matches('/'),
        probe_npub,
        probe_id
    ))
}

/// A throwaway local git repo with one commit, suitable as the source of
/// a `git push` to a /prs/ endpoint under test.
///
/// All git configuration is set locally (`-c user.name=...`) rather than
/// through global config, so the test never touches the running user's
/// `~/.gitconfig`. Drops the directory on `Drop`.
struct LocalWorkspace {
    path: PathBuf,
}

impl LocalWorkspace {
    fn init() -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!("grasp06-prs-push-{}", uuid::Uuid::new_v4()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).map_err(|e| format!("Failed to create temp dir: {}", e))?;

        // git init with a fixed initial branch so behaviour matches across
        // host git versions (some default to `master`, some to `main`).
        run_git(&path, &["init", "--initial-branch=main"])?;

        // Local-only identity — does not touch global config.
        run_git(&path, &["config", "user.email", "audit@grasp-audit.local"])?;
        run_git(&path, &["config", "user.name", "GRASP Audit"])?;
        // Disable GPG signing for hermetic behaviour even if the host has
        // commit.gpgsign=true in global config.
        run_git(&path, &["config", "commit.gpgsign", "false"])?;

        // One trivial commit. Contents don't matter for push acceptance.
        fs::write(path.join("README"), "grasp-06 audit push test\n")
            .map_err(|e| format!("Failed to write README: {}", e))?;
        run_git(&path, &["add", "README"])?;
        run_git(&path, &["commit", "-m", "audit"])?;

        Ok(Self { path })
    }
}

impl Drop for LocalWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// A plain temp directory that wipes itself on drop.
///
/// Unlike [`LocalWorkspace`] this does NOT run `git init` — callers that
/// use [`init_local_repo`] (which clones from a URL) need an empty directory,
/// not a pre-initialised repo.
struct LocalWorkspace2 {
    path: PathBuf,
}

impl LocalWorkspace2 {
    fn init(prefix: &str) -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!("{}{}", prefix, uuid::Uuid::new_v4()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).map_err(|e| format!("Failed to create temp dir: {}", e))?;
        Ok(Self { path })
    }
}

impl Drop for LocalWorkspace2 {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Run a `git` command in `cwd` and require success. Returns the stderr text
/// on failure so the caller's error message contains the actual git output.
fn run_git(cwd: &Path, args: &[&str]) -> Result<(), String> {
    let output = git_command()
        .args(args)
        .current_dir(cwd)
        .output()
        .map_err(|e| format!("Failed to execute git {:?}: {}", args, e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("git {:?} failed: {}", args, stderr.trim()));
    }
    Ok(())
}

/// Run `git push <url> HEAD:<refname>` in `cwd`. Does not assert anything
/// about the exit code — the caller decides whether success or failure is
/// the spec-correct outcome.
fn git_push(cwd: &Path, url: &str, refname: &str) -> std::io::Result<std::process::Output> {
    git_command()
        .args(["push", url, &format!("HEAD:{}", refname)])
        .current_dir(cwd)
        .output()
}

/// Drive a `git push` and require that it is rejected — but not with a 404.
///
/// A 404 means the `/prs/<npub>/<id>.git` endpoint doesn't exist at all,
/// which is itself a spec violation (line 13 requires the endpoint to be
/// reachable as an empty bare repo). Treating a 404 as "rejected" would let
/// this test pass against an unimplemented relay, defeating the purpose.
///
/// Spec-correct rejection looks like:
/// - exit non-zero, AND
/// - stderr does NOT contain `not found` / `Not Found` / similar 404 hints.
///
/// In practice this means the rejection came from `git-receive-pack` on the
/// server side (typically an `ERR` pkt-line such as
/// `remote: refusing to push refs/heads/main ...`).
fn check_push_rejected_not_404(cwd: &Path, url: &str, refname: &str) -> Result<(), String> {
    let out = git_push(cwd, url, refname)
        .map_err(|e| format!("Failed to execute git push to {}: {}", url, e))?;

    if out.status.success() {
        return Err(format!(
            "Expected push to {} (ref={}) to be REJECTED, but it succeeded: relay accepted \
             a ref outside `refs/nostr/<event-id>` which violates GRASP-06 06.md line 13",
            url, refname
        ));
    }

    let stderr = String::from_utf8_lossy(&out.stderr);
    // Match git's two common 404 phrasings. `to_lowercase` keeps it robust to
    // future git releases tweaking capitalisation; the substrings are stable.
    let lower = stderr.to_lowercase();
    if lower.contains("not found") || lower.contains("404") {
        return Err(format!(
            "Push to {} (ref={}) failed with a 404 — the /prs/ endpoint is not implemented. \
             GRASP-06 06.md line 11 requires the endpoint to be reachable as an empty bare \
             repo, so this test cannot meaningfully assert the line 13 rejection contract. \
             stderr was: {}",
            url,
            refname,
            stderr.trim()
        ));
    }

    Ok(())
}
