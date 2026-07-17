//! GRASP-06 `/prs/` `git-receive-pack` handler.
//!
//! Spec 06.md line 13:
//!
//! > MUST accept pushes to `refs/nostr/<event-id>`. MUST reject pushes to any
//! > other ref namespace.
//!
//! The handler:
//!
//! 1. Pre-scans the pkt-line ref-update list and rejects the entire push (via
//!    an `ERR` pkt-line on a 200 response) if *any* ref name is not of the
//!    exact shape `refs/nostr/<64-lowercase-hex>`. The repo on disk is not
//!    touched in this path — probe pushes that would have been rejected
//!    leave no trace.
//! 2. Pre-validates every ref against the database and purgatory via the
//!    **shared** [`crate::git::authorization::pre_validate_refs_nostr_push`]
//!    helper. The check is parameterised with `PrsUrlConstraints` so signer
//!    / `a`-tag identifier / `c`-tag commit mismatches against a known event
//!    reject the whole push with an `ERR` pkt-line — matching the
//!    standard-endpoint UX. Nothing on disk has been touched yet so failed
//!    probes leave no state.
//! 3. Acquires the per-path coordination state from [`RepoInitLocks`]
//!    briefly: under its mutex it runs the on-demand `git init --bare`
//!    and increments the `in_flight` counter, then releases the mutex.
//!    Steps 4 and 5 run *without* the per-path lock so concurrent pushes
//!    to the same `(submitter, identifier)` proceed in parallel — git's
//!    own ref locking handles intra-push concurrency, and the
//!    `in_flight` counter is what off-push cleanup paths consult to know
//!    a push is active.
//! 4. Starts `git-receive-pack`, writes the full request body to the child, and
//!    immediately returns an HTTP response whose body is backed by a bounded
//!    channel. From this point on Hyper can stream stdout to the client while a
//!    detached task owns the subprocess, stderr, and all post-push work.
//! 5. In the detached task, each stdout chunk is forwarded as it is read. If Git
//!    exits with a protocol-level error before writing stdout, the task sends a
//!    Git `ERR` pkt-line through the same stream so clients still see a normal
//!    receive-pack failure. If stdout has already been sent, the task cannot
//!    safely append a late protocol error without corrupting the Git stream, so
//!    it logs and performs cleanup instead.
//! 6. After a successful receive-pack, for each accepted
//!    `refs/nostr/<event-id>` ref, re-runs the shared pre-validation as a
//!    **race safety net** — an event for one of the pushed ids may have arrived
//!    via WebSocket during the receive-pack window. On mismatch the ref is
//!    deleted (and any populated purgatory entry is dropped). When neither the
//!    DB nor purgatory knows about the event a scoped PR placeholder is added so
//!    the standard 30-minute purgatory sweep can clean it up if the event never
//!    arrives.
//! 7. The detached task re-acquires the per-path mutex briefly, decrements
//!    `in_flight`, and — if no other push is in flight and the repo has zero
//!    refs left — removes the bare directory. This runs on success, protocol
//!    errors, client disconnects, and subprocess I/O failures, so a failed push
//!    that has just initialised an empty repo does not leak it.
//! 8. Finally, on successful pushes where the repo still exists, the detached
//!    task triggers the standard purgatory-release path via
//!    [`crate::git::sync::process_newly_available_git_data`] so PR events already
//!    in purgatory waiting for these commits get promoted.

use std::collections::HashSet;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use hyper::body::{Bytes, Frame};
use hyper::Response;
use nostr_relay_builder::LocalRelay;
use nostr_sdk::prelude::*;
use std::sync::Mutex;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::git::authorization::{
    parse_pushed_refs, pre_validate_refs_nostr_push, NostrRefPreValidation, PrsUrlConstraints,
};
use crate::git::handlers::{
    build_git_protocol_error_response, err_pktline_frame, is_git_protocol_error,
    pump_stdout_to_channel, read_stderr_to_end, record_git_operation, streaming_response, GitError,
    PumpResult, STREAM_CHANNEL_DEPTH,
};
use crate::git::protocol::GitService;
use crate::git::subprocess::GitSubprocess;
use crate::git::sync::process_newly_available_git_data;
use crate::git::{delete_ref, list_refs, GitResponseBody};
use crate::grasp06::endpoint::PrsUrl;
use crate::grasp06::paths::prs_repo_path;
use crate::metrics::Metrics;
use crate::nostr::builder::Nip34WritePolicy;
use crate::nostr::SharedDatabase;
use crate::purgatory::promotion_hooks::NostrPurgatoryPromotionHooks;
use crate::purgatory::Purgatory;
use crate::sync::rejected_index::RejectedEventsIndex;

/// Per-`(submitter, identifier)` coordination state shared between
/// `/prs/` receive-pack pushes and the cleanup paths that may delete the
/// bare repo.
///
/// `mu` is held only briefly:
///
/// * by the receive handler to perform `git init --bare` and register
///   the request as in-flight (`fetch_add` on `in_flight`),
/// * by the detached receive-pack streaming task at end-of-push to decrement
///   `in_flight` and, if no other push is in flight and the repo has zero refs,
///   remove the bare directory,
/// * by off-push cleanup paths (PR-event validation discard, purgatory
///   expiry) for the duration of one `delete_ref` + optional
///   `remove_dir_all`.
///
/// `git-receive-pack` itself and per-ref validation run *without* the
/// mutex held, so two pushes to the same path proceed in parallel; git's
/// own ref locking handles intra-push concurrency.
///
/// Off-push cleanup paths only `rm -rf` the bare repo when both
/// `in_flight.load() == 0` *and* `list_refs` returns empty while they
/// hold `mu` — the same mutex that gates `in_flight` updates — so a
/// repo can never be deleted while a push is mid-receive.
///
/// `mu` is a `std::sync::Mutex` (not `tokio::sync::Mutex`) because every
/// critical section is purely synchronous (git I/O, no `.await`). This
/// lets the purgatory sweep call `lock()` directly from sync context
/// instead of `try_lock()`, eliminating the leak-on-contention bug where
/// a purgatory entry was dropped even when the lock was busy.
pub struct PrsPathState {
    pub mu: Mutex<()>,
    pub in_flight: AtomicUsize,
}

impl PrsPathState {
    fn new() -> Self {
        Self {
            mu: Mutex::new(()),
            in_flight: AtomicUsize::new(0),
        }
    }
}

/// Shared per-path state map for the GRASP-06 `/prs/` endpoint. See
/// [`PrsPathState`] for the locking discipline.
pub type RepoInitLocks = Arc<DashMap<PathBuf, Arc<PrsPathState>>>;

/// Create a fresh, empty [`RepoInitLocks`] for use as an [`HttpService`]
/// field.
///
/// [`HttpService`]: crate::http
pub fn new_repo_init_locks() -> RepoInitLocks {
    Arc::new(DashMap::new())
}

/// Look up (or insert) the [`PrsPathState`] for `repo_path` in `locks`.
/// Used by off-push cleanup paths so they take the same Arc the receive
/// handler will see.
pub fn path_state(locks: &RepoInitLocks, repo_path: &Path) -> Arc<PrsPathState> {
    locks
        .entry(repo_path.to_path_buf())
        .or_insert_with(|| Arc::new(PrsPathState::new()))
        .value()
        .clone()
}

/// Handle `POST /prs/<npub>/<identifier>.git/git-receive-pack`.
///
/// See the module-level docs for the full algorithm. All application-level
/// rejections are returned as HTTP 200 with an `ERR` pkt-line so the git
/// client can display the message and exit non-zero.
#[allow(clippy::too_many_arguments)]
pub async fn handle_prs_receive_pack(
    prs: &PrsUrl,
    request_body: Bytes,
    database: SharedDatabase,
    relay: LocalRelay,
    purgatory: Arc<Purgatory>,
    write_policy: Arc<Nip34WritePolicy>,
    rejected_events_index: Arc<RejectedEventsIndex>,
    git_data_path: &str,
    git_protocol: Option<&str>,
    repo_init_locks: RepoInitLocks,
    domain: &str,
    metrics: Option<Arc<Metrics>>,
) -> Result<Response<GitResponseBody>, GitError> {
    // 1. Pre-scan refs and reject the whole push if any ref name is not
    //    `refs/nostr/<64-lowercase-hex>`. We use the same parser as the
    //    standard receive-pack path so behaviour stays in lock-step.
    let pushed_refs = parse_pushed_refs(&request_body);
    if pushed_refs.is_empty() {
        warn!(
            "/prs/ receive-pack: no parsable refs in push to {}/{}",
            prs.submitter.to_hex(),
            prs.identifier
        );
        record_git_operation(&metrics, "push", "error");
        return Ok(build_git_protocol_error_response(
            GitService::ReceivePack,
            "no ref updates found in push",
            Some(&request_body),
        ));
    }

    for (_, _, ref_name) in &pushed_refs {
        if let Some(reason) = invalid_ref_reason(ref_name) {
            warn!(
                "/prs/ receive-pack: rejecting push to {}/{} — {}",
                prs.submitter.to_hex(),
                prs.identifier,
                reason
            );
            record_git_operation(&metrics, "push", "error");
            return Ok(build_git_protocol_error_response(
                GitService::ReceivePack,
                &format!(
                    "GRASP-06: only pushes to refs/nostr/<event-id> are accepted ({})",
                    reason
                ),
                Some(&request_body),
            ));
        }
    }

    // 2. Pre-validate every ref against the DB + purgatory. Same logic the
    //    standard endpoint uses in `authorize_push`, parameterised with the
    //    `/prs/<npub>/<identifier>` URL constraints so signer / a-tag
    //    identifier mismatches are caught alongside the commit mismatch.
    //    Any rejection returns an ERR pkt-line *before* the bare repo is
    //    initialised — failed probes leave no on-disk state.
    let prs_constraints = PrsUrlConstraints {
        submitter: &prs.submitter,
        identifier: &prs.identifier,
        domain,
    };
    for (_, new_oid, ref_name) in &pushed_refs {
        match pre_validate_refs_nostr_push(
            &database,
            &purgatory,
            new_oid,
            ref_name,
            Some(prs_constraints),
        )
        .await
        {
            NostrRefPreValidation::Rejected { reason } => {
                warn!(
                    "/prs/ receive-pack: rejecting push to {}/{} — {}",
                    prs.submitter.to_hex(),
                    prs.identifier,
                    reason
                );
                record_git_operation(&metrics, "push", "error");
                return Ok(build_git_protocol_error_response(
                    GitService::ReceivePack,
                    &format!("GRASP-06: {}", reason),
                    Some(&request_body),
                ));
            }
            NostrRefPreValidation::Authorized { .. } | NostrRefPreValidation::Unknown => {}
        }
    }

    // 3. Acquire the per-path coordination state and, under its mutex,
    //    initialise the bare repo on demand and register this request as
    //    in-flight. The mutex is then released — `git-receive-pack` and
    //    per-ref validation run WITHOUT the lock so concurrent pushes to
    //    the same `(submitter, identifier)` proceed in parallel. Cleanup
    //    paths consult `in_flight` (under the same mutex) before
    //    deleting the bare repo, so a repo can never vanish mid-receive.
    let repo_path = prs_repo_path(
        Path::new(git_data_path),
        &prs.submitter.to_hex(),
        &prs.identifier,
    );
    let state = path_state(&repo_init_locks, &repo_path);

    {
        let _g = state.mu.lock().expect("prs path mutex poisoned");
        if let Err(e) = ensure_repo_initialised(&repo_path) {
            error!(
                "/prs/ receive-pack: failed to initialise repo at {}: {}",
                repo_path.display(),
                e
            );
            record_git_operation(&metrics, "push", "error");
            return Err(e);
        }
        state.in_flight.fetch_add(1, Ordering::Relaxed);
    }

    // 4. The pre-validation and repo creation work above must stay buffered so
    //    rejections can be returned as a complete Git `ERR` response before any
    //    repository state is touched. Once we start `git-receive-pack`, switch
    //    to the same streaming shape as the standard receive-pack endpoint:
    //    write stdin here, then hand stdout/stderr and all follow-up state to a
    //    detached task that feeds the response body channel.
    let mut git =
        match GitSubprocess::spawn(GitService::ReceivePack, &repo_path, false, git_protocol)
            .map_err(GitError::ProcessSpawnFailed)
        {
            Ok(git) => git,
            Err(e) => {
                finish_prs_receive_pack(&state, &repo_path);
                record_git_operation(&metrics, "push", "error");
                return Err(e);
            }
        };

    if let Some(mut stdin) = git.take_stdin() {
        if let Err(e) = stdin.write_all(&request_body).await {
            let _ = git.kill().await;
            finish_prs_receive_pack(&state, &repo_path);
            record_git_operation(&metrics, "push", "error");
            return Err(GitError::IoError(e));
        }
        drop(stdin);
    }

    let stdout = match git.take_stdout() {
        Some(stdout) => stdout,
        None => {
            let _ = git.kill().await;
            finish_prs_receive_pack(&state, &repo_path);
            record_git_operation(&metrics, "push", "error");
            return Err(GitError::IoError(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "git receive-pack stdout unavailable",
            )));
        }
    };
    let stderr = git.take_stderr();
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, io::Error>>(STREAM_CHANNEL_DEPTH);

    // The request future returns as soon as the channel-backed response is
    // built. Everything that previously happened after the buffered
    // `run_receive_pack` call must therefore move into this task: forwarding
    // stdout, classifying Git failures, decrementing `in_flight`, race-window
    // validation, empty-repo cleanup, purgatory promotion, and metrics.
    tokio::spawn(stream_prs_receive_pack_output(
        git,
        stdout,
        stderr,
        tx,
        repo_path,
        state,
        pushed_refs,
        database,
        relay,
        purgatory,
        write_policy,
        rejected_events_index,
        git_data_path.to_string(),
        request_body,
        prs.submitter,
        prs.identifier.clone(),
        domain.to_string(),
        metrics,
    ));

    Ok(streaming_response(GitService::ReceivePack, rx))
}

/// Return `Some(reason)` if `ref_name` is not exactly
/// `refs/nostr/<64-lowercase-hex>`.
///
/// The shape is deliberately strict: anything else (including upper-case
/// hex, short/long event IDs, or `refs/heads/*`) is "any other ref
/// namespace" per the spec and must be rejected.
fn invalid_ref_reason(ref_name: &str) -> Option<String> {
    let Some(event_id) = ref_name.strip_prefix("refs/nostr/") else {
        return Some(format!("ref {} is outside refs/nostr/", ref_name));
    };
    if event_id.len() != 64 {
        return Some(format!(
            "event-id segment of {} is {} chars, expected 64",
            ref_name,
            event_id.len()
        ));
    }
    if !event_id
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Some(format!(
            "event-id segment of {} is not lowercase hex",
            ref_name
        ));
    }
    None
}

/// `mkdir -p` the parent and `git init --bare --initial-branch=main
/// --quiet` into `repo_path` if it does not already exist.
///
/// The caller must hold the per-path mutex from [`PrsPathState`] for
/// `repo_path` before invoking this function.
fn ensure_repo_initialised(repo_path: &Path) -> Result<(), GitError> {
    if repo_path.exists() {
        return Ok(());
    }

    if let Some(parent) = repo_path.parent() {
        std::fs::create_dir_all(parent).map_err(GitError::IoError)?;
    }

    let output = std::process::Command::new("git")
        .args(["init", "--bare", "--initial-branch=main", "--quiet"])
        .arg(repo_path)
        .output()
        .map_err(GitError::ProcessSpawnFailed)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        error!(
            "/prs/ git init --bare failed at {}: {}",
            repo_path.display(),
            stderr.trim()
        );
        return Err(GitError::GitFailed(output.status.code()));
    }

    info!(
        "/prs/ initialised bare repo at {} on demand",
        repo_path.display()
    );
    Ok(())
}

/// End-of-push cleanup. Always runs — including on receive-pack protocol
/// errors and client disconnects — so a failed push that has just initialised
/// an empty repo does not leak it. Decrements `in_flight`; if no other push is
/// in flight and the repo has zero refs left, removes the bare directory.
fn finish_prs_receive_pack(state: &PrsPathState, repo_path: &Path) {
    let _g = state.mu.lock().expect("prs path mutex poisoned");
    state.in_flight.fetch_sub(1, Ordering::Relaxed);
    if state.in_flight.load(Ordering::Relaxed) == 0 {
        if let Ok(refs) = list_refs(repo_path) {
            if refs.is_empty() {
                if let Err(e) = std::fs::remove_dir_all(repo_path) {
                    warn!(
                        "/prs/ receive-pack: failed to clean up empty repo {}: {}",
                        repo_path.display(),
                        e
                    );
                } else {
                    debug!(
                        "/prs/ receive-pack: removed empty repo {} (no refs after push)",
                        repo_path.display()
                    );
                }
            }
        }
    }
}

/// Own the live `/prs/` receive-pack after the request handler has returned its
/// streaming response.
///
/// This task is the continuation of [`handle_prs_receive_pack`], not just a
/// stdout pump. It must preserve the old buffered handler's guarantees while the
/// HTTP body is already streaming:
///
/// * if stdout reaches EOF cleanly, inspect Git's exit status and stderr;
/// * if Git failed before sending stdout, synthesize a final Git `ERR` pkt-line
///   through the response channel;
/// * always run `finish_prs_receive_pack` on every terminal path after
///   `in_flight` was incremented;
/// * only run race-window validation and purgatory promotion after a successful
///   receive-pack.
#[allow(clippy::too_many_arguments)]
async fn stream_prs_receive_pack_output<S, E>(
    mut git: GitSubprocess,
    stdout: S,
    stderr: Option<E>,
    tx: mpsc::Sender<Result<Frame<Bytes>, io::Error>>,
    repo_path: PathBuf,
    state: Arc<PrsPathState>,
    pushed_refs: Vec<(String, String, String)>,
    database: SharedDatabase,
    relay: LocalRelay,
    purgatory: Arc<Purgatory>,
    write_policy: Arc<Nip34WritePolicy>,
    rejected_events_index: Arc<RejectedEventsIndex>,
    git_data_path: String,
    request_body: Bytes,
    submitter: PublicKey,
    identifier: String,
    domain: String,
    metrics: Option<Arc<Metrics>>,
) where
    S: tokio::io::AsyncRead + Unpin + Send + 'static,
    E: tokio::io::AsyncRead + Unpin + Send + 'static,
{
    // Drain stderr concurrently with stdout. Git can write enough diagnostics to
    // fill its stderr pipe while still producing stdout; draining both prevents
    // child-process deadlock and preserves stderr for protocol-error reporting.
    let stderr_task = stderr.map(|stderr| tokio::spawn(read_stderr_to_end(stderr)));
    let pump_result = pump_stdout_to_channel(stdout, &tx).await;

    // If the client goes away or stdout read fails, stop Git rather than letting
    // it continue writing into a response nobody can receive. Cleanup below will
    // still release `in_flight` after `wait()` observes process termination.
    if !matches!(pump_result, PumpResult::Eof { .. }) {
        let _ = git.kill().await;
    }

    let status = match git.wait().await {
        Ok(status) => status,
        Err(e) => {
            let _ = tx.send(Err(e)).await;
            finish_prs_receive_pack(&state, &repo_path);
            record_git_operation(&metrics, "push", "error");
            return;
        }
    };

    let stderr_output = match stderr_task {
        Some(task) => task.await.unwrap_or_default(),
        None => Vec::new(),
    };

    let sent_stdout = match pump_result {
        PumpResult::Eof { sent_stdout } => sent_stdout,
        PumpResult::ClientDisconnected | PumpResult::ReadError => {
            finish_prs_receive_pack(&state, &repo_path);
            record_git_operation(&metrics, "push", "error");
            return;
        }
    };

    if !status.success() {
        record_git_operation(&metrics, "push", "error");
        let stderr_str = String::from_utf8_lossy(&stderr_output);
        if is_git_protocol_error(status.code(), &stderr_output) {
            warn!(
                "/prs/ git-receive-pack protocol error (returning ERR pkt-line): {}",
                stderr_str.trim()
            );
            if !sent_stdout {
                let _ = tx
                    .send(Ok(err_pktline_frame(
                        GitService::ReceivePack,
                        &stderr_str,
                        Some(&request_body),
                    )))
                    .await;
            }
        } else {
            error!(
                "/prs/ git-receive-pack failed (transport): {}",
                stderr_str.trim()
            );
            if !sent_stdout {
                let msg = if stderr_str.trim().is_empty() {
                    format!("git receive-pack failed with code {:?}", status.code())
                } else {
                    stderr_str.to_string()
                };
                let _ = tx
                    .send(Ok(err_pktline_frame(
                        GitService::ReceivePack,
                        &msg,
                        Some(&request_body),
                    )))
                    .await;
            }
        }
        // Whether or not an ERR frame could be sent, the HTTP headers are
        // already committed as a streaming 200 response. The only remaining
        // safe action is to close the body after cleanup.
        finish_prs_receive_pack(&state, &repo_path);
        return;
    }

    debug!("/prs/ git-receive-pack stream completed successfully");
    record_git_operation(&metrics, "push", "success");

    // Race safety net. The pre-validation in `handle_prs_receive_pack` was
    // performed before `git-receive-pack` ran, so an event with one of the
    // pushed ids may have arrived via WebSocket during the receive-pack window.
    // Re-run the same shared check now and delete the ref on any mismatch.
    for (_, new_oid, ref_name) in &pushed_refs {
        let event_id_hex = ref_name
            .strip_prefix("refs/nostr/")
            .expect("ref shape validated above");
        let post_push_constraints = PrsUrlConstraints {
            submitter: &submitter,
            identifier: &identifier,
            domain: &domain,
        };
        post_push_validate(
            &database,
            &purgatory,
            &repo_path,
            post_push_constraints,
            event_id_hex,
            new_oid,
            ref_name,
        )
        .await;
    }

    finish_prs_receive_pack(&state, &repo_path);

    // Drive the standard purgatory-release pipeline so PR events already
    // waiting on these commits can be promoted out of purgatory. Only fires on
    // a successful push, and only if the repo still exists (it may have been
    // removed by end-of-push cleanup).
    if repo_path.exists() {
        let new_oids: HashSet<String> = pushed_refs
            .iter()
            .filter(|(_, new_oid, _)| new_oid != "0000000000000000000000000000000000000000")
            .map(|(_, new_oid, _)| new_oid.clone())
            .collect();

        let promotion_hooks = NostrPurgatoryPromotionHooks::git_push(
            write_policy,
            rejected_events_index,
            Some(relay.clone()),
        );

        if let Err(e) = process_newly_available_git_data(
            &repo_path,
            &new_oids,
            &database,
            Some(&relay),
            &purgatory,
            Path::new(&git_data_path),
            Some(&promotion_hooks),
        )
        .await
        {
            warn!(
                "/prs/ receive-pack: post-push processing failed for {}/{}: {}",
                submitter.to_hex(),
                identifier,
                e
            );
        }
    }
}

/// Race safety net for the `/prs/` receive-pack post-push phase.
///
/// Pre-validation (step 2 of [`handle_prs_receive_pack`]) already gates
/// every ref against the DB and purgatory *before* `git-receive-pack`
/// runs, so the common case here is `Authorized` (event was found and
/// matched at pre-validation, or matched again after a no-op race) or
/// `Unknown` (no event known yet — register a scoped placeholder).
///
/// A `Rejected` outcome here means an event for this `event_id` arrived
/// via WebSocket during the receive-pack window and either:
///
/// - mismatches commit / signer / a-tag identifier (delete the ref), or
/// - was held in purgatory with a populated entry that also mismatches
///   (delete the ref AND drop the purgatory entry — its event is wrong).
///
/// Anything left here is best-effort: errors deleting refs are logged and the
/// push response is not changed. By the time this runs the response body has
/// already streamed Git's success output, so the only safe correction is to fix
/// repository state before `finish_prs_receive_pack` decides whether the bare
/// repo is now empty.
async fn post_push_validate(
    database: &SharedDatabase,
    purgatory: &Purgatory,
    repo_path: &Path,
    prs_constraints: PrsUrlConstraints<'_>,
    event_id_hex: &str,
    pushed_commit: &str,
    ref_name: &str,
) {
    match pre_validate_refs_nostr_push(
        database,
        purgatory,
        pushed_commit,
        ref_name,
        Some(prs_constraints),
    )
    .await
    {
        NostrRefPreValidation::Rejected { reason } => {
            warn!(
                "/prs/ post-push: deleting {} — race-window mismatch ({})",
                ref_name, reason
            );
            let _ = delete_ref(repo_path, ref_name);
            // If the rejection came from a populated purgatory entry whose
            // event is itself wrong for this URL, drop it so the
            // 30-minute sweep doesn't try to re-validate it again.
            if let Some(entry) = purgatory.find_pr(event_id_hex) {
                if entry.event.is_some() {
                    purgatory.remove_pr(event_id_hex);
                }
            }
        }
        NostrRefPreValidation::Authorized { .. } => {
            debug!(
                "/prs/ post-push: {} validated against DB/purgatory",
                ref_name
            );
            // Edge case B2: a standard-endpoint push with the *wrong* commit
            // may have created an un-scoped placeholder for this event_id
            // before the /prs/ push arrived.  When the PR event eventually
            // arrives it would find an un-scoped placeholder, enter the
            // "supersedes" branch (because placeholder commit X ≠ event
            // commit Y), discard the placeholder, and then fail to find
            // commit Y in any announced repo — sending the event to
            // purgatory with no trigger to release it.
            //
            // Fix: if the placeholder is un-scoped (no event, no scope),
            // upgrade it in-place to a scoped placeholder referencing
            // this /prs/ URL and the commit we just received.  The event
            // arrival will then take the scope-match branch in
            // PrEventPolicy::git_data_check, find commit Y in the /prs/
            // repo, and mirror it (overwriting the incorrect ref) into
            // every matching announced repo.
            if let Some(entry) = purgatory.find_pr(event_id_hex) {
                if entry.event.is_none() && entry.prs_scope.is_none() {
                    purgatory.add_prs_pr_placeholder(
                        event_id_hex.to_string(),
                        pushed_commit.to_string(),
                        *prs_constraints.submitter,
                        prs_constraints.identifier.to_string(),
                    );
                    debug!(
                        "/prs/ post-push: upgraded un-scoped placeholder to scoped for {} (commit {})",
                        ref_name, pushed_commit
                    );
                }
            }
        }
        NostrRefPreValidation::Unknown => {
            // No event known. Register a scoped placeholder so the
            // 30-minute purgatory sweep deletes the ref if the event
            // never arrives, and so an unrelated event of the same id
            // can't later claim this ref. See
            // [`Purgatory::add_prs_pr_placeholder`].
            purgatory.add_prs_pr_placeholder(
                event_id_hex.to_string(),
                pushed_commit.to_string(),
                *prs_constraints.submitter,
                prs_constraints.identifier.to_string(),
            );
            debug!(
                "/prs/ post-push: added scoped PR placeholder for {} awaiting matching event",
                ref_name
            );
        }
    }
}
