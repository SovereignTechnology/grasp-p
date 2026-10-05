# Cloud handoff (2026-10-05)

State of the work when it moved to a cloud session, and what to do next. `PLAN.md` beside this
file has the whole plan; this page is only the part a cloud session acts on.

## Where things stand

| Milestone | State |
|---|---|
| M0 spec and housekeeping | Done. `OVERVIEW.md` is the short spec. |
| M1 repos and CI | Repos done. The CI runners are not deployed yet, so no pipeline has ever run. |
| **M2 port the server onto v3.0.7** | **In progress on `sovtech/grasp-p-port`. Nothing has been compiled.** |
| M3 and later | Not started. |

Two repositories:

- **This one** (server). `legacy/v1.2-grasp-p` is the complete, working GRASP-P server on upstream
  v1.2.0 (lib tests, `phase0_gates`, `private_repos`, `private_two_node`, `private_watchdog` all
  passed there in July).
- **`cord-git`** (client library `cord-core`, the `cord-git` CLI, and the end-to-end script
  `scripts/e2e.sh`). Its `ci/SERVER_REF` pins the server commit the end-to-end suite runs against,
  currently the tip of `legacy/v1.2-grasp-p`.

## What is on the port branch

Read `PORTING.md` for the file-by-file list. In short:

- Every file that existed only in the legacy line is carried over, with `src/private/` moved to
  `src/grasp_p/` and settings renamed `NGIT_PRIVATE_*` to `NGIT_GRASP_P_*`.
- Twelve upstream files took the legacy change by three-way apply.
- **Five files are still upstream's and need porting by hand:** `src/server.rs`,
  `src/http/mod.rs`, `src/nostr/builder.rs`, `src/sync/mod.rs`, `tests/common/relay.rs`.
  The legacy change to each is `git diff cbf6f1d legacy/v1.2-grasp-p -- <file>`
  (`cbf6f1d` is the upstream commit the legacy line forked from).

## The next task: finish M2

Goal: `sovtech/grasp-p-port` builds, and upstream's suite plus the four GRASP-P suites pass.

Suggested order, smallest loop first:

1. `cargo check --lib`. Expect errors from the dependency moves: `nostr_relay_builder::prelude` is
   gone (use `nostr_sdk::local_relay`), `nostr::hashes` is no longer re-exported (use
   `bitcoin_hashes`), and the nostr crates moved from 0.45.0-alpha.3 to 0.45.5. Regenerate
   `Cargo.lock`.
2. Port `src/server.rs`, `src/http/mod.rs` and `src/nostr/builder.rs` (construct the service,
   route the blob endpoints, the admission arm in `Nip34WritePolicy::admit_event`). The service is
   threaded beside upstream's `private_access` (GRASP-08), not instead of it. Make the blob
   routes (`/upload`, `/<sha256>`, `/list/`) aware of upstream's base-path support
   (`strip_base_path`).
3. Config validation: GRASP-P and upstream's `NGIT_PRIVATE_MODE` are mutually exclusive, fatal
   at boot. GRASP-08 puts a NIP-42 gate in front of every read, which breaks GRASP-P's
   anonymous-read design.
4. Port `tests/common/relay.rs` (the two `TestRelay` constructors, onto upstream's
   `PortReservation`). Then `cargo test --test phase0_gates` and `--test private_repos`.
5. Port the sync seams in `src/sync/mod.rs` against upstream's reworked sync (grouped
   subscriptions). This is the largest piece: the legacy change is about 700 lines in a file that
   has tripled. Route the blob mirror's outbound requests through upstream's `src/outbound.rs`
   policy. Then `--test private_two_node` and `--test private_watchdog`.
6. Full gate: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D
   warnings`, `cargo test --locked`, `cargo test -p grasp-audit --locked`. Upstream's own tests
   must still pass unchanged.
7. If the `cord-git` repository is available in the session: build it, build this branch's server,
   and run `scripts/e2e.sh` with `SERVER_BIN`, `CORD_BIN` and `INBOX_BIN` set. The script spawns
   servers with `NGIT_PRIVATE_*` settings, so it needs the same rename to `NGIT_GRASP_P_*` on a
   branch of `cord-git`, together with a bump of `ci/SERVER_REF`.
8. Keep `PORTING.md` true as you go, and delete it when the port is complete.

Keep upstream's behaviour identical when GRASP-P is disabled: with `NGIT_GRASP_P_REPOS_ENABLE`
unset, every upstream test must pass and none of the four kinds may be admitted by a new path.

## After M2

M3 (server hardening) is next and is listed in `PLAN.md`. The first item is the unauthenticated
`GET /list/<pubkey>` route. Do not start M4 (protocol v0.2) without re-reading the decisions in
`PLAN.md`: the owner model and the key list change the client substantially.

## How work gets back

Push branches to this GitHub repository. Do not open pull requests against `main` here: merge
requests, CI and releases happen on GitLab, and branches are carried over from the maintainer's
machine. Say in your final message which branches you pushed and what state they are in
(builds or not, which suites pass, what is left).

## Not doable from a cloud session

Deploying, registering CI runners, anything on SovTech hosts, anything on GitLab, and publishing
specs or proposals upstream. If a task needs one of these, stop and say so.
