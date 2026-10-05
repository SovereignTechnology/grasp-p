# Cloud handoff (2026-10-05)

State of the work and what to do next. `PLAN.md` beside this file has the whole plan; this
page is only the part a cloud session acts on.

## Where things stand

| Milestone | State |
|---|---|
| M0 spec and housekeeping | Done. `OVERVIEW.md` is the short spec. |
| M1 repos and CI | Done. Two GitLab runners take this project's and `cord-git`'s jobs in single-use VMs. |
| M2 port the server onto v3.0.7 | Done. `main` is upstream v3.0.7 plus GRASP-P; `SEAMS.md` says how it sits on upstream. |
| **M3 server hardening** | **Next.** |
| M4 and later | Not started. |

Two repositories:

- **This one** (server). `legacy/v1.2-grasp-p` is the server as it was on upstream v1.2.0,
  kept for reference only.
- **`cord-git`** (client library `cord-core`, the `cord-git` CLI, and the end-to-end script
  `scripts/e2e.sh`). Its `ci/SERVER_REF` pins the server commit the end-to-end job builds
  and runs; it names a commit on this repository's `main`.

## What M2 established

- **The server needs git 2.42 or newer at run time.** Debian 12 has 2.39.5 and no backport,
  so the CI test job builds git 2.47.3 for itself, and a production guest must be Debian 13
  or carry its own git. Details in `SEAMS.md`.
- **Synced events were not verified.** nostr-sdk accepts an event whose claimed id it has
  seen before without checking it, and upstream's sync trusted that. Any relay a node syncs
  from could forge an event from any author; on a GRASP-P node that meant registrations and
  deletions. The server now verifies every synced event itself. The same flaw is in
  unmodified upstream v3.0.7 and has not been reported there: that needs the maintainer's
  go-ahead.
- **One test uses real TLS** (`tests/grasp_p_tls.rs`). Keep reqwest on native-tls.
- **The review of the port left a list for M3**, in `PLAN.md` under "Found in the M2 review".

## The next task: M3

`PLAN.md` lists the items. Issue 14 is done: `GET /list/<pubkey>` answers only the listed
key. Before changing the sync or mirror code, read `SEAMS.md`: the pair tests run
with both SSRF guards switched off (`NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS=true`,
`NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS=true`), so the production peer path has no test yet.

Do not start M4 (protocol v0.2) without re-reading the decisions in `PLAN.md`: the owner
model and the key list change the client substantially.

## How work gets back

Push branches to this GitHub repository. Do not open pull requests against `main` here:
merge requests, CI and releases happen on GitLab, and branches are carried over from the
maintainer's machine. Say in your final message which branches you pushed and what state
they are in (builds or not, which suites pass, what is left).

## Not doable from a cloud session

Deploying, registering CI runners, anything on SovTech hosts, anything on GitLab, and
publishing specs or proposals upstream. If a task needs one of these, stop and say so.
