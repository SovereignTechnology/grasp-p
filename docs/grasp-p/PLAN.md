# GRASP-P to production: plan

A copy of the working plan for people and agents working in this repository. Deployment and
infrastructure detail is deliberately left out; it lives with the maintainer.

## Context

Upstream's GRASP-08 private mode is an access gate: the host still reads plaintext. GRASP-P with
its client (`cord-git`) is the system built in July 2026 where the server holds ciphertext only.
The goal is to make it production ready as the paid private tier of **sovdev.pro**, for external
paying customers.

State on 2026-10-05:

- No GRASP-P server is running anywhere.
- **Server:** complete on upstream v1.2.0 (`legacy/v1.2-grasp-p`); upstream has since moved to
  v3.0.7 (about 450 commits) and now ships its own `src/private/` for GRASP-08.
- **Client:** a working prototype, not a product. No fetch or pull, no `git` integration, the whole
  history is uploaded on every push, keys are passed on the command line, the keystore is
  plaintext, and 13 correctness defects are open.

## Approach

A fresh fork of upstream ngit-grasp v3.0.7 with GRASP-P ported in as an overlay; the client
library reworked to Concord's ownership and key-sync model and made embeddable; a fork of the
ngit client so plain git works over `nostr://`; private repositories in the sovdev.pro web UI;
then deployment, only at launch.

Milestones M0 to M9 plus a parallel standardisation track. Each milestone ends green in CI and
merged before the next starts.

Conventions: branch and merge request, fast-forward only, never squash; commits as
`sovtech <git@sovtech.pro>` with the prefix `sovtech:`; no AI attribution; upstream synced by merge
only, on `sync/upstream-*` branches; release tags `sovtech-vX.Y.Z`; a security review before every
push; `git status` before every commit.

### M0 - Spec and housekeeping (done)
`OVERVIEW.md` written; the client README rewritten.

### M1 - Repositories and CI (repositories done, runners pending)
- Two projects: this server fork and `cord-git`. Here, `main` is unmodified upstream v3.0.7 and
  the old line is kept as `legacy/v1.2-grasp-p`.
- CI is a GitLab pipeline (`.gitlab-ci.yml` on the `sovtech/ci` branches): fmt, clippy, tests, the
  client's end-to-end suite against a pinned server commit, and release binaries on protected
  refs. Jobs run in single-use VMs on two dedicated runners, one for merge requests and one for
  protected refs. The runners are not deployed yet.

### M2 - Port the server onto v3.0.7
- Module renamed **`src/private/` -> `src/grasp_p/`** (upstream now owns `src/private/` for
  GRASP-08); env prefix `NGIT_PRIVATE_*` -> `NGIT_GRASP_P_*` (free now: nothing is deployed);
  rename `HttpService.private`, `TestRelay::start_with_private_repos`.
- Deps to upstream's: nostr 0.45.5, `nostr_relay_builder::prelude` -> `nostr_sdk::local_relay`,
  `nostr::hashes` -> `bitcoin_hashes`. Keep upstream's reqwest `native-tls` (our `rustls` switch
  caused the CryptoProvider panic); add one wss/https test so TLS paths are exercised.
- Re-seat the 19 seams. Trivial/moderate: `config.rs`, `nostr/builder.rs` (`Nip34WritePolicy::admit_event`
  arm), `http/mod.rs` (make `/upload`, `/<sha>`, `/list/` base-path aware via `strip_base_path`),
  `metrics`, `nip11.rs`, `server.rs`, `sync/filters.rs`, `nix/module.nix`.
  **Rewrite**: `sync/mod.rs` hunks + `sync/private_index.rs` against upstream's new sync
  (grouped subscriptions); route the blob mirror through upstream's `src/outbound.rs` policy.
- Config validation: GRASP-P and `NGIT_PRIVATE_MODE` (GRASP-08) are **mutually exclusive**, fatal
  at boot (GRASP-08's `ws_auth` would break GRASP-P's anonymous-read invariant).
- Gate: lib tests, `phase0_gates`, `private_repos`, `private_two_node`, `private_watchdog`,
  upstream's own suite, and cord-git e2e all green in CI.

### M3 - Server hardening (issues on project 12)
- **#14** `/list/<pubkey>`: add `BlossomOp::List` (`src/grasp_p/blossom_auth.rs`), a shape
  verifier without the `x` requirement, signer must be the tenant key; mirror
  `verify_blossom_auth` in `mod.rs`. Resolve the base64 vs base64url spec/code divergence.
- **#24** `/metrics` off by default on GRASP-P nodes, loopback only, no relay URLs in labels.
- **#25** per-tenant claim/file-count caps; **#26** mirror fairness; **#20** purgatory SSRF and
  **#3** DNS rebinding (both via `outbound.rs`); **#16** announcement-indexer pin + leak canary.
- **#1** offboard: kind-5 tombstone frees alias, keys, ledger; retention purge (customers leave).
- **#21** document every config var; **#10** adversarial re-review of the ported sync/mirror.

### M4 - Protocol v0.2 and client correctness (`sovtech/cord-git`, `crates/cord-core`)
No private repo is live anywhere, so v0.2 breaks compatibility freely. Decisions are the maintainer's,
2026-10-05, after checking how Concord does it (CORD-02 section 8, CORD-05 section 4, CORD-06).

- **Owner = the user's own npub (Concord model).** Today the owner *is* the per-repo hosting key
  (`repo.rs:1559`, `owner_pk = hosting.public_key()`). Change: `community_id` commits to the
  owner's real key (`crypto.rs:47`, same formula, different input). Rekeys (inner 3303), roster
  records, invites and promotions are signed by the owner through their signer, inside encrypted
  content the server never sees. Members verify against the key committed in `community_id`.
  - The **hosting key** shrinks to a server-facing registration key: it signs kind 30640 only.
    The server is unchanged; it still sees only the hosting key.
  - The write set stops being trusted from the registration alone: clients accept a state root
    only from a write key named in an **owner-signed epoch record** (this is roster-anchored
    sequencing, **#3**, and it also gives the monotonic floor against operator rollback). A
    leaked hosting key can then disrupt a repo, not take it over or grant write access.
- **Key list (Concord's Community List model).** Each user publishes a self-encrypted (NIP-44 to
  self), addressable, fragmenting list signed by their own key: per repo the current keys, the
  earliest keys held (for history), role, node URLs, and for an owner the hosting secret.
  Tombstones for repos left. Merges are commutative and idempotent; every write is
  read-modify-write. Own kind number, **not** Concord's 33302. Published to the user's own relays.
  The CLI keystore becomes a local cache of it. Replaces "rebuild from invites".
- **Rotation resumable from the list, no local pending file.** One random rotation seed is written
  to the owner's list entry before anything is published; every new secret and rekey slot derives
  from it, so any device or client resumes the same rotation. The fold accepts repeated rekeys
  carrying identical keys and picks a deterministic winner on a true race (Concord's rule) instead
  of failing. Subsumes **#15**, **#24**, **#26**; still do **#23/#31** (validate and size-check the
  rekey before publishing anything).
- **Invites are real NIP-59**: the seal is signed by the inviter's own key (**#17**); `join` checks
  the inviter against the owner-signed roster and the delivered keys against the live repo.
- Remaining defects: **#22** per-working-tree CAS anchor, **#25** "none valid" is not "never
  pushed", **#27** publish to every relay with read-back, **#34/#33** rejection recovery, **#28**
  invite size ceiling, **#30** co-maintainer announcement leak, **#18** e2e false-pass.
- Server follow-on in the same milestone: drop the legacy 1059/21059 stream-wrap window (nothing
  deployed needs it), and bump `ci/SERVER_REF` to the ported server.

### M5 - cord-core as an embeddable library
Three consumers need it: the CLI, the ngit fork (native) and the web UI (WebAssembly). Today it is
blocking (`reqwest` blocking, `tungstenite`) and reads keystore files directly.

- Three traits, core logic async and free of direct IO:
  - `Signer`: public key, sign event, NIP-44 encrypt/decrypt. Implementations: local key (read
    from stdin, prompt or file, **never argv**), NIP-46 bunker, and a JS bridge for the browser.
  - `Transport`: relay REQ/EVENT and blob GET/PUT. Native and browser (`fetch`, `WebSocket`).
  - `Store`: key-list cache, CAS anchors, rollback floors.
- `wasm32-unknown-unknown` build and tests in CI (the runner image already has the target).
  Git pack building and unpacking via the `git` binary stays in a native-only module.
- Efficiency: **#4** delta packs (incremental pack per push, periodic repack, delete superseded
  blobs), fetch into an existing clone, tags, streamed upload with a size preflight.
- **Re-key by manifest only**: after a revoke, publish a manifest under the new state key that lists
  the same pack blobs. No pack is re-uploaded. A removed member could already read those packs
  (revocation is forward-only), so nothing is given up, and it makes revoke cheap enough to run in a
  browser.
- CLI: `keygen` stops printing the nsec, keystore cache encrypted at rest with file locking,
  **#6** export/offboard, user guide, signed release binaries from CI.

### M6 - Fork ngit so private repos use `nostr://`
the maintainer, 2026-10-05 (decided in a /btw side thread and relayed to this session; replaces the
`git-remote-cord` / `cord://` helper; tracks cord-git #20). Git picks its helper from the URL
scheme, so `nostr://` always runs `git-remote-nostr`, which ngit ships.

- New fork **`sovtech/ngit`** (a new repository), same conventions as the other
  forks: `upstream` = ngit's Nostr repo with push DISABLED, merge-only sync, ff-only, `sovtech:`
  commits, `sovtech-v*` tags, CI on the `ci-grasp` runners (assign both runners to the project).
  Overlay only: private-repo code in its own module behind a thin seam.
- **First step is a read-only study** of ngit 3.x's `git-remote-nostr` (list / fetch / push entry
  points, git transport, address resolution, how it holds the user's signer) before the design
  is fixed. The July note that it uses libgit2 with bundled OpenSSL is unverified for 3.x.
- Address `nostr://<hosting-npub>/<alias>`. Dispatch by what exists there: a kind 30617
  announcement is public (upstream's path, untouched); a kind 30640 registration plus an entry in
  the user's key list is private (our path, `cord-core` as a dependency, ngit's own signer behind
  the `Signer` trait).
- `git clone`, `git fetch`, `git push` (per ref, non-fast-forward as git's own rejection, tags).
  Membership commands stay in the `cord-git` CLI and the web UI for v1.
- Offer the same code upstream once it works; if upstream takes it, the fork can be retired.

### M7 - Private repos in the web UI (`sovtech/git`, sovdev.pro build only; REQUIRED for launch)
the maintainer, 2026-10-05: full management from the browser, with every login method the build offers.

- **Study first** (read-only): how the UI reads git objects (`src/hooks/useGitPool.ts`,
  `src/lib/git-http-auth.ts`), its existing private-repo surface built for GRASP-08
  (`src/lib/private-grasp.ts`, `src/services/privateRepositoryScope.ts`,
  `src/lib/private-git-relays.ts`), and the overlay seams (`src/sovtech/**`, `vite-plugin.ts`).
- `cord-core` as a WebAssembly package built by cord-git's protected pipeline, pinned by hash in
  `sovtech/git`. Overlay only, enabled only in the sovdev brand profile.
- Signer bridge: the UI's `ISigner` (applesauce-signers) to the `Signer` trait. Any login whose
  signer does NIP-44 works; one that does not gets a clear message. Today's UI has extension,
  bunker (NostrConnect), Amber and private-key accounts.
- Features: my private repos (from the key list); browse code, commits, branches, tags (manifest
  and packs fetched, verified and decrypted in a Web Worker, fed to the UI's existing git reader);
  issues and patches, read and write; create repo; invite (to the invitee's inbox relays) and
  join; roster; promote and demote; revoke with the full rotation, resumable; leave.
- Not in the browser for v1: pushing code (that is git with the ngit fork).
- Key hygiene: decrypted keys live in worker memory only, never in `localStorage` or IndexedDB;
  strict CSP; no third-party scripts in this build.
- **Served from the same third-party host as the rest of sovdev.pro** (maintainer decision,
  2026-10-05, made knowing the trade-off).
  Whoever serves the page's JavaScript can read what a web user opens, so for web users the
  third-party host is in the trust path. "The host can't read it" therefore holds for git and CLI
  users only, and **the site must say so** where private repos are offered. Reduce the exposure
  anyway: strict CSP, no third-party scripts, the WebAssembly package pinned by hash, and the
  build's hashes published with each release so a served copy can be checked.
- **Login and key generation as upstream has them** (the maintainer, 2026-10-05): private-key (nsec)
  login stays, and so does key generation in the browser. This reverses the sovdev.pro plan's
  "no nsec login and no key generation" rule for that build.

### M8 - Deployment (maintainer; at launch only)
Nothing is deployed until M2 to M7 are done. The storage node runs on a third-party host, which
is acceptable because it only ever holds ciphertext. A second node provides replication and the
watchdog pair.

### M9 - Paid tier and launch
- A payment webhook drives the tenant allowlist and per-plan quotas; NIP-11 `fees`.
- Launch review: a full adversarial pass on the server, the client library, the ngit fork and the
  web UI, then tag `sovtech-v1.0.0` on each.

### S - Standardisation track (parallel; the maintainer 2026-10-05: yes, alongside the build)
Nothing is published until M4's wire format has settled, and each publication is outward-facing,
so it needs the maintainer's go-ahead at the time.
- S1: CORD-git client spec as a standalone v0.2 document (owner model, key list, rotation),
  free of references to our code paths.
- S2: submit `docs/grasp-p/grasp-xx-draft.md` to the GRASP repo as a proposal; post the GRASP-08
  review comment (grasp-p #18).
- S3: register the kinds (30640, 30641, 3359, 23359 and the key-list kind) in the NIPs kind table.
- S4: offer the ngit private-repo path upstream.

## Verification
- Every MR: CI pipeline green on `ci-grasp` (fmt, clippy, unit, integration, e2e).
- M2: the four GRASP-P suites + upstream's suite + cord-git e2e (81+) against the v3 binary.
- M3 #14: anonymous and wrong-key `GET /list/<pk>` return identical 401; tenant-signed returns the list.
- M4: e2e scenarios that fail before each change. A hostile server serving an older state is
  refused. A stolen hosting key cannot add a writer that members accept. A second device with
  only the signer recovers every repo from the key list. A rotation killed mid-way is finished
  from a different device. A second checkout cannot clobber history.
- M5: the same scenario suite passes against the native and the WebAssembly builds; a 1-commit push
  to a large repo uploads O(delta); a revoke uploads no pack; no secret appears in `ps` output.
- M6: `git clone nostr://<hosting-npub>/<alias>` with the forked ngit, commit, `git push`, second
  clone `git pull`, all with stock git; a public `nostr://` repo still clones and pushes unchanged.
- M7: in a real browser against a test node, with an extension signer and with a bunker: create a
  repo, invite a second account, both browse code pushed with git, file and answer an issue,
  revoke the second account and confirm it can no longer read new content. Nothing key-like in
  `localStorage`/IndexedDB after the session.
- M8: verified at deployment time by the maintainer (replication between two nodes, the
  watchdog parity checks, no plaintext on the data volume, a reboot).

## Decisions already taken (2026-10-05)

Do not reopen these without the maintainer.

- The private tier is GRASP-P, not GRASP-08: GRASP-08 does not protect content from the host.
- The bar for the first release is external paying customers.
- The repository owner is the user's own npub (Concord's model); the per-repository hosting key
  only signs registrations.
- Each user's repository keys sync through a self-encrypted key list (Concord's Community List
  model), with its own kind number.
- Plain git over `nostr://` comes from a fork of the ngit client, not from a `cord://` helper.
- The web UI gets full management of private repositories, in the sovdev.pro build only, and it
  is required for launch.
- The web app is served from the same third-party host as storage. "The host cannot read it"
  therefore holds for git and CLI users only, and the site must say so.
- Private-key login and key generation stay in the web UI as upstream has them.
- A standardisation track runs alongside the build. Nothing is published without the
  maintainer's go-ahead at the time.
