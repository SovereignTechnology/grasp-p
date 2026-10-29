# GRASP-P to production: plan

A copy of the working plan for people and agents working in this repository. Deployment and
infrastructure detail is deliberately left out; it lives with the maintainer.

## Context

Upstream's GRASP-08 private mode is an access gate: the host still reads plaintext. GRASP-P with
its client (`cord-git`) is the system built in July 2026 where the server holds only ciphertext of
a private repository.
The goal is to make it production ready as the paid private tier of **sovdev.pro**, for external
paying customers.

State when this plan was written (2026-10-05):

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

### M1 - Repositories and CI (done)
- Two projects: this server fork and `cord-git`. Here, `main` started as unmodified upstream
  v3.0.7 (it carries GRASP-P since M2) and the old line is kept as `legacy/v1.2-grasp-p`.
- CI is a GitLab pipeline (`.gitlab-ci.yml` in each project): fmt, clippy, tests, the
  client's end-to-end suite against a pinned server commit, and release binaries on protected
  refs. Jobs run in single-use VMs on two dedicated runners, one for merge requests and one for
  protected refs.

### M2 - Port the server onto v3.0.7 (done)
`SEAMS.md` records the result: the seams, the decisions and what changed with v3.
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
- **#14** (done) `/list/<pubkey>` answers only the listed pubkey: `BlossomOp::List` and
  `authorize_list` in `src/grasp_p/blossom_auth.rs` (no `x` or `a` tag needed, the signer must be
  the pubkey in the path, every refusal is one identical 401). The server now accepts the
  authorization token in standard base64 and in base64url; the client still sends standard.
- **#24** (done) `/metrics` off by default on GRASP-P nodes, loopback only, no relay URLs in
  labels. With GRASP-P enabled the public listener answers `/metrics` like any unknown path,
  and the scrape is served by a listener of its own, only on the loopback address in
  `NGIT_GRASP_P_METRICS_BIND` (unset by default: collected, served nowhere), with no CORS
  header (`src/grasp_p/metrics_endpoint.rs`). The node that hosts private repositories serves
  public ones in the same process, so their `/metrics` is closed with it. In that scrape no
  relay is named by its URL (`src/grasp_p/relay_labels.rs`): the configured peers, which are
  the entries of `NGIT_GRASP_P_SYNC_PEER_URLS` (the bootstrap relay only when the list names
  it), appear as `peer-1`, `peer-2`, ..., and the per-relay series of every other relay are
  left out, those of the public service included; the aggregates stay. The peer alert
  selects the alias and also fires when the peer has no series. Both parts are in
  `SEAMS.md`, "Metrics leave a GRASP-P node on loopback only". Found on the way: upstream
  never sets `ngit_sync_relay_failures`, so the alert rule on it could not fire and is
  removed.
- **#6** (done) blob route hardening, three parts and one from its comment
  (`SEAMS.md`, "What the blob routes answer"):
  - A kind-24242 authorization could be replayed for a day either side of its `created_at`.
    It is now accepted only from one hour before to fifteen minutes after the node's clock,
    and a BUD-11 `server` tag binds it to the node: required for `list`, and for `upload`
    and `delete` checked when present and required once the client sends it (M4). The node
    keeps no record of used event ids, on purpose. Inside its window (75 minutes at most) a captured
    list authorization still returns that key's inventory, a captured upload with its bytes
    stores the blob again if the owner deleted it meanwhile, and a captured delete removes
    the claim again if the owner uploaded it again meanwhile; nothing else. A record of used
    ids would close these only on one node and only until its next restart, because a table
    in one process is neither shared with the peer nor kept over a restart.
  - The text of an internal error went to the client in `X-Reason`. The client is now told
    `internal error`, and the detail is logged.
  - `GET /list` reported `uploaded: 0`. A claim now records when the node first stored the
    blob, and the list and the upload descriptor report it.
  - `WWW-Authenticate: Nostr` on every 401 of the blob routes and on no other status.
- **#25** per-tenant claim/file-count caps (decided on 2026-10-27: a minimum billable size,
  no count; below); **#26** mirror fairness (**done**, below); **#20**
  purgatory SSRF and **#3** DNS rebinding (both via `outbound.rs`; the mirror half of #3
  **done**, below); **#16** announcement-indexer pin + leak canary.
  - **#26 done.** The mirror keeps one queue per account and serves them in turn, an
    account holds at most half of the fetch slots, the worker never waits for a slot,
    every failure class backs off (none is retried by every scan any more),
    `NGIT_GRASP_P_MIRROR_MAX_ATTEMPTS_PER_MIN` (default 600) bounds fetches started per
    minute over all accounts, the cheap local checks run before a request is sent, the
    scan runs off the async runtime, and a fetch's deadline grows with the blob's length.
    See "The blob mirror" in [`SEAMS.md`](SEAMS.md). Still open: nothing clears an
    account's retry gates when its quota is raised (a blob refused with `quota` waits out
    its backoff, about an hour at most; a restart clears it), and off a private link each
    attempt looks the peer's name up twice (the early check, then the resolver whose answer
    is connected to).
  - **#3, mirror half done.** The blob mirror's client has a resolver of its own
    (`src/grasp_p/vetted_dns.rs`) and uses no proxy: the DNS answer it vets is the one the
    connection uses, an answer with any address the mirror may not reach is refused whole
    (`blocked`), and nothing falls through to the system resolver. The early check stays
    for hosts that are IP literals. Still open: the relay dial is vetted and not pinned (a
    pinned WebSocket dial is offered upstream), and off a private link a name is looked up
    twice per attempt.
    See "The blob mirror fetches from the operator's peers only" in [`SEAMS.md`](SEAMS.md).
- **#1** offboard: kind-5 tombstone frees alias, keys, ledger; retention purge (customers leave).
- **#21** document every config var; **#10** adversarial re-review of the ported sync/mirror.

**Found in the M2 review (2026-10-05).** Each was traced in the code by a reviewer and
checked by a second one; none was run. Most were already on the v1.2 line. New with v3: the
NIP-11 probe, the wider reach of #10, the base-path check, the second SSRF switch under
"Peers", the git version and the stale runbook citations. They are not issues on the
project yet.

- **Report the unverified-sync flaw upstream** (ngit-grasp and nostr-sdk; `SEAMS.md`,
  "Synced events are verified here"). The fork is fixed. Reported on 2026-10-27, under the
  decision on upstream reports (below); our seam goes when upstream verifies for itself.
- **Upstream's NIP-11 probe follows redirects and reads an unbounded body** (done)
  (`src/sync/relay_connection.rs`), past the outbound target policy. The fork's probe
  follows no redirect, uses no proxy, reads at most 256 KiB, and checks an event-directed
  target on every call and, under the default target policy, connects only to the
  addresses that check vetted; not behind the GRASP-P switch (`SEAMS.md`, "The NIP-11
  probe is vetted, pinned and bounded here"). Beside #20. Offered upstream on 2026-10-27
  with the unverified-sync report (below); our seam goes when upstream hardens the probe
  itself.
- **Alias takeover by backdating** (done, the server half). A cross-tenant conflict was won
  by the lowest `created_at`, which has no lower bound, so any admitted tenant could evict
  another's alias, or, holding one of its keys (every member holds the shared aux key), the
  whole repository, and the loser's blobs were collected after the grace period. Now a seat
  whose first edition is more than an hour older than the node's clock is never the loser,
  by its alias or by any of its keys (`SEAT_SETTLE_SECS`, a constant, not a setting); younger
  seats merge as before, so two nodes that saw a fresh conflict in different orders still
  agree. The refusal is the ordinary conflict answer, and the warning carries
  `incumbent_settled=true`. A replay at start-up judges the seats the meta store already held
  by their age, as live (a refusal by age there deletes nothing), and the seats it creates (a
  rebuild) by the order alone; the cases where a restart or a rebuild still differs from the
  live decision are listed in SEAMS.md and the runbook, and a node must never start on a meta
  store older than its relay database. The runbook and both specs say so. See "A settled
  seat is not displaced" in [`SEAMS.md`](SEAMS.md). Still open: a repository can be taken in
  its first hour (M4 binds the alias to the account key); the node's clock now enters the
  merge, so a challenger that arrives just as a seat settles, or one racing a seat dated more
  than an hour back, can split the pair, with no repair tool before the offboarding work
  (#1); the loser's blob claims are still stripped at eviction.
- **Who may delete.** A kind 5 or a vanish request signed by a write key or a stream key is
  honoured for state roots and stream wraps, so a read-only or revoked member can delete a
  repository's stream history and block the shared stream key. Decided on 2026-10-27: only
  the account key deletes, and only a whole repository (below). **Done:** a write or aux key
  can send no vanish and no deletion request but a kind 5 naming 30640 coordinates under its
  own key (an offboard request); no request may name a state root or a stream wrap the node
  holds by id, or any by coordinate; the account deletes a repository by its registration's
  coordinate with `["k", "30640"]`, dated at most 15 minutes ahead, and may vanish unless its
  key is a write or aux key or signed stored state roots or wraps; tombstones no longer gate
  state roots and stream wraps, so a request sent before a key was registered cannot block
  it; upstream's deletion paths, the cascade of a public repository included, remove no
  state root or wrap, and the cascade no registration. Offboard requests and the accounts'
  vanishes ride the peer filters, so the other node of a pair sees the same deletion. **Done
  in merge request 15b** (decisions D15-6 and D15-7, below): a kind 5 with `["k", "30640"]`
  or a 30640 coordinate, the coordinate's kind read as a number, has the pure offboard shape
  whoever signs it (the signer's own coordinates and `["k", "30640"]` only, no event id, no
  more coordinates than the alias cap, within the private event size, and in whitelist mode
  only from a listed or registered key); an account's vanish names all relays or every node
  of the pair (the configured peers) and every node its registrations' `server` tags list,
  each value as written, and fits the size; a vanish frees every claim of its account whatever its date, with a canary
  test that fails if upstream ever bounds its vanish by date; a registration leaves the
  store only by its coordinate or its account's vanish, and an `e` id frees no claim. Other
  deletion requests and vanishes are upstream's, so strangers keep deleting their public
  events. See "Offboard requests and account vanishes on a shared node" in
  [`SEAMS.md`](SEAMS.md). Still open: the hold, restore and purge (#1, below); a vanish that
  reaches one node before the account's registration does, and names only that node, splits
  the pair.
- **Offboarding (#1) is half there.** An accepted deletion of a registration already frees
  the alias, the key claims and the blob claims. A deletion accepted on one node of a pair
  now reaches the other ("Who may delete", above). Missing: the tombstone and retention window
  (`NGIT_GRASP_P_OFFBOARD_RETENTION_SECS` is read and unused) and removal of the stored
  state roots and wraps. The text of issue 1 predates this. The hold is decided: 30 days,
  restorable by the same account key (below).
- **The hold for out-of-order events is capped by count only**, and an event is held before
  its size is checked. One sync relay can pin about 4096 x 5 MB. Give it a byte budget and
  do not hold what can never be admitted. **Done:** the size is checked first, only a
  rejection a later registration can cure is held, the hold has a byte budget (32 MiB, or
  64 events of the largest size) and the id skip-set a cap, and
  `ngit_private_hold_dropped_total` counts what was not kept. See "The out-of-order hold"
  in [`SEAMS.md`](SEAMS.md). Still open: the budget is one pool for the node, so a flood
  can fill it and honest early events then wait for the full re-issue.
- **Upload slots.** 64 for the whole node, no cap per tenant and no timeout on reading a
  body, so one write key can hold them all and stall the mirror too. With #25 and #26.
  **Done:** at most `NGIT_GRASP_P_MAX_UPLOADS_PER_TENANT` uploads in flight per account
  (default 8, answered `429`), a full node answers `503` where it answered `507`, the
  mirror takes no slot, and an upload body is cut with `408` after 30 seconds of silence
  or past a deadline set by `NGIT_GRASP_P_UPLOAD_MIN_BYTES_PER_SEC`.
  `ngit_private_upload_refused_total` counts each. See "Upload slots and the body
  timeout" in [`SEAMS.md`](SEAMS.md). Still open: eight or more accounts that each declare
  a large blob and send a byte inside every idle period can hold the node's 64 slots
  until the total deadline (about 4 h 33 min for 256 MiB at the default rate), because
  the rate is not checked as the body arrives; the bytes uploads in flight have reserved
  (up to 16 GiB at the defaults) still count against the global budget, so a node that
  close to it can still have mirror fetches refused with `quota`; and the client does
  not retry these answers yet.
- **#5 has a hostile form.** A tenant that references another tenant's stored blob keeps the
  charge on the uploader for good, at no cost to itself. Decided on 2026-10-27: every
  referencing repository pays the full size (below).
- **Order of checks in registration** (done). Proofs of possession were verified before
  the key count was capped and before the admission mode was consulted, and the mode was
  consulted after the conflict merge, so an anonymous sender could cost CPU and raise the
  conflict alert. A registration is now checked for shape first, without any signature
  check and with the key cap ahead of the keys; then for admission, on a read snapshot;
  then its proofs are verified; and the write transaction asks for admission again
  before it looks at any conflict. A sender the mode refuses costs no signature check
  and raises no alert. No message text changed and no registration is accepted or
  refused that was not before; which message a registration with several faults gets
  did change. See "Registration: cheap checks first ..." in [`SEAMS.md`](SEAMS.md).
  Still open: an admitted account can resend a 64-key registration and cost 64 checks
  each time, `open` mode refuses nobody before the proofs, and in `pow` mode one mined
  event with a bad proof can be re-sent.
- **Events of other kinds can attach to GRASP-P events** through upstream's related-event
  rule: uncharged plaintext stored beside a private repository, and served for it. **Done**
  (decisions of 2026-10-28, below): an event of any kind GRASP-P does not own, kinds 5 and
  62 aside, is refused when it tags a registration, a state root or a wrap by a coordinate
  of their kinds (judged from the event alone) or by the id of one stored here, whoever
  signs it, so a 10317 and the relay owner's events too; a report (kind 1984) is refused,
  logged and counted when it points at private content in any of the ways D10 needs (the
  node's blobs and denylist, an `x` beside either node's name, a write or aux key in `p`),
  and every other report is upstream's again, neither logged nor counted; registrations,
  state roots and wraps carry no reference tags beyond the state root's own `a`, nor the
  audit hashtag that upstream's cleanup deletes by. No seam in upstream's related-event
  rule: no GRASP-P event can reach it or vouch through it. See "Nothing attaches to
  private-repository events" in [`SEAMS.md`](SEAMS.md). Still open: an event naming a
  private event by an id this node does not hold yet is stored (accepted, D15-5); what was
  stored before stays.
- **Blob responses** (done). Every response of the blob routes says
  `X-Content-Type-Options: nosniff`, and a served blob also carries a
  `Content-Security-Policy` that makes it inert in a browser. A blob is served
  `Cache-Control: no-cache` with its sha256 as `ETag`, no longer cacheable for a year: a
  cache may keep it but asks the node before each reuse, and that question is answered 304
  only after the denylist and existence checks, so a taken-down blob gets the 451. Errors
  and 404s say `no-store`. Upload temp files left by an earlier run are removed when the
  store is opened. The operator's event blacklist now applies to the blob routes' writes
  ("The event blacklist", below).
- **Denylist reload** (done). The reload now starts from what the boot load read, so a file
  that can no longer be read or parsed keeps the entries it had at boot when another file
  changes. Still open: **what a missing denylist file means.** Today a file that is absent
  counts as empty, at boot and on reload, so a file that disappears (an unmounted volume, a
  deploy that is not atomic) lifts its takedowns within one reload interval. Decided on
  2026-10-27, not built yet: keep its last-known entries until a readable file no longer
  lists them (below).
- **Peers** (done). A configured peer, which is an entry of `NGIT_GRASP_P_SYNC_PEER_URLS`
  (the bootstrap relay counted as well at first, and no longer does; see the next point),
  is kept when its session ends, is not muted by the naughty list, and is dialled
  at least once every five minutes while it is down, where it used to be retired and muted
  for 12 hours. A pair on a private network sets `NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS=true`
  and leaves `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS` off: only the connection to a configured peer
  is exempt from upstream's target policy. Every event-directed relay dial of a GRASP-P
  node also refuses a NAT64 or 6to4 address that wraps an internal one. A pair test runs
  with upstream's guard on. Still open: the dial is vetted and not pinned (#3), a naughty
  list entry outlives the peer's recovery by up to 12 hours, and no test runs with GRASP-P's
  own guard on. See "Configured peers" in [`SEAMS.md`](SEAMS.md).
- **Egress on a node that also serves public repositories** (done in merge request 15c,
  decision C below). A GRASP-P node dials a relay that an event names over `wss://` only:
  the relays of announcements, purgatory's dependency relays, and the NIP-65 discovery and
  mailbox relays, the operator's index and fallback relays among them, since upstream
  registers them the same way. A `ws://` one is refused through upstream's own refusal
  branch, never dialled, and NIP-65 discovery passes over it when it picks the next source
  to dial. The bootstrap relay and the publishing of the relay's identity keep the scheme
  they are given, the bootstrap relay also when upstream registers it again after its
  session ended, and a `ws://` bootstrap relay draws a warning at startup;
  `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS=true` lifts the rule, and draws a warning too. A
  configured peer keeps `ws://` only under `NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS=true`,
  and without it a `ws://` peer stops the node at startup (unless
  `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS=true`, for tests and closed networks): a peer that is
  also the bootstrap relay is dialled as written and sent every alias and key. The relay
  dial and the blob mirror also refuse IPv6 outside `2000::/3` or inside `2001::/23`
  (Teredo, SIIT, SRv6), and still judge IPv4-mapped and NAT64 addresses by what they carry.
  No setting was added. See "Egress on a node that also serves public repositories" in
  [`SEAMS.md`](SEAMS.md). Still open, for merge request 20: git fetches get upstream's
  address check only; refused `ws://` entries still take an author's NIP-65 places.
- **#10 is wider on v3** (the reach of sync: done). The GRASP-P filters went to every live
  relay, including upstream's NIP-65 discovery connections, and any relay could bring a
  GRASP-P event into admission. The maintainer decided that GRASP-P data replicates only
  between operator-configured peers, with no setting to widen it, so both now happen on a
  configured peer's connection alone: only a peer is sent the filters (so only a peer's
  subscription slots carry them), only a peer may bring GRASP-P events, and only a peer's
  connection forwards duplicates; the bootstrap relay is a peer only when the list names it.
  See "Configured peers" in [`SEAMS.md`](SEAMS.md). Still open: on the peer link the GRASP-P
  and announcement filters share one subscription budget, and the watchdog's discovery
  filter does not page past 500 events; the sync filters do, through upstream's historic
  sync.
- **The fingerprint matched only a pair that bootstrapped to each other** (done). Its domain
  set was the node's address and the bootstrap relay, which since the point above says
  nothing about replication. With fingerprint v4 (`grasp-p-policy-v4`) it is the node's
  address and its configured sync peers, each spelled as the sync code files it, so two nodes
  that list each other hash one set and a list that leaves the other out shows; the
  bootstrap relay is out of it. The startup line names the peer set, and a node with the
  mirror on or a bootstrap relay set but no sync peer warns. The label also marks settled
  seats and who may delete, which changed acceptance with no setting since v3, and upstream's
  `NGIT_DELETION_REQUEST_DISRESPECTOR` joined, since it decides whether an offboard frees a
  registration's claims; later M3 changes add their knobs under v4, and M4 takes v5. See
  "Policy fingerprint v4 and the event blacklist" in [`SEAMS.md`](SEAMS.md). Still open: a
  pair that reaches each other by link addresses that are not their NGIT_DOMAINs cannot
  match without a setting that names the peer's service address.
- **The event blacklist** (done). It was checked against the author of an event only, so a
  listed account's write and aux keys kept writing, and the blob routes never read it. Now a
  state root, a stream wrap (stored or ephemeral), an upload preflight, an upload or a blob
  delete is refused when its signer is listed or the account holding the registration it is
  made under is, from clients and from sync alike (`blocked: Account <npub> is
  blacklisted`, `403` on the blob routes). A registration signed by one of a listed
  account's keys is refused, and no registration displaces a listed account's seat, however
  young. Reads, `GET` and `/list` stay open. The listed keys
  joined the fingerprint. Still open: the list is read at start, so each change needs both
  nodes restarted with the same list (M9's reload path); the published digest lets someone
  who can guess every other input test a guess of the list, as it always could for the
  whitelist.
- **Base path** (done). The check that a registration names this node ignored
  `NGIT_BASE_PATH`, and no test ran GRASP-P under one. A node under a mount path is now
  named by its host and that path together: in the `relays` and `server` tags of a
  registration, where the mirror and the private sync leave this node out of a peer
  list, and where the watchdog derives a blob base. Nothing changes for a node at the
  root of its domain. One integration test runs a single node under a path; no pair
  test does. See "Under a base path the node is its host and its path" in
  [`SEAMS.md`](SEAMS.md).
- **Blob mirror peers** (done). They defaulted to the `server` tags of accepted
  registrations when no allowlist was set, so tenant events chose hosts the node
  connected to. With #26 a blob that several accounts claim is fetched for the account
  with the least backlog, the other claimants are tried when that account's own state
  refuses it, and one account holds at most half of the fetches. Now, under the
  maintainer's decision that GRASP-P events and blobs replicate only between
  operator-configured peers, the mirror's peers are `NGIT_GRASP_P_MIRROR_PEER_URLS` alone,
  less the entries that name this node; `server` tags are advisory and choose no host; a
  node with the mirror on and no peer warns at startup and fails each missing blob as
  `no_peer`. Every peer is believed about a blob's length up to the maximum, and the rule
  that held a registration-named peer to the declared size is gone. The connection goes to
  the address the client's resolver vetted (#3, above). No setting was added. Still open:
  the sync and mirror lists are separate settings the node does not compare. See "The blob
  mirror fetches from the operator's peers only" in [`SEAMS.md`](SEAMS.md).
- **Fail fast on old git** (done). The server checks `git --version` at startup, before the
  storage migration (`src/git/version.rs`). With GRASP-P enabled a git older than 2.42 stops
  it with a message that names the version found, the minimum and the symptom, and so does
  a git that cannot be run; with GRASP-P off either is one warning.
- **Docs (#21).** The runbook cites `file:line` from the v1.2 line and names a deployment
  that does not exist; the config reference still describes the tagless-1059 window.

### M4 - Protocol v0.2 and client correctness (`sovtech/cord-git`, `crates/cord-core`)
No private repo is live anywhere, so v0.2 breaks compatibility freely. Decisions are the maintainer's,
2026-10-05, after checking how Concord does it (CORD-02 section 8, CORD-05 section 4, CORD-06).

- **Owner = the user's own npub (Concord model).** Today the owner *is* the per-repo hosting key
  (`repo.rs:1559`, `owner_pk = hosting.public_key()`). Change: `community_id` commits to the
  owner's real key (`crypto.rs:47`, same formula, different input). Rekeys (inner 3303), roster
  records, invites and promotions are signed by the owner through their signer, inside encrypted
  content the server never sees. Members verify against the key committed in `community_id`.
  - The **hosting key** shrinks to a server-facing registration key: it signs kind 30640 only.
    The server is unchanged; it still sees only the hosting key. The hosting (account) key must
    never be the user's public npub: the node also serves public repositories, and one REQ for
    kind 30640 by that author would answer whether someone is a customer of the private tier.
  - **One hosting key per customer, not per repository** (the maintainer, 2026-10-05; needed for
    per-account storage, M9). It is the customer's account on the node, and the key list holds
    it once. Design it in here, before the v0.2 wire format settles.
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
- **Alias bound to the account key** (decided 2026-10-27; see the M3 decisions below). The
  registration commits its alias to the hosting key, so no other account can ever register an
  alias that is taken; the server checks it from the event alone and the alias half of the
  conflict merge goes. Until then the server protects repositories older than one hour (M3).
  The client, both specs and the GRASP draft change with it.
- **Invites are real NIP-59**: the seal is signed by the inviter's own key (**#17**); `join` checks
  the inviter against the owner-signed roster and the delivered keys against the live repo.
- Remaining defects: **#22** per-working-tree CAS anchor, **#25** "none valid" is not "never
  pushed", **#27** publish to every relay with read-back, **#34/#33** rejection recovery, **#28**
  invite size ceiling, **#30** co-maintainer announcement leak, **#18** e2e false-pass.
- Server follow-on in the same milestone: drop the legacy 1059/21059 stream-wrap window (nothing
  deployed needs it).

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
the maintainer, 2026-10-05 (replaces the `git-remote-cord` / `cord://` helper; tracks cord-git
#20). Git picks its helper from the URL scheme, so `nostr://` always runs `git-remote-nostr`,
which ngit ships.

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
  bunker (NostrConnect), Amber and private-key accounts. The login key signs the owner's records,
  never a registration: the account key is a key of its own, never the user's public npub (M4),
  since a REQ for kind 30640 by that npub on the shared node would show the user as a customer.
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
Nothing is deployed until M2 to M7 are done. The private tier runs in the public git service's own
process and under its hostname (decided 2026-10-05): the public git service runs this fork's
binary with GRASP-P enabled, on a third-party host. That host holds the public repositories in the
clear, as it does today, and only ciphertext of the private ones. A second node provides
replication and the watchdog pair. Each node lists the other by its public `NGIT_DOMAIN`: in
`NGIT_GRASP_P_SYNC_PEER_URLS` over `wss://`, and in `NGIT_GRASP_P_MIRROR_PEER_URLS` over
`https://`. On a private link it may use `ws://` and `http://` with
`NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS=true`, but only when that address is the peer's
`NGIT_DOMAIN`, the name the fingerprint's domain set holds; a sync peer listed by another address
never matches. A `ws://` sync peer without that setting stops the node at startup, unless
`NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS=true` (tests and closed networks). The same two lists name
the pair when a report's `server` tag is judged.

### M9 - Paid tier and launch
- A payment webhook drives the tenant allowlist and per-plan quotas; NIP-11 `fees`.
- **Storage is sold per account, with any number of private repositories inside it, and paid
  upgrades raise it** (the maintainer, 2026-10-05). An account is one hosting key; a plan is a
  byte allowance for that key. Already there: the server keeps a ledger per hosting key
  (`src/grasp_p/quota.rs`), and allowlist admission is enforced at registration. To build, and
  where it lands:
  - **Server, per-account limit (with M3 #25).** A limit record per hosting key in the meta
    store (bytes, repository count, paid-until). `quota::check` and the alias-limit check in
    `registration.rs` read it and fall back to the node default. The per-repository cap stops
    binding (repository limit = account limit). The repository-count limit stays as an
    anti-spam bound, raised per plan, not removed.
  - **Server, set it without a restart.** The allowlist and the limits are read once at boot
    today. Add a local-only admin path, or a file re-read the way the denylist is. Both nodes of
    a pair must hold the same record, or one accepts a push the other refuses (the allowlist is
    in `policy_fingerprint`; decide whether the limits join it or the hook writes both nodes).
  - **Server, lapsed accounts (with M3 #1).** The admission mode gates NEW aliases only, so
    leaving the allowlist does not stop existing repositories. A lapsed account goes read-only
    (no new state roots or uploads, reads keep working), then offboards after the retention
    window. The blacklist's freeze (M3) already asks one question on every write path
    (`PrivateService::write_blocked`); a lapsed account can be one more answer to it.
  - **Client, one hosting key per customer (M4).** `cord-git create` mints a fresh hosting key
    per repository by default, and the server treats each hosting key as a separate account.
    All of a customer's repositories register under one account key. Cost, known when this was
    added: the server and anyone watching it can link all of a customer's private repositories
    to one key, where today each repository looks unrelated. Addresses become
    `nostr://<account-npub>/<alias>` (M6).
  - **Usage (M5 CLI, M7 web UI).** A hosting-key-signed usage request (bytes used, limit,
    repository count) so the CLI and the web UI can show it. Nothing reports usage to a tenant
    today.
  - **Order.** Not before delta packs (M5 #4): today every push is one full pack and the last
    16 editions stay charged, so an account pays for up to 16 copies of each repository, and a
    repository cannot exceed the 256 MiB blob cap. Not before cross-tenant charge pinning is
    fixed (issue 5, M3): one tenant can keep bytes charged to another.
  - The allowance per plan is not decided.
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
- M3 #24: on a GRASP-P node `GET`, `HEAD` and `POST /metrics` on the public port answer like an
  unknown path; the loopback endpoint serves the scrape with no CORS header; a node whose
  metrics address is taken does not start; on both nodes of a replicating pair the scrape shows
  the peer as `relay="peer-1"`, connected, and holds neither the peer's address nor `ws://`
  nor `wss://`; a relay that only a public repository on one of the nodes names is counted
  there as tracked and has no series in the scrape.
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
  watchdog parity checks, no plaintext of a private repository on the data volume, a reboot).
- M9: a key that is not on the allowlist cannot register. Two repositories under one account
  share one allowance: the push that crosses it is refused, and raising the account's limit
  through the hook lets it through with no restart, on both nodes. A lapsed account can read
  and cannot push. The CLI and the web UI show the same usage figure as the server's ledger.

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
- Storage is sold per account, with any number of private repositories inside it. An account is
  one hosting key, so all of a customer's repositories register under one key, which lets the
  server link them.

## Decisions taken for M3 (2026-10-27)

Do not reopen these without the maintainer either. Each is the option that was recommended
when the question was put.

- A stored blob that several repositories reference is paid by every one of them, at its full
  size, while it references it; two repositories of one account count it twice in v1, and the
  disk keeps one copy (#5). An account's bill then depends on its own repositories alone, and
  both nodes of a pair compute the same ledger in any arrival order.
- Small objects are billed at a minimum of 16 KiB per stored or declared blob, with no separate
  count of objects (#25). The minimum is advertised in NIP-11 and stated wherever plans are
  described. Objects are then bounded by bytes at every scope, and the per-account limit record
  of M9 needs no object field.
- Only the account (hosting) key deletes anything from the server, and only a whole repository,
  through its registration (done in M3; above). Members cannot delete from the server: clients hide content through
  the encrypted stream, and the site says that the ciphertext stays until the repository is
  deleted. The server cannot tell members apart behind a shared key, so any deletion by a member
  would be a right for every member to delete everything.
- A deleted repository, or a closed account, is held for 30 days and can be restored by the same
  account key; its bytes count against the allowance until the purge (#1). A NIP-62 vanish closes
  the account under the same hold. The deletion request itself stays public under upstream's
  retention, and the privacy text says so. The site promises erasure within 30 days, plus one day
  of blob grace.
- A repository older than one hour cannot be displaced by another account, by its alias or by any
  of its keys (done in M3; above). In M4 the alias is bound to the account key in the v0.2 wire
  format, so that no other account can ever register it. Accepted until then: an admitted account
  can take a repository's alias in its first hour; the node alerts with that account's key, and
  the account is closed. Accepted with it: the node's clock enters a merge decision, so the two
  nodes can disagree about a challenger that arrives just as a repository turns one hour old, and
  the tool to repair that arrives only with the offboarding work.
- An account on `NGIT_EVENT_BLACKLIST` is frozen on both nodes (done in M3; above): no new
  registrations, state roots, stream wraps, uploads or deletions, by the account or by any of
  its registered keys.
  Reads and `/list` keep working, so a customer can take their data and leave; removing content
  stays the denylist's job. The list joins the policy fingerprint, so each change needs both
  nodes restarted with the same list until M9's reload path takes it over.
- Reports (kind 1984) that point at private-repository events are logged and counted as today,
  then refused: they are neither stored nor served. The runbook asks reporters to include the
  blob key, so a stored report would publish that key beside a public blob, and an accusation
  against a customer's repository with it. The log line and the counter stay the operator's
  intake. On a node that also serves public repositories (D1) this covers only the reports that
  point at private content; the others are the public service's, under upstream's rules, and
  are neither logged nor counted (decided 2026-10-28, below; done in M3).
- A denylist file that was loaded and then disappears keeps its takedowns: the node keeps its
  last-known entries and logs an error, and a takedown is lifted only by a readable file that no
  longer lists the hash. A file missing at boot is still tolerated.
- Findings in upstream's own code go upstream in two batches. Ordinary robustness and
  documentation fixes are offered as they land here. The security-relevant ones (the NIP-11
  probe, `/metrics` open with CORS `*`, the related-event anchors, the NAT64 and 6to4 gap) go
  privately with the unverified-sync report, after the operator's own public instance has been
  checked. Each offer still needs the maintainer's go-ahead at the time. The unverified-sync
  report and the NIP-11 and NAT64 items went upstream on 2026-10-27; the `/metrics` and
  related-event items follow later.

## Decisions taken for M3 merge request 15 (2026-10-28)

Do not reopen these without the maintainer either. The node that hosts private repositories
also serves public ones, in the same process and under the same hostname (decided 2026-10-05),
so the written "private-only node switch" was re-scoped for a mixed node, in three merge
requests (15a, 15b, 15c); every recommendation was taken.

- No event of a kind GRASP-P does not own may reference private-repository content: not by a
  coordinate of a registration, state root or stream-wrap kind, and not by the id of such an
  event stored on the node. This covers every kind, not reports alone, so a 10317 and the relay
  owner's events are covered too, and a public event that tags private content is refused even
  when it also tags public content. Kinds 5 and 62 stay with the deletion rules.
- The report intake (log line and counter) takes only the reports that point at private
  content; every other report is upstream's.
- A report that names in `p` a write or aux key held on the node points at private content; an
  account key does not count.
- A refused reporter gets one neutral fixed text. The runbook and the client spec tell reporters
  to put the blob's sha256 in an `x` tag and to send the blob key only by direct mail to the
  operator, never in an event.
- A reference by id to a private event that the node does not hold yet (one still on its way
  from the peer) is not recognised; this is accepted and documented.
- Deletion requests shaped as offboard requests (a `["k", "30640"]` tag, or a 30640
  coordinate) take the pure offboard shape for every signer, with caps and a whitelist refusal;
  a vanish from a key that holds registrations must name every node of the pair or all relays
  (15b, done). Review narrowed two points, both so that the two nodes of a pair answer
  alike: an offboard request names no event id at all (the decision allowed ids of the
  account's own editions beside their coordinate, but whether an id is one depends on which
  editions each node holds), and the vanish names the configured peers and every `server`
  value as written, this node's included (each node knows the other's own address only from
  its peer list).
- A vanish dated before an account's registrations frees every claim, matching what upstream
  actually deletes, with a test that fails if upstream ever bounds its vanish by date (15b,
  done).
- The bootstrap relay and the publishing of the relay's identity keep `ws://` with a boot
  warning; relays that events name are dialled over `wss://` only (15c, done). A configured
  peer keeps `ws://` only on a link declared private, checked at startup.
- The fingerprint over private links needs no code: M8 lists each peer by its public
  `NGIT_DOMAIN`, over `wss://`, or over `ws://` on a private link only when that address is the
  peer's `NGIT_DOMAIN` (M8, above). 15c refuses at startup a `ws://` peer on a link not declared
  private.
- A report's `server` tag names the pair only as this node's service address and the peers in
  `NGIT_GRASP_P_SYNC_PEER_URLS` and `NGIT_GRASP_P_MIRROR_PEER_URLS`, never the `server` values of
  registrations: an account writes those as it likes, so it could otherwise make the node refuse
  public reports, at a cost no cap bounds (taken in the review of 15a).
- Refused synced public events share the sync hold's id-only budget with GRASP-P's own
  refusals until merge request 18 gives them a budget of their own (taken in the review of 15a).
