# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Summary

Private Repos - via private grasp service (grasp-08) - initially self-hosted only but the intention is to allow providers to offer it as service.

Proactive Sync Plus (GRASP-03) - a big enabler for maintainer based moderation and simplier and more performant git nostr clients.

Performance and Security fixes - along with other improvements; immediate upgrade recommended; some breaking changes make v2-v3 a one way street!

Expect a bit of downtime as a git data migraiton is performed on startup. The largest grasp service relay.ngit.dev took 50mins.

### Breaking changes

- Version 3 performs an automatic, one-way migration of `NGIT_GIT_DATA_PATH`
  from complete per-owner and `/prs/` repositories to thin views backed by
  shared identifier families. Version 2 does not coordinate reads and writes
  through this layout and must not be run against migrated Git data. Rollback
  requires restoring the Git and relay-data snapshot taken before the v3
  launch, not only downgrading the binary.
- The v3 storage migration finishes before the HTTP server starts listening,
  so operators must plan for relay downtime during the upgrade. The largest
  GRASP service migrated so far spent 51 minutes migrating 2,294 repository views
  into 2,014 identifier families, retired 2,291 backups, and retained three for automatic integrity repair.
- Maintainer authorization now uses reciprocal membership. A pubkey listed by
  a confirmed maintainer is only invited and cannot publish authoritative
  repository state until its own kind-30617 announcement for the same
  identifier lists back an existing confirmed maintainer. At release time,
  this changes the effective authorization state of zero live repositories;
  it is breaking for future invitations because they now require an explicit
  acceptance step. Repository announcements now support the NIP-34 `M`
  (lead maintainer), `m` (co-maintainer), and `o` (moderator) role tags.
  Active `M` and `m` entries define maintainers; `o` does not grant
  repository-state authority. The deprecated `maintainers` tag is used as a
  fallback only when none of those role tags are present.
- Added `trusted_proxy_cidrs` to the public `Config` struct. Rust consumers
  that construct `Config` with a struct literal must provide it.
- Added `base_path` to the public `Config` struct. Rust consumers that
  construct `Config` with a struct literal must provide it.
- Added `startup_integrity_identifiers` to the public `Config` struct. Rust
  consumers that construct `Config` with a struct literal must provide it.

### Security

- Reject unsuitable peer-advertised NIP-65 relay URLs before they can occupy
  mailbox selection slots, overlays, probe queues, or metrics: URLs failing
  the static outbound-target checks, `.onion` hosts (temporary mailbox
  policy), URLs matching nostr-watch's 52-word generated-path rule, 64-hex
  path segments, hostname-repeating path segments, and URLs over 2,048 bytes.
  These are single-URL rules; relay lists are never rejected wholesale, and
  legitimate path-based relays (`/inbox`, `/outbox`, language and versioned
  paths, semantic queries) remain accepted.
- Canonicalize accepted NIP-65 relay URLs and bound every per-author selection
  to at most four relays per purpose, taken in published tag order after
  deduplication so trailing-root-slash and default-port variants of one relay
  consume a single slot. Live inbox coverage and owner/maintainer repository
  inboxes select `read`/unmarked relays, identity refresh selects
  `write`/unmarked relays, and participant history prefers `write`/unmarked
  relays with read-only relays filling remaining slots. The bound is a hard
  internal constant, so one hostile or machine-generated kind `10002` list
  cannot inflate mailbox inventory. Canonical keys now match the connection
  map, fixing trailing-root-slash mailbox relays that previously could never
  start their history probe.
- Bound every sync-actor notification channel and require `auth-required`
  retry IDs to own a current subscription-ledger permit. Repeated terminals,
  forged subscription IDs, and delayed worker results can no longer create
  unbounded retained memory.
- Added opt-in trusted-proxy CIDRs so WebSocket connection policy, per-IP
  metrics, abuse indicators, and logs can use the real client address without
  trusting spoofable forwarding headers from arbitrary direct peers.
- Reject non-canonical and path-traversing repository coordinates after URL
  decoding across repository landing pages, Git Smart HTTP, and GRASP-06.
  All tagged releases through v2.1.2 could resolve crafted requests outside
  the requested repository namespace, allowing unauthenticated reads of Git
  repositories accessible to the service. With GRASP-06 enabled, crafted PR
  submissions could also write Git objects and PR refs into another hosted
  repository without its maintainer authorization. Any deployment that enabled
  GRASP-06 on a tagged build through v2.1.2 should treat its hosted Git
  repositories as potentially containing unauthorized objects or refs until it
  completes the v3 integrity checks. Conforming Nostr Git clients that resolve
  refs from valid signed State, PR, and PR Update events are not expected to
  accept this unauthorized data; direct Git consumers do not have that
  protection. Operators must upgrade to v3.0.0. By default, every v3 startup
  runs a non-blocking authorization-integrity pass that compares every served
  branch, tag, `HEAD`, and `refs/nostr/*` ref with the
  accepted State, PR, and PR Update events (including precisely scoped
  in-flight events). Owner-view PR refs require either confirmed-maintainer
  overlap with the target or an exact standard clone URL naming that owner and
  identifier on the service; similar, foreign, and `/prs/` URLs do not count.
  It repairs unambiguous differences and emits
  `manual_inspection=true` errors without deleting unexplained PR refs that
  may be evidence. GRASP-06 operators must check those logs and the terminal
  `Git authorization-integrity startup pass completed` summary; any non-zero
  `manual_inspection` or `failed` count means the named repository still
  requires review. `NGIT_STARTUP_INTEGRITY_IDENTIFIERS` can temporarily scope
  both startup integrity passes for release-candidate validation, but scoped
  logs establish integrity only for the named repositories. Operators must
  remove the scope and complete the default all-family sweep before treating
  the v3 upgrade as complete. The live `integrity-check --identifier` command
  now compares storage and event authorization together; it is check-only by
  default and applies safe fixes with `--repair`.

### Added

- Build a reproducible, statically linked x86_64 Linux archive and checksum
  from every version tag.

- Add `NGIT_BASE_PATH` / `--base-path` (NixOS `basePath`) so one GRASP server
  can be mounted below a shared domain path. WebSocket, Git Smart HTTP,
  GRASP-06, NIP-11, metrics, icons, landing pages, service matching, generated
  NIP-65 identity, and self-sync all use the configured prefix. Requests
  outside it are rejected. Path-mounted servers neither serve nor advertise
  the root-domain NIP-05 identity, and their generated kind-0 profile omits
  the `nip05` field.

- Publish the relay-owner identity on startup as a minimal kind-0 profile with
  the scheme-less public URL as `name`, `bot: true`, and `_@domain` NIP-05 for
  domain-root deployments,
  plus a kind-10002 list naming this relay as its sole read/write relay. An
  operator-customized profile survives restarts, and no identity event —
  stored or generated — is published before the local database and at least
  one user-index relay have been checked for that kind. Every send is
  preceded by a per-relay re-check: an identity found on a user-index relay
  (for example after a local database wipe) is adopted locally and never
  overwritten, so the relay only fills identity gaps on the indexes,
  retrying transient failures with a capped backoff. In private mode the
  identity is seeded locally but never published, so a private relay's
  existence is not advertised. The relay also trusts events signed by its
  own key so that key can operate an `ngit-ci` coordinator, but only for
  kinds without a dedicated admission policy: owner-signed NIP-34 repository
  events pass the normal announcement, state, and PR policies, and
  NIP-09/NIP-62 tombstones still prevent replaying retracted owner events.
- Serve the relay owner's public key as the NIP-05 `_@domain` identity from
  `/.well-known/nostr.json`. NIP-11 advertises NIP-05 only when requested at
  the domain root (`/`); relays mounted below a path do not claim support.
- Add fixed-cardinality aggregate metrics for important long-lived sync state
  and document the producer, cleanup owner, bound, and terminal behavior of
  every peer-influenced transient subsystem.
- Add bounded, operator-configurable inbox fallback coverage when a successful
  Sync+ user-index query finds no accepted NIP-65 relay list for a root author.
- Add a default-on `NGIT_SYNC_PLUS_ENABLED` opt-out and advertise GRASP-03 in
  NIP-11 only when the Sync+ overlay is effective.
- Recover repository-event descendants which reference a direct thread member
  but omit the repository and root-event tags. When the per-connection ledger
  can retain complete descendant coverage while preserving control and
  historic capacity, those filters stay live; otherwise bounded EOSE-closing
  history provides eventual coverage. Direct replaceable and addressable
  members contribute both their event ID and NIP-01 coordinate, covering
  descendants which use `a`, `A`, or coordinate-valued `q` tags. The frontier
  is deliberately non-recursive and connection sharding remains unnecessary.

### Changed

- Retire identifier-family migration backups family by family. Once every
  view of a family is installed, each backup is verified (family contains
  every Git-readable backup object, thin views match their journal snapshot,
  family packs are indexed and valid), and the ordinary family integrity
  report must be healthy before deletion. Unhealthy families retain their
  backups for automatic repair. Healthy backups are deleted before the next
  family migrates, bounding peak migration disk overhead to the family in
  flight. Unindexed legacy packs are quarantined by content under
  `.grasp/migration/unindexed-packs/`, unverifiable backups are retained with
  a warning, backup-directory removals are fsynced before their journals are
  removed, and completed installations whose backups were already removed
  manually start unchanged.
- Reconcile server-side shallow repositories left by untagged development
  builds between 2026-01-05 (`623cae5`) and 2026-01-12 (`f25eea8`). No tagged
  v1 or v2 release shipped the depth-one fallback fetch. The affected
  non-happy path fetched missing state or PR data from another listed Git
  server when the objects had not arrived by push. V3 preserves existing
  shallow clone behavior and the legacy backup, automatically requests the
  complete closure from accepted clone sources, and logs any family that
  remains shallow without making it less available.
- Scope bare log levels to ngit-grasp while keeping dependencies at warnings;
  explicit tracing filter expressions remain unchanged.
- Keep per-event discovery and validation details at debug, retain aggregate
  sync outcomes at info, and report unsupported NIP-77 once per connection
  instead of warning once per filter.
- Treat routine client disconnects, incomplete HTTP/WebSocket sessions, and
  Git missing-object probes as debug diagnostics while preserving internal
  service and database failures as errors.
- Metrics compatibility: removed the
  `ngit_sync_naughty_relay_info{relay,category,reason}` metric because its relay
  and raw reason labels were peer-controlled and unbounded. Use the unchanged
  `ngit_sync_naughty_relays_total{category}` metric for fixed-cardinality
  aggregate quarantine counts.

- Minimise live-subscription churn as repository coverage grows: stable full
  core groups and descendant groups remain open. The mutable core tail is
  repacked in full when doing so releases slots; otherwise only the smallest
  useful subset is replaced to absorb new filters. This accounts for both
  filter-count and serialized-byte limits. Repository filter chunks are
  deterministic, and failed tail replacement restores the previous tail.

### Fixed

- Restore cold rejected-maintainer recovery after policy admission pre-saves
  the newly authorized announcement for membership reconciliation. An exact
  duplicate from that intentional pre-save now still broadcasts the
  announcement and expands its state/Git dependencies, while a genuinely
  superseded replaceable event remains classified as a duplicate without
  downstream fan-out.

- Discover historical repository roots and descendants from the NIP-65
  inboxes of accepted repository owners and maintainers. Public Sync+
  instances probe exact repository coordinates and every known root on those
  authors' bounded, sanitized read/unmarked inboxes through paced,
  byte-bounded history workers. This coverage is deliberately historical-only:
  owning or maintaining a repository never adds an author's inbox relays to
  ordinary persistent live repository targets, while accepted root authors
  retain the pre-existing live inbox coverage. Private instances continue to
  withhold repository coordinates, and the ordinary write policy and
  persistent deletion tombstones remain authoritative.

- Retire peer-closed outbound subscriptions from rust-nostr's desired registry
  without interrupting NIP-42: the first `auth-required` response keeps the
  same subscription and ledger slot for one authenticated retry, while a repeat
  refusal becomes a 24-hour policy pause. This prevents authentication replay
  and live repair from multiplying rejected IDs without bound. Policy detection
  precedes descendant fallback, while an unclassified live closure waits for
  the ordinary cooldown before one repair attempt.

- Bound duplicate repository Git acquisition to one primary and one delayed
  distinct-domain hedge, and recover from silent transports without imposing a
  total fetch deadline. Continuously active large transfers remain unbounded;
  a process group silent for five minutes is terminated gracefully then
  forcibly, after which remaining sources are tried sequentially. Concurrent
  object acquisition does not write `FETCH_HEAD`, run automatic maintenance,
  or infer source speed from a shared object database.

## [2.1.2] - 2026-08-08

ngit-grasp 2.1.2 is a patch release improving repository-event sync under
cold-start archive load. It prevents permanent relay policy refusals from
driving subscription rebuild loops, adapts request grouping to unusually low
remote filter-count limits, and keeps valid purgatory events alive while their
Git data is actively being fetched. It also adds whole-service resource
metrics and reduces routine missing-repository log noise.

### Changed

- Log routine Git `info/refs` requests for repositories not yet available
  locally at DEBUG rather than WARN; this is expected during propagation.

### Added

- Export total cgroup CPU and memory usage, including child Git processes,
  through the Prometheus metrics endpoint on Linux. Process-only CPU, memory,
  thread, and file-descriptor metrics provide diagnostic detail.

### Fixed

- Adapt to relays with undocumented per-REQ filter-count limits. Explicit
  multi-filter refusals now lower a per-session grouping ceiling geometrically
  and retry the exact live or historic coverage; response numbers are not
  trusted because implementations variously report submitted counts or caps.
- Stop permanently refused live subscriptions from rebuilding themselves in a
  tight loop. Blocked, restricted, membership-required, and filter-incompatible
  responses retain the connection, retire the rejected coverage for 24 hours,
  then receive one recovery probe; bounded metrics distinguish the policies.
- Keep purgatory announcements, state events, and PR events alive while a
  concrete background Git sync for their repository is actively running. A
  large healthy clone can exceed the nominal 30-minute purgatory window;
  queued and backoff-only work remains eligible for normal expiry so broken
  repositories cannot extend retention indefinitely.
- Preserve purgatory and rejected-event recovery across abrupt termination.
  Their snapshots now remain after restore and are atomically replaced every
  60 seconds, bounding crash loss to one interval instead of consuming the
  only durable copy at startup.
- Treat cumulative retained-subscription byte refusals as capacity signals,
  not temporary query-rate episodes. The sync client learns the disclosed cap,
  rebuilds persistent coverage within it while reserving one maximum transient
  REQ, serializes transient work against that reserve, and covers overflow with
  paced five-minute history plus overlap instead of retrying the same
  impossible live set.
- Replace relay ownership when an addressable repository announcement changes,
  rather than retaining every relay URL ever listed. Fully expired StateOnly
  purgatory targets are pruned while soft-expired and promoted repositories are
  preserved. Healthy connections and live requests are left undisturbed;
  naturally closed subscriptions rebuild from current ownership, and naturally
  ended connections omit obsolete items when deciding whether to reconnect.
- Raise retained subscription state per connection from 1 MiB to 5 MiB. A
  production 34-filter repository-sync live set reached roughly 1.2 MiB, so
  rust-nostr's newly introduced default repeatedly closed part of persistent
  coverage. The replacement remains a finite per-connection bound and matches
  the relay's maximum admitted WebSocket message size.

## [2.1.1] - 2026-08-08

ngit-grasp 2.1.1 is a patch release improving relay-to-relay sync stability
under newly introduced query-rate limits. It handles explicit query refusals,
paces non-urgent background work per relay, and temporarily relaxes the
embedded relay's over-restrictive rust-nostr 0.45 query allowance while the
upstream NIP-77 accounting is reviewed.

### Fixed

- Temporarily override rust-nostr 0.45's newly introduced LocalRelay query
  allowance from 120 to 1,200 messages per minute per connection. This retains
  a finite DoS backstop while avoiding an unusually restrictive default that
  also charges every SDK-managed NIP-77 `NEG-MSG` continuation. Re-evaluate
  the 10× allowance after upstream revises that NIP-77 accounting.
- Proactively space non-urgent historic sync, pagination, hydration, retry,
  and dependency query starts at one per second per relay connection. Live
  subscriptions bypass the background gate, while the existing adaptive
  refusal handling remains the backstop for tighter or internally generated
  traffic.
- Pace query starts after a relay reports its per-connection query-rate budget
  is exhausted, preventing fixed cooldown recovery from replaying the same
  fast historic-sync burst indefinitely. If an SDK-managed NIP-77 exchange
  exhausts that budget, use paced REQs for the rest of the connection session
  because the application cannot pace individual `NEG-MSG` frames. This is a
  reactive compatibility backstop for an unadvertised limit, layered over the
  proactive background pacing while leaving live coverage prioritised.

## [2.1.0] - 2026-08-07

ngit-grasp 2.1.0 substantially improves proactive repository-event sync
reliability, compatibility, resource accounting, and recovery without adding
new sync features. It also updates rust-nostr to 0.45.0 and makes the relay's
defensive limits explicit and operator-configurable.

### Added

- Expanded `grasp-audit` with stable machine-readable results, full JSON
  reports, explicit audit identities, and hardened discovered-server probes.
- Added bounded request-class labels to transient-sync watchdog logs and
  metrics so operators can identify which historic recovery path is stalling.

### Changed

- Upgraded the rust-nostr crates from `0.45.0-alpha.8` to the stable `0.45.0`
  release, including the upstream NEG-OPEN handling fix and new local-relay
  resource hardening. The embedded relay now imposes 500 active REQs per
  connection; per-minute connection quotas of 60 event writes, 120 queries,
  30 authentication events, and 6,000 WebSocket messages (raised from
  rust-nostr's 300/minute default after it disconnected legitimate bursty
  clients in production); 20 filters per REQ; 500
  results per filter; 250-byte
  subscription IDs; 1 MiB retained subscription state; 10 active negentropy
  sessions and 50,000 negentropy items per connection; 5 MiB WebSocket
  messages; and a 10-second handshake deadline. ngit-grasp deliberately:
  - makes the discoverable subscription and filter-result limits configurable
    and advertises them in NIP-11;
  - raises rust-nostr's new 64 KiB event bound to a configurable 192 KiB
    default because valid NIP-34 patch events in production reach about
    149 KiB; and
  - overrides rust-nostr's new 128-connection default to preserve documented
    unbounded-by-default inbound admission, while keeping configured caps exact.

### Security

- Restricted event-directed sync targets to globally reachable endpoints.
  Relay and clone URLs from untrusted repository announcements and PR events
  reached the proactive WebSocket and `git fetch` sinks after syntax-only
  checks; production logs showed sync dialling `ws://localhost:3334`,
  `ws://127.0.0.1:7334`, and a CGNAT address, so a crafted event could point
  a public relay at loopback or internal infrastructure (SSRF). A fail-closed
  outbound target policy now runs immediately before every event-directed
  connection and git fetch: per-sink scheme allowlists, no credentials, no
  local hostnames, and only globally reachable addresses for IP literals and
  all DNS answers. Git fetches additionally pin the vetted DNS answers and
  disable redirects, proxies, credential helpers, and alternate protocols.
  Service admission and self-fetch filtering now compare parsed host and port
  instead of substrings, so `gitnostr.com.attacker.example` no longer
  satisfies a check for `gitnostr.com`. The operator-configured bootstrap
  relay remains usable even when local; event URLs never inherit that
  exception. The new `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS` flag (default
  `false`) disables the reachability checks for tests and closed development
  networks. Known limitation: relay-connection DNS is re-validated before
  every dial but cannot be pinned through nostr-sdk's connector, leaving a
  narrow DNS-rebinding window that needs upstream connector support.

### Fixed

- Published the source revision in build metrics, NIP-11 metadata, and the
  landing page for Nix-built releases, where the filtered source archive does
  not contain Git metadata.
- Stopped routine client connection resets without a WebSocket close handshake
  from being reported as server errors, while retaining other embedded-relay
  failures at their original severity.
- Adapted historic pagination to each relay's observed page size and guarded
  NIP-11 `default_limit` hint, so omitted-limit filters continue past relays
  that return small pages without trusting unrelated maximum-limit metadata.
- Batched unresolved purgatory dependency IDs into one query per relay on the
  existing 30-second cadence, reducing subscription and rate-limit pressure
  without delaying newly available repository data.
- Prevented naughty-listed and self-referential relay targets from being
  rescheduled while unavailable or unnecessary.
- Kept NIP-77 reconciliation enabled when historic hydration leaves a small
  recoverable residual, and stopped repeatedly requesting Git object IDs that
  a remote has already advertised as missing.
- Stopped structurally malformed synced events from being downloaded and
  revalidated on every historic pass.
- Kept proactive sync within each relay connection's active-subscription
  allowance. Live subscriptions, negentropy rounds, historic and fallback
  queries, pagination verification, and purgatory dependency polling now share
  one per-session budget derived from NIP-11 with a conservative fallback.
  Live coverage is consolidated first, capacity is reserved for control work,
  and timed-out queries are closed relay-side before their slots are reused.
- Fixed historic sync silently abandoning events a relay identified but failed
  to deliver. Negentropy reconciliation finds event IDs missing locally, but a
  relay's exact-ID response can return only a subset; for batches without
  repository/root-event metadata (the Layer 1 announcements batch) no semantic
  REQ+EOSE fallback exists, and production logs showed such batches completing
  "with partial results" — dropping the missing IDs until the next daily sync
  up to 25 hours later. The still-missing IDs are now kept in a per-relay
  recovery index and refetched over the existing connection with bounded
  exponential backoff (30s doubling to 15min, one in-flight attempt per relay,
  300 IDs per fetch). Progress clears only the recovered IDs and resets the
  backoff; duplicate incomplete responses merge without duplicating work; IDs
  satisfied by live sync are cleared without consuming attempts; 12
  consecutive zero-progress attempts expire the pending IDs explicitly, and
  the relay stays observably degraded (`ConnectedHistoricSyncFailures`) until
  the daily sync. Startup remains non-blocking throughout, and a relay whose
  missing events are all recovered — with no unrelated batch failures — is now
  promoted back to `Connected` instead of reporting failures forever. Also
  fixed the retry-subscription-failure path confirming an incomplete batch as
  successful, and bounded the previously unbounded `missing_ids` log arrays to
  a five-ID sample.
- Fixed malformed client messages tearing down the whole WebSocket connection.
  A single unparseable message - in production, requests carrying invalid event
  IDs that fail with `Invalid input length 64` - closed the session, forcing
  clients to reconnect and re-subscribe. Invalid messages are now answered with
  a `NOTICE` and the connection stays open. Fixed upstream in rust-nostr and
  picked up by upgrading to the stable `0.45.0` release.
- Fixed proactive sync losing repository events when public relays cap active
  subscriptions. Compatible GRASP filters now share bounded NIP-01 REQs while
  retaining per-filter history pagination.
- Fixed repeated relay rate-limit notices extending the cooldown indefinitely.
  Notices during an active cooldown keep its original deadline, while a new
  rejection after recovery begins a fresh cooldown.
- Removed superseded same-author repository states from purgatory after their
  replacement is promoted when the locally available Git data cannot
  reconstruct them. Reconstructable rollback states and other maintainers'
  states are retained.

## [2.0.0] - 2026-07-27

### Breaking changes

- Removed `--relay-owner-nsec` because command-line secrets are exposed through
  process listings and service diagnostics. Use the `relay_owner_nsec` systemd
  credential, `NGIT_RELAY_OWNER_NSEC`, or `.relay-owner.nsec`. The NixOS
  `relayOwnerNsecFile` option remains supported and now supplies a protected
  systemd credential.
- Removed the hidden `repair-deletion-requests` command and the public
  `ngit_grasp::repair_deletion_requests` module. Deletion-request lifecycle
  reconciliation now runs automatically.
- Added four deletion-request retention fields to the public `Config` struct.
  Rust consumers that construct `Config` with a struct literal must provide
  them.

### Added

- Added configurable bounded retention for NIP-09 deletion requests and NIP-62
  request-to-vanish events, with cleanup telemetry for operators.

### Changed

- Deletion requests now move through a bounded served and gating lifecycle
  based on whether they affected accepted events. Retention catch-up runs in
  the background after the relay and synchronization workers start.
- Deletion-disrespector mode now applies to both NIP-09 deletion requests and
  NIP-62 request-to-vanish events.

### Fixed

- Fixed maintainer invitation acceptance and synchronization across owner-only,
  invitee-only, shared, and temporarily unavailable GRASP servers. Acceptance
  now converges without an invitee state event or additional Git push, handles
  an invitee repository that already exists, and withholds the invitee's state
  authority until reciprocal acceptance.
- Kept invitation recovery responsive during restarts, rate limits, large relay
  sets, and expired dependency caches by bounding actor work, retaining exact
  relay hints, and keeping connection and subscription retries scheduler-owned.
- Fixed promoted repositories remaining on state-only GRASP sync filters, which
  prevented remote issues, patches, and pull requests from being discovered
  after their Git data arrived.
- Delayed the terminal smart-HTTP receive-pack flush until matching repository
  events are promoted and queryable. Sideband clients receive progress during
  long Git processing and post-push repository alignment.
- Batched the one-time deletion-request lifecycle migration so large databases
  do not remain unavailable while historical requests are reconciled.
- Applied NIP-01's lowest-event-ID tie-break to same-second repository state
  replacements in purgatory.

### Security

- Kept relay-owner private keys out of process arguments by loading NixOS
  secret files through a protected systemd credential. Empty or invalid
  configured keys now stop startup instead of rotating identity, generated
  fallback keys use mode `0600`, and existing fallback files are restricted
  before being read.

## [1.2.0] - 2026-07-06

### Fixed

- Prevented redundant NIP-09 deletion requests from polluting relay storage and query results.

### Added

- Implemented repository lifecycle handling for removals caused by NIP-09 deletion requests, NIP-62 requests-to-vanish, repository blacklist matches, and removal from whitelist. Removed repository scopes now archive git data and move data through holding/recovery flows with a 90-day default retention period, cascade-delete related events that lose their accepted-reference path, roll back deleted state-event versions where possible, and keep served nostr state aligned with git refs. This is an enabler for moderation features.

### Changed

- Stream git smart HTTP responses instead of buffering full responses before sending them to clients, improving behavior for long-running fetch and push operations.

- Upgraded dependencies: rust-nostr to `0.45.0-alpha.3` from a patched version to enable publishing ngit-grasp to crates.io, a Rust toolchain bump via Nix flake upgrade, and other Rust dependencies.

### Fixed

- Wrapped `receive-pack` error pkt-lines in sideband framing so git clients receive push rejection messages correctly during smart HTTP pushes.

## [1.1.0] - 2026-05-22

### Added

- **GRASP-06 contributor PR submission endpoint** (`NGIT_GRASP06_ENABLE`, default off). When enabled, the relay accepts unauthenticated `git push` of `refs/nostr/<event-id>` to `/prs/<npub>/<identifier>.git` from any contributor, even for repositories this relay has no accepted announcement for. The corresponding PR (kind 1618) or PR Update (kind 1619) event is accepted into purgatory when its `clone` tag names this relay's `/prs/<signer>/<d>.git` endpoint and its `a` tag's d-tag matches the URL identifier. When the event and the push match (signer, d-tag, c-tag commit) the event is released from purgatory and the ref is mirrored into any accepted-announcement repos on this relay. Empty `/prs/` repos (probe pushes, mismatched events) are garbage-collected inline at the three runtime sites that can leave them empty (receive handler at end of push, PR-event policy when discarding a mismatched scoped placeholder, purgatory sweep when a scoped placeholder expires without a matching event) plus a one-shot startup scan that removes any zero-ref `/prs/` bare repos left behind by a previous run (crash, mid-cleanup failure, or shutdown with unresolved scoped placeholders). GRASP-06 is advertised in NIP-11 `supported_grasps` when enabled. See [how-to/enable-grasp-06.md](docs/how-to/enable-grasp-06.md) and [explanation/grasp-06-contributor-pr-submission.md](docs/explanation/grasp-06-contributor-pr-submission.md).

### Fixed

- Handle `HEAD` requests for `info/refs` endpoints (previously returned 405).

## [1.0.2] - 2026-04-10

### Fixed

- Replacement announcements (kind 30617) for a purgatory entry were being saved to the database immediately, bypassing the purgatory gate. When a second copy of the same announcement arrived (e.g. via sync from another relay) while the original was still in purgatory awaiting git data, the policy returned `Accept` instead of `AcceptPurgatory`, causing the event to be stored without the corresponding git data or state events ever arriving. The fix returns `AcceptPurgatory` for replacements of purgatory entries so the updated event is held in purgatory until git data arrives.

- Repository identifiers containing characters that require percent-encoding in URLs (e.g. spaces, emoji) are now accepted and served correctly. NIP-01 places no restriction on `d` tag values and NIP-34 only recommends kebab-case without mandating it, so rejecting non-kebab identifiers was overly strict. Identifiers are stored verbatim on disk and percent-encoded when used in URLs, per the `nostr://` clone URL spec formalised in [NIP-34 PR #2312](https://github.com/nostr-protocol/nips/pull/2312) and the GRASP-01 HTTP path spec. The landing page clone URL now also correctly percent-encodes the identifier.

- `--git-dir` is now passed as a global git option (before the subcommand) in `check_repo_empty`, fixing compatibility with git versions that require global options to precede the subcommand.

### Changed

- Remove arbitrary default max connections limit; when `NGIT_MAX_CONNECTIONS` is unset the relay imposes no connection cap, deferring to OS fd limits and infrastructure controls

- Added `cleanup-empty-repos` subcommand to remove stale events for empty git repositories

## [1.0.1] - 2026-02-27

### Fixed

- Push authorization now correctly ignores `refs/tags/<name>^{}` peeled-tag entries in state events (kind 30618). These entries are git's internal notation for the dereferenced commit behind an annotated tag and are never sent as part of a push. Previously, their presence in the state event caused `can_satisfy_state` to reject valid annotated-tag pushes because the would-be ref state after the push did not include the spurious `^{}` entry, making the exact-equality check fail.

### Changed

- Push auth rejections now send the reason to the git client via ERR pkt-line (e.g. "authorisation failed: No state events in purgatory") instead of a generic HTTP 403, so users see actionable error messages directly in their terminal

## [1.0.0] - 2026-02-26

Initial release of ngit-grasp, a GRASP relay implementation in Rust.

[unreleased]: https://gitworkshop.dev/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp/compare/v2.1.2...HEAD
[2.1.2]: https://gitworkshop.dev/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp/compare/v2.1.1...v2.1.2
[2.1.1]: https://gitworkshop.dev/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp/compare/v2.1.0...v2.1.1
[2.1.0]: https://gitworkshop.dev/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp/compare/v2.0.0...v2.1.0
[2.0.0]: https://gitworkshop.dev/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp/compare/v1.2.0...v2.0.0
[1.2.0]: https://gitworkshop.dev/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp/compare/v1.1.0...v1.2.0
[1.1.0]: https://gitworkshop.dev/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp/compare/v1.0.2...v1.1.0
[1.0.2]: https://gitworkshop.dev/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp/compare/v1.0.1...v1.0.2
[1.0.1]: https://gitworkshop.dev/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp/compare/v1.0.0...v1.0.1
[1.0.0]: https://gitworkshop.dev/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp/releases/tag/v1.0.0
