# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Upgraded the rust-nostr crates from `0.45.0-alpha.8` to the stable `0.45.0`
  release, including the upstream NEG-OPEN handling fix.

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
  an invitee repository that already exists, and preserves the one-way
  authority granted by an invitation before reciprocal acceptance.
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

[unreleased]: https://gitworkshop.dev/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp/compare/v2.0.0...HEAD
[2.0.0]: https://gitworkshop.dev/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp/compare/v1.2.0...v2.0.0
[1.2.0]: https://gitworkshop.dev/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp/compare/v1.1.0...v1.2.0
[1.1.0]: https://gitworkshop.dev/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp/compare/v1.0.2...v1.1.0
[1.0.2]: https://gitworkshop.dev/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp/compare/v1.0.1...v1.0.2
[1.0.1]: https://gitworkshop.dev/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp/compare/v1.0.0...v1.0.1
[1.0.0]: https://gitworkshop.dev/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp/releases/tag/v1.0.0
