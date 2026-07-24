# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Added four configuration options for bounded retention of NIP-09 deletion requests and NIP-62 request-to-vanish events, together with cleanup telemetry for operators.

### Fixed

- Fix maintainership invitation syncing by retrying the source maintainer announcement once reciprocal membership is known, allowing GRASP to discover and copy the existing repository.
- Purgatory promotion now applies NIP-01's lowest-event-ID tie-break for same-second repository state replacements.

### Changed

- Addressed a production storage imbalance where roughly 50k of 60k stored events were deletion requests. Deletion requests now have a bounded lifecycle, so requests that are no longer relevant are reconciled and retired while requests that may still affect valid event handling are preserved.
- Deletion-disrespector mode now explicitly applies to both NIP-09 deletion requests and NIP-62 request-to-vanish events.
- Retired the hidden `repair-deletion-requests` maintenance command.

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

[unreleased]: https://gitworkshop.dev/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp/compare/v1.2.0...HEAD
[1.2.0]: https://gitworkshop.dev/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp/compare/v1.1.0...v1.2.0
[1.1.0]: https://gitworkshop.dev/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp/compare/v1.0.2...v1.1.0
[1.0.2]: https://gitworkshop.dev/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp/compare/v1.0.1...v1.0.2
[1.0.1]: https://gitworkshop.dev/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp/compare/v1.0.0...v1.0.1
[1.0.0]: https://gitworkshop.dev/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp/releases/tag/v1.0.0
