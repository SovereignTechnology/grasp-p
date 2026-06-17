# Deletion request architecture (NIP-09 / NIP-62)

This document explains how deletion works in ngit-grasp today.

It is intentionally architecture-focused: what the relay does at runtime, why it
does it that way, and where operators have control.

## Why this design exists

Deletion in a git relay has competing goals:

1. **User agency:** repository owners can request deletion (NIP-09).
2. **Network resilience:** relays may choose archival behavior to avoid “left-pad”
   style loss of shared work.
3. **Operational safety:** operators can still enforce moderation and retention.

ngit-grasp addresses this by making deletion policy explicit in relay code (not
delegated to hidden backend behavior), while preserving deterministic lifecycle
rules for deleted data.

## Ownership of deletion behavior

ngit-grasp disables backend auto-processing and owns NIP-09/NIP-62 policy in
its write path:

- main DB: `process_nip09(false)`, `process_nip62(false)`
  (`src/nostr/builder.rs:1071`)
- tombstones DB: `process_nip09(false)`, `process_nip62(false)`
  (`src/nostr/tombstones.rs:86`)
- holding DB: `process_nip09(false)`, `process_nip62(false)`
  (`src/nostr/holding.rs:120`)

This keeps behavior auditable and lets ngit-grasp implement cascade, holding,
archive, and recovery consistently.

## Core architecture

Deletion uses three persistence layers plus a write-time gate:

- **Main DB:** live query-serving events.
- **Tombstones DB:** persisted kind-5/kind-62 request records used to derive
  deleted/vanished state (`src/nostr/tombstones.rs:1`).
- **Holding DB:** deleted payload + metadata retained for cleanup/recovery
  (`src/nostr/holding.rs:19`).
- **Deletion gate:** enforced before kind-specific admission to reject:
  - events from vanished pubkeys,
  - re-submission of deleted ids,
  - replaceable/addressable events covered by coordinate tombstones
    (`src/nostr/builder.rs:757`).

## Runtime flows

### 1) Standard NIP-09 deletion flow

When a kind-5 event is processed (`src/nostr/policy/deletion.rs:84`):

1. Validate ownership for `e` targets; cross-author deletes are rejected
   (`src/nostr/policy/deletion.rs:118`).
2. Evict matching purgatory entries (including purgatory bare-repo cleanup)
   (`src/nostr/policy/deletion.rs:831`, `src/nostr/policy/deletion.rs:1029`).
3. Move targeted main-DB events into holding with metadata, then delete from main
   (`src/nostr/policy/deletion.rs:640`, `src/nostr/holding.rs:144`).
4. Record deletion tombstone so future submissions are gated
   (`src/nostr/policy/deletion.rs:150`).

The deletion request event itself is accepted/stored if valid.

### 2) Disrespector mode (archival NIP-09 behavior)

With `deletion_request_disrespector=true`, NIP-09 processing short-circuits
(`src/nostr/policy/deletion.rs:101`):

- kind-5 request is accepted/stored,
- but no purgatory eviction, no main DB delete, no holding move, no tombstone.

Result: repository content remains served.

This switch is NIP-09-specific; blacklist parity deletion still runs
(`src/nostr/policy/deletion.rs:445`).

NIP-11 currently omits 9 and 62 in this mode (`src/http/nip11.rs:115`).

### 3) Startup blacklist parity flow

On startup, ngit-grasp scans stored announcements against blacklist config and
deletes matches through the same cascade + holding + archive path, marking
metadata source as `blacklist` (`src/nostr/builder.rs:123`,
`src/nostr/policy/deletion.rs:442`).

This gives parity for already-stored repos that became blacklisted while the
relay was offline.

### 4) NIP-62 vanish flow

For kind-62 requests targeting this relay (or `ALL_RELAYS`), ngit-grasp:

- records vanish tombstone,
- hard-deletes all events by the author,
- evicts that author’s purgatory entries
  (`src/nostr/builder.rs:847`).

Non-targeting kind-62 requests are accepted/stored without local action
(`src/nostr/builder.rs:862`).

## Cascade deletion behavior

Deleting an announcement coordinate (`30617:<owner>:<identifier>`) triggers a
graph-based cascade (`src/nostr/policy/deletion.rs:243`).

Candidate set and traversal:

- candidates include all announcements + dependent graph kinds in
  `GRAPH_DEPENDENT_KINDS` (1111, 1617, 1618, 1619, 1621, 1630, 1631, 1632,
  1633) (`src/nostr/policy/deletion.rs:61`),
- references are evaluated through `a` / `e` / `q` relationships,
- orphaned events are moved to holding then deleted from main.

### Multi-maintainer semantics

If multiple maintainers announce the same identifier, deleting one maintainer’s
announcement does **not** delete events still anchored by surviving
maintainer announcements (`src/nostr/policy/deletion.rs:334`).

Circular components without a surviving anchor are deleted.

### Kind 30618 handling

Kind 30618 (repo state) is keyed by identifier, not by graph edges. After
announcement deletion, repo-state events are deleted only when no announcement
for that identifier remains (`src/nostr/policy/deletion.rs:478`).

## Holding DB lifecycle

Holding DB stores archived payload + metadata events:

- metadata includes source, deleted-at timestamp, and optional
  coordinate/identifier/owner/archive tags (`src/nostr/holding.rs:154`),
- default retention window is 90 days (`DEFAULT_RETENTION`)
  (`src/nostr/holding.rs:29`).

Cleanup lifecycle:

- **Startup catch-up pass:** one cleanup run when relay starts (`src/main.rs:381`).
- **Periodic cleanup:** recurring pass at `DEFAULT_CLEANUP_INTERVAL` (24h)
  (`src/main.rs:409`, `src/nostr/holding.rs:32`).
- **Expiration behavior:** deletes expired metadata, payloads, and linked archive
  files with idempotent, best-effort semantics for partial/missing state
  (`src/nostr/holding.rs:513`, `src/nostr/holding.rs:589`).

## Git archive lifecycle

On announcement deletion, ngit-grasp attempts to archive git data to:

`<git_data_path>/.archive/<owner>/<identifier>-<timestamp>.tar.gz`

(`src/nostr/policy/deletion.rs:722`).

Archive path/created-at are linked into holding metadata
(`src/nostr/holding.rs:24`).

### Fail-safe semantics

When live repo data exists but archive creation fails, destructive announcement
deletion is skipped (both coordinate and cascade paths) so data is not dropped
without a recoverable artifact (`src/nostr/policy/deletion.rs:618`,
`src/nostr/policy/deletion.rs:676`).

Archive files are removed during holding expiry cleanup (`src/nostr/holding.rs:525`).

## Recovery workflow

Recovery is triggered by accepted re-announcement for the same
`owner+identifier` scope (`src/nostr/builder.rs:297`, `src/nostr/builder.rs:1319`).

Eligibility (`src/nostr/holding.rs:315`):

- scope match (owner + identifier),
- parseable `holding-deleted-at`,
- still within retention window.

Recovery behavior (`src/nostr/builder.rs:1336`):

- restore git archive when path is valid and archive is readable,
- restore holding payload events into main DB,
- clean recovery records from holding,
- delete consumed archive file after full cleanup.

### Partial-state and idempotency rules

- Missing/invalid archive path: continue with events-only recovery.
- Missing payload referenced by metadata: clean metadata and continue.
- Archive open/extract failure: abort recovery attempt; preserve state for retry.
- Already-restored events are not duplicated (existence checked before save).
- Recovery-record delete is idempotent (`src/nostr/holding.rs:403`).

Tombstones are not removed by recovery; prior deletion gate semantics remain in
force for older versions.

## Manual ejection and operator behavior

Operators can permanently remove holding/archive artifacts for a repo scope:

```bash
ngit-grasp holding-eject --owner <npub|hex> --identifier <id>
```

(`src/main.rs:40`, `src/main.rs:100`).

Behavior:

- deletes matching holding metadata and payload rows,
- deletes linked archive files,
- idempotent for missing rows/files,
- records ejection metrics (`src/nostr/holding.rs:638`).

Current operator model:

- startup blacklist parity is implemented,
- manual ejection is implemented,
- dynamic blacklist reconciliation is not implemented (startup-only parity),
- no dedicated restore CLI exists today.

## Metrics currently exposed

Defined in `src/metrics/mod.rs:35`:

- `ngit_blacklist_deletions_total{phase,result}`
- `ngit_holding_cleanup_runs_total`
- `ngit_holding_cleanup_deleted_total{type}`
- `ngit_holding_cleanup_last_run_deleted{type}`
- `ngit_recovery_total{result}`
- `ngit_manual_ejections_total`
- `ngit_manual_ejection_deleted_total{type}`

## Why this approach works

In practice, this architecture gives ngit-grasp predictable behavior across
deletion, archival, and recovery:

- **Deterministic policy:** deletion logic is in ngit-grasp policy code, not
  backend internals.
- **Durable enforcement:** tombstones persist and feed admission-time gating.
- **Safer deletion:** move-to-holding + git archiving provide a controlled
  retention window.
- **Recoverability:** re-announcement-driven recovery can restore data while
  tolerating partial state.
- **Operator control:** blacklist parity and manual ejection support moderation
  and storage pressure workflows.

## Future work / open ideas

- Dynamic blacklist updates beyond startup-only reconciliation.
- Expanded operator restore controls and UX.
- Concurrency/race/scale hardening for large deletion and recovery workloads.
- Optional policy ideas (not commitments): delayed archival/ejection controls
  for high-activity repositories.
