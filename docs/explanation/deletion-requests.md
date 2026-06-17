# Deletion requests architecture (NIP-09 / NIP-62)

This document describes the deletion system as currently implemented in ngit-grasp.

## Ownership and core components

- ngit-grasp owns NIP-09 and NIP-62 processing in policy code; backend auto-processing is disabled (`process_nip09(false)`, `process_nip62(false)`) for main DB, tombstones DB, and holding DB (`src/nostr/builder.rs:1030`, `src/nostr/tombstones.rs:86`, `src/nostr/holding.rs:120`).
- Deletion/vanish requests are persisted in a dedicated tombstones store and interpreted by query (event-id deletes, coordinate deletes with created_at semantics, vanished pubkeys) (`src/nostr/tombstones.rs:1`).
- A deletion gate runs before kind-specific handling and rejects:
  - events from vanished pubkeys,
  - re-submissions of deleted event ids,
  - replaceable/addressable events whose coordinate tombstone covers the event timestamp
  (`src/nostr/builder.rs:757`).

## Runtime deletion flows

### 1) NIP-09 flow

When a kind-5 deletion request is processed (`src/nostr/policy/deletion.rs:84`):

- `e`-tag ownership is validated first; cross-author deletes are rejected (`src/nostr/policy/deletion.rs:118`).
- Purgatory targets are evicted (including bare-repo removal for purgatory announcements) (`src/nostr/policy/deletion.rs:831`, `src/nostr/policy/deletion.rs:1029`).
- Main-DB targets are moved into holding before deletion (`src/nostr/policy/deletion.rs:640`, `src/nostr/holding.rs:144`).
- A tombstone record is written so future submissions are gated (`src/nostr/policy/deletion.rs:150`).

### 2) Disrespector mode

With `deletion_request_disrespector=true`, NIP-09 handling short-circuits:

- kind-5 event is accepted/stored,
- no purgatory eviction,
- no main-DB deletion,
- no tombstone write
  (`src/nostr/policy/deletion.rs:101`).

This switch affects NIP-09 processing only. Startup blacklist deletion remains active (`src/nostr/policy/deletion.rs:445`).

NIP-11 advertisement omits NIP-09 and NIP-62 when disrespector is enabled (`src/http/nip11.rs:115`).

### 3) Startup blacklist parity path

On relay start, stored announcements are scanned against blacklist config. Matches run through the same cascade + holding + archive deletion pipeline, marked with `DeletionSource::Blacklist` (`src/nostr/builder.rs:123`, `src/nostr/policy/deletion.rs:442`).

### 4) NIP-62 vanish flow

For kind-62 requests targeting this relay (or `ALL_RELAYS`), ngit-grasp:

- records the vanish tombstone,
- hard-deletes all events authored by the vanished pubkey,
- evicts that author's purgatory entries
  (`src/nostr/builder.rs:847`).

Non-targeting kind-62 requests are accepted/stored without action (`src/nostr/builder.rs:862`).

## Cascade behavior

Announcement-coordinate deletion (`30617:<owner>:<identifier>`) uses graph-based cascade (`src/nostr/policy/deletion.rs:243`):

- Candidate set includes all announcements plus dependent kinds in `GRAPH_DEPENDENT_KINDS` (1111, 1617, 1618, 1619, 1621, 1630, 1631, 1632, 1633) (`src/nostr/policy/deletion.rs:61`).
- Re-evaluation keeps events still anchored by surviving maintainers.
- Orphans are archived-to-holding then removed from main DB.
- Circular dependency components without a surviving anchor are deleted.

Multi-maintainer behavior: deleting one maintainer’s announcement does not delete events that remain reachable from other maintainers’ surviving announcements (`src/nostr/policy/deletion.rs:334`).

Kind 30618 is handled separately: once no announcement remains for an identifier, repo-state events for that identifier are deleted (`src/nostr/policy/deletion.rs:478`).

## Holding DB lifecycle

- Store: dedicated DB at `<relay_data_path>/holding` for LMDB (or in-memory backend) (`src/nostr/holding.rs:19`).
- Deletion move: events are copied into holding with metadata (`holding-source`, `holding-deleted-at`, optional coordinate/identifier/owner/archive tags) before main deletion (`src/nostr/holding.rs:154`).
- Retention: current default window is 90 days (`DEFAULT_RETENTION`) (`src/nostr/holding.rs:29`).
- Cleanup behavior:
  - startup catch-up pass (`src/main.rs:381`),
  - periodic cleanup pass at 24h interval (`src/main.rs:409`, `src/nostr/holding.rs:32`),
  - idempotent deletion of expired metadata/payload/archive records, tolerant of missing files/rows (`src/nostr/holding.rs:513`, `src/nostr/holding.rs:589`).

## Git archive lifecycle

- On announcement deletions, git repo data is archived to `.archive/<owner>/<identifier>-<timestamp>.tar.gz` and linked from holding metadata (`src/nostr/policy/deletion.rs:722`, `src/nostr/holding.rs:24`).
- Cleanup removes archive files when holding records expire (`src/nostr/holding.rs:525`).
- Fail-safe semantics:
  - if a live repo exists but archive creation fails, announcement deletion is skipped,
  - this applies in coordinate and cascade paths
    (`src/nostr/policy/deletion.rs:618`, `src/nostr/policy/deletion.rs:676`).

## Recovery workflow

Recovery is triggered by accepted re-announcement of the same owner+identifier (`src/nostr/builder.rs:297`, `src/nostr/builder.rs:1319`).

Eligibility (`src/nostr/holding.rs:315`):

- same owner+identifier scope,
- metadata has parseable `holding-deleted-at`,
- still within retention window.

Behavior (`src/nostr/builder.rs:1336`):

- restore archive to git repo when archive path is valid and readable,
- restore archived holding events into main DB,
- clean recovered holding records,
- remove consumed archive file after full record cleanup.

Partial-state handling and idempotency:

- missing/invalid archive path => continue events-only recovery,
- missing payload referenced by metadata => clean metadata and continue,
- archive extraction/open failure => abort recovery attempt and keep state for retry,
- already-restored events are not duplicated (existence check before save),
- cleanup operations are idempotent (`src/nostr/builder.rs:1268`, `src/nostr/holding.rs:403`).

Tombstones are not removed by recovery, so deletion gate semantics for prior deleted versions remain in effect.

## Manual ejection and operator behavior

- Command: `ngit-grasp holding-eject --owner <npub|hex> --identifier <id>` (`src/main.rs:40`, `src/main.rs:100`).
- Action: permanently removes matching holding metadata/payload rows and linked archive files; operation is idempotent (`src/nostr/holding.rs:638`).
- Current operator model:
  - explicit manual ejection is available,
  - startup blacklist parity is active,
  - dynamic blacklist reconciliation is not implemented (startup scan only),
  - no dedicated operator restore CLI path is implemented today.

## Metrics currently exposed

- `ngit_blacklist_deletions_total`
- `ngit_holding_cleanup_runs_total`
- `ngit_holding_cleanup_deleted_total`
- `ngit_holding_cleanup_last_run_deleted`
- `ngit_recovery_total`
- `ngit_manual_ejections_total`
- `ngit_manual_ejection_deleted_total`

Defined in `src/metrics/mod.rs:35`.

## Future work / open ideas

- Dynamic blacklist updates beyond startup-only reconciliation.
- Expanded operator restore controls and UX.
- Concurrency/race/scale hardening for large deletion/recovery workloads.
- Optional policy ideas (not committed): delayed archival/ejection controls for high-activity repositories.
