# Repository Lifecycle (Deletion, Holding, Archive, and Recovery)

## Overview

ngit-grasp owns the lifecycle of repository-related nostr events and git data
when a served repository scope is removed, restored, or quarantined. This covers
NIP-09 deletion requests, NIP-62 request-to-vanish events, operator blacklist and
whitelist reconciliation, service de-listing, holding/archive retention, recovery,
and purgatory transitions.

## Bounded request retention

> **Status:** Lifecycle metadata, NIP-09 and NIP-62 lifecycle admission
> (including disrespector read-only would-have-deleted classification),
> deterministic admission-use attribution, measured destructive outcomes,
> startup reconciliation, periodic request cleanup/permanent expiry, removal of
> target-set deduplication, and repair-command retirement are implemented.

### Production motivation

Deletion and vanish requests are necessary admission controls, but they can also
create substantial retention pressure without hostile traffic. Valid requests
published by reputable users may be unrelated to this relay's Git data, and a
request can arrive before any event it names. The relay therefore cannot require
the target to exist without breaking legitimate out-of-order delivery.

Production measurements exposed the cost of retaining every such request
indefinitely: approximately 50,000 of 60,000 stored events were deletion
requests. In other words, the relay was receiving and storing roughly five times
more deletion requests than all other event kinds combined. Target-coverage
deduplication accounted for only about 1,500 requests, leaving approximately
48,000 requests whose retention was not addressed by target-set deduplication.
Retaining every accepted request permanently is therefore the wrong storage
policy; the relay should retain requests according to demonstrated utility
instead.

Bounded lifecycle retention is a storage-hygiene mechanism, not comprehensive
adversarial admission control. Trust-based admission, rate controls, and
operator moderation are separate concerns and can be layered over this policy.

### Intent

The relay should:

1. accept valid out-of-order requests without requiring an existing target;
2. serve a new request for an intentionally generous probation window that
   covers delayed rebroadcasting and intermittently connected clients;
3. retain an unserved request for a further window in which it can still block a
   late event;
4. retain and serve requests that demonstrably deleted or blocked data;
5. eventually expire both the request and its admission-gate effect; and
6. permanently remove expired requests and their lifecycle metadata from live
   storage.

This lifecycle applies to NIP-09 deletion requests and NIP-62 vanish requests.
For NIP-62, a request that does not target this relay is never an active local
vanish gate, but it still follows the bounded served/unserved retention schedule.
In deletion-disrespector mode, NIP-09 and NIP-62 requests likewise follow the
storage schedule. A request is classified as used when it would have removed an
existing main-database or purgatory event under normal policy, but the relay does
not perform that removal or enforce an admission gate. Used requests in this
mode remain served indefinitely; unused requests age out normally.

### Request lifecycle

Retention is based on a durable relay-observed `first_seen_at` timestamp, not the
client-controlled Nostr `created_at` timestamp.

#### New and unused

1. **Served probation — 30 days from first receipt:** store the original signed
   request in the main database and serve it normally. Thirty days is
   intentionally much longer than ordinary Nostr propagation, which is usually
   measured in hours: the additional time accommodates delayed client
   rebroadcasting and intermittently connected clients. If processing the
   request successfully removes at least one event from the main database or
   purgatory, the request is immediately considered used. Attempted or failed
   deletions do not count.
2. **Unserved pending gate — a further 180 days:** if still unused after 30 days,
   remove it from the main database but retain it in the tombstone database.
   Continue consulting locally actionable requests during admission; retained
   disrespector and non-targeting NIP-62 records do not enforce a gate.
3. **Expiry:** if it remains unused after the additional 180 days, permanently
   remove the request and its lifecycle metadata from the tombstone database.

A pending request becomes used only when it actually causes a later event to be
rejected under valid ownership, coordinate-cutoff, relay-targeting, and other
NIP-09/NIP-62 rules. Merely matching a tag, inspecting the request, or discovering
that a different author owns the target does not count as use.

The unserved gate is the deliberate observation period that establishes whether
an apparently unused request still has practical value. While the request was
served, clients that saw it could avoid sending the deleted target to this relay,
even if copies of that target continued circulating elsewhere. Removing the
request from relay queries gives those late copies an opportunity to reach the
relay again. The retained Tombstone gate still rejects a covered target; that
rejection is evidence of current utility, so the winning request becomes used,
is promoted back to Main, and begins the longer used lifecycle. If no covered
target arrives during the unserved period, the request has supplied no evidence
that its gate is still needed and can expire. Replaying the deletion or vanish
request itself is not such evidence and does not update `last_used_at`.

#### Used

When a request is used:

1. promote it back to the served main database if necessary;
2. serve it and enforce its admission gate for **9 months after its last use**;
3. after 9 months, stop serving it but continue enforcing its gate for a further
   **3 months**; and
4. after 12 months without use, expire its gate and permanently remove the
   request and its lifecycle metadata.

The normal-mode schedule above does not expire used requests in disrespector
mode: because archival relays exist to preserve deletion history, a request that
would have deleted stored data remains served there indefinitely.

Every successful use resets `last_used_at` and therefore restarts the 9-month
served plus 3-month unserved lifecycle. Unused retention is based on
`first_seen_at`; used retention is based on `last_used_at`. Expiry is intentional:
once both periods end, a previously deleted event, coordinate version, or
vanished-author event is eligible for admission again unless another live
request covers it.

The four lifecycle durations are operator-configurable, with defaults of
30 days for unused serving, a further 180 days for unused gating, 9 months for
used serving, and a further 3 months for used gating. Configuration validation
must preserve the ordering of each served period followed by its unserved gate
period. The existing holding cleanup cadence also schedules deletion-request
retention cleanup. Timestamp-derived deadlines determine lifecycle eligibility;
physical removal from Main and Tombstones is asynchronous cleanup and may occur
on the next scheduled pass. This bounded cleanup delay is intentional and does
not extend admission-gate eligibility past the deadline.

Durations use seconds for configuration consistency and to permit short automated
tests. Production values are expected to be at least one day and comfortably
longer than the worst-case processing time for a deletion or vanish request,
including repository archival and cascade work. Sub-day values are a testing
facility, not a supported production operating point; cleanup is therefore not
coordinated with an initial request handler across an artificially short total
lifetime.

### Multiple matching requests

If several pending requests would independently reject the same arriving event,
promoting all of them would turn one target arrival into retention amplification:
an attacker could publish many equivalent requests and make all of them long
lived with one later event. Exactly one deterministic sufficient request should
receive credit for the use and be promoted. The remaining matching requests keep
their existing lifecycle and expire normally.

The winner-selection rule must be deterministic across restarts and independent
of database iteration order. It must also preserve deletion correctness: for an
`a`-tag target, the selected request must have a cutoff that actually covers the
arriving event. A stable event-ID tie-break should be used after semantic
eligibility and lifecycle priority are considered.

### Multi-target requests

Nostr events are signed and cannot be rewritten into a smaller authentic event.
If any target makes a request used, retain and promote the whole signed request,
including all of its valid targets. This is why the existing maximum target-tag
limit remains an important admission bound.

### Integration with lifecycle storage

Request retention should extend the existing lifecycle stores rather than add an
independent archive hierarchy:

1. **Main database — served state:** contains a copy of each request during its
   initial 30-day probation and each normally honored used request within 9
   months of `last_used_at`. A used request on a disrespector relay remains here
   indefinitely. Presence in this database determines whether normal relay
   queries serve the original signed request.
2. **Tombstone database — unserved gate and request lifecycle:** contains the
   original signed NIP-09/NIP-62 request plus relay-generated lifecycle metadata.
   In normal mode it remains the authoritative admission-gate source. It also
   retains unused disrespector and non-targeting NIP-62 requests until their
   lifecycle expires, although those records do not enforce a local gate.
   Disrespector NIP-09 requests are read-only evaluated after persistence and
   receive `last_used_at` only when an existing main-database or purgatory
   target would be removed by normal policy.
3. **Holding database — deleted payload retention:** continues to contain events
   actually removed by NIP-09/NIP-62, with its existing deletion metadata and
   independent holding-retention clock. Expiry of a request does not shorten or
   extend holding retention, and expiry of holding data does not change a live
   request gate.
4. **Replaceable-history database — rollback state:** remains independent and
   continues to supply valid prior replaceable/addressable versions during a
   deletion rollback. Request retention must not duplicate this payload history.

No cold request database is added. This matches holding cleanup's existing model:
when retention ends, payload and internal metadata are permanently removed.

The Tombstone store should adopt the same payload-plus-internal-metadata-event
pattern already used by Holding and Replaceable History. The original request is
stored verbatim. A relay-generated metadata event, linked to the request with an
`e` tag and never exposed to clients, records at least `first_seen_at`, optional
`last_used_at`, and whether the request is locally actionable, non-targeting, or
handled in disrespector mode.

State transitions must be ordered so failures cannot silently lose a live gate:

- On receipt, persist the request and `first_seen_at` metadata in Tombstones
  before destructive work or acceptance for main-database storage.
- Mark it used only after at least one main-database or purgatory removal has
  succeeded. A partial deletion counts as use if at least one removal succeeded.
- In disrespector mode, classify it as used when a read-only normal-policy
  target lookup finds at least one existing main-database or purgatory event
  that would be removed, without deleting that event, installing a gate, or
  performing holding, archive, cascade, rollback, or repository work.
- When a later admission is blocked, durably update the deterministic winner's
  `last_used_at` and restore its main-database copy before completing the
  rejection path. If that update fails, report an internal policy error rather
  than claiming that retention was extended.
- On expiry, remove the main-database copy first, then its Tombstone payload and
  metadata. If Tombstone cleanup fails, the unserved gate remains conservative
  and the next cleanup pass retries it.

The Tombstone store should expose one canonical current metadata record per
request. A `last_used_at` update should save its replacement metadata before
deleting the older metadata record; readers choose the newest valid record during
an interrupted update. Cleanup then compacts stale metadata so frequent reuse
cannot create another unbounded stream.

### Deterministic use attribution

Admission lookup may find several sufficient requests. It should first discard
requests that do not actually authorize rejection, including wrong-author
NIP-09 requests, coordinate deletions with an insufficient cutoff, expired
requests, and NIP-62 requests not targeting this relay. From the remaining
candidates it should choose exactly one winner using this stable order:

1. prefer an already-used request over an unused request, avoiding unnecessary
   promotion of another payload;
2. prefer the earliest relay-observed `first_seen_at`; and
3. use the lowest event ID as the final tie-break.

Only the winner receives a `last_used_at` update and possible promotion to the
main database. Other sufficient requests still participate in rejection
correctness, but their retention clocks do not change. This rule is independent
of database iteration order and prevents one event arrival from extending an
arbitrary number of duplicate requests.

This deterministic single-winner rule applies when one later target admission is
matched against already-pending requests. Initial processing of distinct deletion
requests is intentionally less strict: two requests processed concurrently may
both observe the same stored target before either removal completes and may both
receive use credit. The database deletion API does not report an authoritative
per-event removed count, so eliminating that narrow race would require broader
target-level serialization. The occasional extra used request is accepted: it is
bounded by actual concurrency, does not change deletion correctness, and still
expires through the normal used lifecycle.

### Simplification of target-set deduplication

The lifecycle replaces semantic target-set deduplication and supersession as the
primary storage-control mechanism. Distinct, valid signed requests receive
independent probation windows even when their target sets overlap. Exact replay
of the same event ID remains an ordinary database duplicate and does not create a
new record or reset `first_seen_at`.

The live write path therefore does not reject a distinct request merely because
another request already covers its targets, and should not delete older requests
by trying to prove one signed request semantically subsumes another. Deterministic
single-winner attribution provides the necessary anti-amplification bound when a
target later arrives, while age-based cleanup handles requests that never become
useful. The temporary target-deduplication repair command has been retired;
startup migration and lifecycle cleanup own historical request handling.

Once an expired request has been permanently removed, replaying that identical
signed event starts a new lifecycle because no live event-ID marker remains.

### Migration and policy-mode changes

Existing request rows predate relay-observed lifecycle metadata, so their true
`first_seen_at` and `last_used_at` cannot be reconstructed reliably. Migration
assigns the migration timestamp as `first_seen_at` and gives every historical
request a fresh 30-day probation window. This deliberately favors preservation
over immediate production cleanup; normal cleanup moves requests that remain
unused out of the served main database after that window.

Startup performs this migration before blacklist/whitelist reconciliation and
before the relay starts serving traffic. It discovers signed kind-5 and kind-62
payloads from both the served and tombstone databases, including tombstone
payloads whose metadata is missing or malformed, and deduplicates by signed
event ID. Valid existing metadata is preserved; missing metadata is written
with one startup timestamp and the original payload is promoted to the served
database for its fresh probation. The pass is restart-safe: replacement
metadata preserves the earliest `first_seen_at` and greatest `last_used_at`.

The same startup pass reclassifies retained requests using current relay
configuration and reconciles served copies against the lifecycle deadline.
In disrespector mode it read-only evaluates unused targeting requests against
main and purgatory data, marking only requests that would currently have an
effect as used; it never changes target data during that evaluation. This
evaluation includes requests whose unused lifecycle elapsed while the relay was
offline: if a matching target is present, startup gives the request use credit
before cleanup runs. Used targeting requests remain served in that mode
indefinitely, while non-targeting NIP-62 and unused no-op requests retain their
ordinary bounded served schedule. Critical query, metadata, promotion, or
removal failures fail startup rather than allowing traffic to begin with an
incomplete lifecycle reconciliation.

The relay's current deletion-disrespector configuration governs retained
requests; receipt-time mode is not permanent metadata. Switching into
disrespector mode removes their local gates and keeps requests that are used or
would delete currently stored data served indefinitely. Switching back to normal
mode reapplies normal gating and the 9-month served plus 3-month unserved expiry
schedule using retained lifecycle timestamps. Startup reconciliation must apply
these transitions before the relay begins serving traffic.

Startup catch-up and periodic cleanup use the holding-cleanup cadence. They
evaluate the same timestamp-derived half-open lifecycle boundaries, remove
expired served copies from Main before Tombstones, and permanently remove
payload plus lifecycle metadata only after the additional gating period. Main
and Tombstone removal can therefore lag a deadline until the next cleanup pass;
that is expected cleanup latency, not an extension of the request's gate
eligibility. Admission first probes for matching live requests without the
lifecycle transition lock, so ordinary unrelated event writes are not serialized
behind deletion-store reads. When that probe finds a possible gate, admission
acquires the shared transition lock and repeats candidate discovery and winner
selection before promotion. This confines serialization to events that actually
match a live request while still preventing cleanup from expiring one candidate
and causing admission to overlook another live candidate during promotion.

Target-set deduplication has been removed and the temporary
`repair-deletion-requests` command has been retired. Startup migration and
periodic cleanup now handle historical requests under the same lifecycle rules.

## Core consistency invariant

ngit-grasp enforces the following invariant across admission, serving, deletion,
and recovery:

> **Served nostr state must always match git refs we can actually serve.**

This invariant is the design center for lifecycle handling and a key rationale
for purgatory. If the currently served repository state is removed and no valid
rollback state exists, the relay must stop serving that state, park the
announcement scope in purgatory, and wait for a promotable state before serving
again.

## Ownership of lifecycle behavior

ngit-grasp disables backend auto-processing and owns NIP-09/NIP-62 lifecycle
handling in relay policy code:

- main DB uses `process_nip09(false)` and `process_nip62(false)`
  (`src/nostr/builder.rs`)
- tombstones DB uses `process_nip09(false)` and `process_nip62(false)`
  (`src/nostr/lifecycle/tombstones.rs`)
- holding DB uses `process_nip09(false)` and `process_nip62(false)`
  (`src/nostr/lifecycle/holding.rs`)

This keeps lifecycle behavior auditable and prevents the storage backends from
silently applying deletion semantics outside ngit-grasp policy code.

The full cascade, holding, archive, and lifecycle flow applies consistently to
NIP-09 repository/content deletions, targeted NIP-62 request-to-vanish events,
and operator-driven blacklist/whitelist deletions. NIP-62 additionally records a
vanish tombstone: archived payloads can remain in holding for retention and
cleanup, but the tombstone continues to gate new events from that pubkey unless
an explicit tombstone-removal path is introduced.

## The Left-Pad Problem

The "left-pad problem" refers to a 2016 incident where a critical npm package was unpublished, breaking thousands of dependent projects. In the context of decentralized Git hosting, this translates to:

**Scenario:** A popular repository with many PRs, issues, and community contributions gets deleted by its owner. All dependent work (forks, patches, discussions) becomes inaccessible, potentially breaking workflows and losing community knowledge.

**Our Solution:** The `deletion-request-disrespector` configuration option allows operators to run **archival relays** that preserve deleted content, ensuring community work survives repository deletion while still respecting deletion requests on standard relays.

## Architecture

### Three-Database Design

The repository lifecycle system uses three relay databases plus archive
filesystem storage:

```
┌─────────────────────────────────────────────────────────┐
│                    Main Database                        │
│         (Live events - actively served)                 │
│    LMDB/Memory backend                                 │
└─────────────────────────────────────────────────────────┘
                         ↓ deletion request
┌─────────────────────────────────────────────────────────┐
│                 Tombstones Database                     │
│     (Kind-5 / Kind-62 requests, deletion gate state)   │
│      Derived state: deleted IDs/coords/vanished keys   │
└─────────────────────────────────────────────────────────┘
                         ↓ delete acceptance gate
┌─────────────────────────────────────────────────────────┐
│                 Holding Database                        │
│    (Archived events - recovery window)                 │
│    Same backend type as main                           │
│    Retention: configurable (default 90 days)           │
└─────────────────────────────────────────────────────────┘
                         ↓ expiry
┌─────────────────────────────────────────────────────────┐
│              Permanent Deletion                         │
│         (Events removed from holding DB)                │
└─────────────────────────────────────────────────────────┘

                    Git Data Flow
┌─────────────────────────────────────────────────────────┐
│          Git Repository (Live)                          │
│    <git_data_path>/<npub>/<identifier>.git             │
└─────────────────────────────────────────────────────────┘
                         ↓ deletion request
┌─────────────────────────────────────────────────────────┐
│           Archive Filesystem                            │
│    .archive/<npub>/<identifier>-<timestamp>.tar.gz     │
│    Metadata is stored as holding DB events/tags         │
│    Retention: configurable (default 90 days)           │
└─────────────────────────────────────────────────────────┘
                         ↓ expiry
┌─────────────────────────────────────────────────────────┐
│              Permanent Deletion                         │
│         (Archive files removed)                         │
└─────────────────────────────────────────────────────────┘
```

### Why Three Stores?

1. **Main Database:** Fast queries, clean data model (deleted = gone)
2. **Tombstones Database:** Durable deletion/vanish state for admission-time gating
3. **Holding Database:** Recovery mechanism, prevents accidental permanent deletion

Archive files on disk complement the DB layers by preserving repository git
data during the retention window.

### Holding Database Operations

**Automatic Operations:**
- **Move to holding:** NIP-09 deletions, targeted NIP-62 vanish removals,
  blacklist/whitelist deletions
- **Automatic recovery:** Re-publishing after NIP-09 deletion or
  operator-driven blacklist/whitelist restoration (within retention window).
  NIP-62 holding records are retained for safety/cleanup, but recovery of events
  authored by the vanished pubkey remains blocked by the vanish tombstone.
- **Expiry cleanup:** Daily background task removes entries older than retention period

**Manual Operations:**
- **Manual ejection:** Operator force-deletes before retention expires
  - Use case: Large repos consuming excessive storage
  - Use case: Confirmed malware requiring immediate permanent deletion
  - Mechanism: `ngit-grasp holding-eject --owner <npub|hex> --identifier <id>`
  - Logged for audit trail
- **Legacy empty-repository cleanup:**
  - Mechanism: `ngit-grasp cleanup-empty-repos`
  - Removes empty git repository directories that no longer have useful backing
    data.
  - This is intentionally narrow. A fuller maintenance cleanup command is a
    planned replacement, not part of the current deletion cascade.

### Maintenance Cleanup Command (safe vs destructive)

`ngit-grasp maintenance cleanup` is planned as the replacement for the narrow
legacy cleanup command. Its intended role is a full repository integrity sweep,
not reuse of the live NIP-09 deletion-cascade planner.

The command should analyze the full relay/git data set and compute the state the
relay should keep:

1. Start from accepted repository announcements.
2. Recursively mark repository-related events that remain valid through accepted
   references.
3. Independently retain GRASP-06 PR and PR-update events only when their backing
   git data exists and is consistent.
4. Treat unmarked repository-related events as cleanup candidates.
5. Reconcile repository git directories, 30618 state events, PR git data, and
   PR/PR-update events so served nostr state matches filesystem git data.

The command should be dry-run by default. Mutations should require explicit
`--execute`, with destructive pruning of non-empty git data and unresolved
missing-git scopes gated by separate opt-in flags and optional age thresholds.
Reports should include candidate event deletions, orphan git directories,
degraded state events, and PR/git mismatches before any destructive cleanup.

### Migration from `cleanup-empty-repos`

`cleanup-empty-repos` remains the current legacy command. It should not be
treated as a general database/git-data repair mechanism, and it should not grow
ad hoc cascade-reconciliation behavior.

The intended migration is to introduce `ngit-grasp maintenance cleanup` in a
separate change as the operator-facing replacement. That command should first
ship as a read-only analyzer, then add explicit `--execute` mutations once the
full-state sweep reports and invariants are well covered. After the replacement
is proven, `cleanup-empty-repos` can be retained as a compatibility alias or
deprecated in favor of the maintenance command.

- **Blacklist restoration policy:** optional startup auto-restore
  - Controlled by `NGIT_BLACKLIST_AUTO_RESTORE` (default `false`)
  - Restores only `holding-source=blacklist` scopes that are now unblacklisted
    and still within holding retention
  - Still-blacklisted scopes are skipped

## Lifecycle Removal Flows

### Standard Mode (Respects Deletions)

#### NIP-09 Deletion Requests

```
1. Kind 5 deletion request arrives
   ↓
2. Validate targets:
   - `e` targets found in the main DB must be authored by the deleter;
     cross-author main-DB targets reject the whole request
   - pre-emptive `e` deletes for unknown targets may be accepted; candidate
     lookup later binds the request author to the arriving event author, so a
     foreign target does not block admission or receive use credit
   - `a` coordinates are acted on only when coordinate pubkey matches deleter
   ↓
3. Record the signed request and independent lifecycle metadata in Tombstones.
   Exact event-ID replay reuses its canonical record without resetting
   `first_seen_at`; a distinct signed request is accepted even when targets
   overlap.
   ↓
4. Process targets:
   - `a` tag targeting a kind-30617 announcement coordinate:
     recursively discover the accepted-reference component affected by the
     announcement deletion
   - `e` tag targeting an active kind-30618 repository state:
     delete the targeted state and attempt rollback from replaceable history;
     if no valid active state remains, move the affected announcement scope
     through cascade/holding into purgatory
   - `e` tag targeting an active kind-30617 repository announcement:
     delete the targeted announcement and attempt rollback from replaceable
     history; this path does not run generic graph cascade when no history
     candidate exists
   - other valid `e`/`a` targets: delete the targeted event/coordinate without
     announcement graph cascade
   ↓
5. Archive git repository to .archive/<npub>/<identifier>-<timestamp>.tar.gz
   when deleting a repository announcement with live git data
   ↓
6. Move deleted events to holding database:
   - Targeted events
   - Repository announcements, when announcement deletion is involved
   - All main-DB events that lose their accepted-reference path after cascade
     reevaluation, for cascade paths
   - Deletion metadata for retention/cleanup/recovery
   ↓
7. Delete events from main database
   ↓
8. Remove the live git repository when the owner+identifier announcement scope
   is no longer served
   ↓
9. Deleted/tombstoned targets no longer serve in queries
   ↓
10. Background task (daily):
    - Check holding database for expired entries
    - Delete events older than retention period
    - Delete corresponding archive files
```

Deletion processing records a structured outcome: successful main-database
removals and successful purgatory removals are counted separately from skipped
fail-safe preservation and query/delete failures. A kind-5 request receives
`last_used_at` only after at least one actual main-DB or purgatory event removal;
archiving to Holding, git/filesystem cleanup, candidate matching, and failed
operations do not constitute use. NIP-62 uses the same rule, including its
author-wide purgatory eviction.

Deletion gate checks tombstones before kind-specific admission and rejects:
- events from vanished pubkeys,
- re-submission of deleted event IDs,
- replaceable/addressable events covered by coordinate tombstones.

#### NIP-62 Vanish Requests

```
1. Kind 62 request-to-vanish arrives
   ↓
2. Validate relay targeting with NIP-62 rules:
   - `ALL_RELAYS` requests are actioned
   - relay URL targets matching this relay are actioned (`NGIT_DOMAIN` is
     interpreted as `wss://<domain>` and `ws://<domain>` when configured without
     a scheme)
   - non-targeting requests are accepted/stored but not actioned
   ↓
3. Record vanish tombstone so future events from that pubkey are gated
   ↓
4. For every live kind-30617 announcement authored by the vanished pubkey:
   - Recursively discover the accepted-reference component
   - Archive git repository to .archive/<npub>/<identifier>-<timestamp>.tar.gz
   - Move announcement and newly orphaned dependents to holding DB with
     holding-source=nip62
   - Delete those events from the main DB
   ↓
5. Move any remaining main-DB events authored by the vanished pubkey to holding
   with holding-source=nip62, then delete them from the main DB
   ↓
6. Evict the vanished author's purgatory entries
```

The vanish tombstone is intentionally independent from holding retention. A
future re-announcement cannot bypass the vanish gate: recovery may preserve data
for operators and cleanup, but publishing new events from the vanished pubkey is
still rejected unless the relay gains an intentional tombstone-removal workflow.

#### Blacklist-Triggered Deletion

When a repository is added to `NGIT_REPOSITORY_BLACKLIST`, the same deletion flow applies:

```
1. Startup: Scan main DB for repos matching blacklist
   ↓
2. For each matching repository:
   - Recursively discover affected accepted-reference component (same cascade logic)
   - Archive git repository to .archive/<npub>/<identifier>-<timestamp>.tar.gz
   - Mark metadata as "blacklist-triggered" (not NIP-09)
   - Move events to holding database
   - Delete from main database
   ↓
3. Background task (daily):
   - Check holding database for expired entries
   - Delete events older than retention period
   - Delete corresponding archive files
```

**Key Differences from NIP-09:**
- No author validation required (operator decision)
- Triggered on startup, not by event arrival
- Metadata marks deletion as blacklist-triggered
- `deletion_request_disrespector` does NOT prevent blacklist deletion (see below)

**Current scope:** startup reconciliation only.

**Future:** When dynamic blacklist updates are supported, deletion can trigger
immediately on config change instead of waiting for restart.

### Archival Mode (Disrespector)

When `deletion_request_disrespector = true`:

```
1. Kind 5 deletion request arrives
   ↓
2. Record independent lifecycle metadata and store the signed deletion request
   event in the main database. Exact event-ID replay reuses its existing
   lifecycle record; distinct overlapping requests remain distinct.
   ↓
3. Do NOT process deletion
   ↓
4. Repository and events remain fully accessible
   ↓
Result: Archival relay preserves all content
```

**Important:** Disrespector mode affects user-initiated NIP-09 deletions and
NIP-62 vanish requests. It does NOT prevent blacklist-triggered deletions.

**Rationale:**
- NIP-09/NIP-62 deletions are user agency decisions (left-pad protection needed)
- Blacklist deletions are operator moderation decisions (spam/malware/abuse)
- Archival relays still need ability to moderate malicious content
- Different policy goals: preservation vs. safety

**Implementation Note:** Implemented. The LMDB backend's automatic NIP-09 and
NIP-62 processing is disabled (`process_nip09(false)`, `process_nip62(false)`);
ngit-grasp owns deletion handling in relay policy code. When
`deletion_request_disrespector` is set, new kind-5
requests are stored but not acted on, and kind-62 requests are stored but not
acted on. NIP-09 and NIP-62 are omitted from the NIP-11 `supported_nips` list
in this mode.

## Recovery Mechanism

The holding database enables **accidental deletion recovery** via two distinct
triggers for the same owner+identifier scope.

### Trigger A: Re-announcement recovery

```
Scenario: repository was deleted via announcement deletion, then announced again

1. Owner publishes new announcement with same identifier
   ↓
2. Before parking that announcement in purgatory, system checks holding/archive
   eligibility for same owner+identifier
   ↓
3. Check: Is entry within retention period?
   ↓
4. If YES:
   - Extract git data from archive tar.gz
   - Restore to <git_data_path>/<npub>/<identifier>.git
   - Move events from holding DB → main DB
   - Re-run acceptance policy (should now pass)
   - Delete archive records
   - Return: "Restored X events"
   ↓
5. If NO (expired):
   - Process as new repository
   - Return: "New repository created"
```

### Trigger B: Promotion recovery (deleted active state)

When deletion removes the currently served state and announcement serving is
parked in purgatory:

1. Wait for a new valid authorized state event that can be promoted.
2. Promotion out of purgatory runs recovery hook for same owner+identifier.
3. Restore archived events/git from holding/archive.
4. Resume normal serving with git/state alignment.

### Rollback history source-of-truth

Rollback for deleted active replaceable/addressable repository events uses
ngit-grasp's dedicated replaceable-history store
(`src/nostr/lifecycle/history.rs`), not backend internal replaceable compaction
behavior.

The relay archives superseded 30617/30618 versions on write and uses that
history at deletion time to pick rollback candidates for active `e`-target
deletions (announcement + state).

This architecture is covered by two integration-test layers:

- `tests/replaceable_history.rs` verifies the durable history substrate:
  superseded 30617/30618 payloads are captured, queryable by coordinate/cutoff,
  survive LMDB restart, and do not change normal serving semantics.
- `tests/nip09_state_cascade.rs` verifies deletion behavior that consumes that
  substrate: active 30618 `e` deletion restores the previous state event and
  realigns refs, active 30617 `e` deletion restores the previous announcement
  when history exists, coordinate deletion cutoff semantics do not incorrectly
  resurrect history, and no-active-state behavior follows the purgatory
  invariant below.

### Active replaceable rollback and git ref restoration

When a kind-5 deletion targets the active repository state (`30618`) by `e` tag,
ngit-grasp must either restore a valid active state or stop serving the affected
repository announcement scope:

1. Before destructive work, deletion policy builds rollback plans only for
   `e`-targeted 30617/30618 events that are still the active version for their
   coordinate.
2. The deletion request is tombstoned, then the targeted active state is moved to
   holding and removed from the main DB.
3. For a deleted active 30618, rollback looks up the latest superseded history
   record for the same `30618:<pubkey>:<identifier>` coordinate at or before the
   deleted state's `created_at` cutoff.
4. The candidate payload is loaded from replaceable history, parsed as
   repository state, and accepted only if its author is still authorized for the
   repository announcements that remain outside purgatory.
5. The candidate state event is saved back to the main DB, making it the served
   active nostr state again.
6. The identifier is then realigned: ngit-grasp reloads repository data, selects
   the newest authorized active state per announcement owner, finds a repository
   copy containing the referenced objects, and runs the normal state-processing
   path to update/delete branch and tag refs in the served bare repositories.

When a kind-5 deletion targets the active repository announcement (`30617`) by
`e` tag, ngit-grasp similarly looks for the latest superseded announcement in
replaceable history and restores it when present. This `e`-tag rollback path is
not the same as announcement-coordinate cascade deletion:

- If a history candidate exists, the previous announcement is restored to the
  main DB.
- If no history candidate exists, no cascade graph is computed from the deleted
  announcement. The targeted announcement is moved to holding and removed from
  the main DB, and the live bare repository is removed when that owner+identifier
  announcement scope is no longer served.
- Dependent event graph cascade for announcement deletion currently belongs to
  announcement-coordinate deletion (`a` tag), targeted NIP-62 vanish over
  announcements, operator-driven blacklist/whitelist deletion paths, and the
  no-active-state transition caused by deleting the only valid active 30618 state.

If another authorized maintainer still has a valid active state for the
identifier, the surviving state remains the active source for git ref alignment;
the deleted maintainer's state rollback must not disturb that maintainer's served
announcement/state.

If no valid active state remains for the affected announcement scope, the relay
must not keep serving an announcement with empty/stale git refs. Instead it must:

1. remove the served announcement scope from the main DB;
2. archive/remove the live bare repository using the same holding/archive safety
   semantics as announcement deletion;
3. park the announcement scope in purgatory, so it is not served while git/state
   alignment is unresolved;
4. wait for a new valid authorized state event and matching git data; and
5. promote/recover the scope only through the normal purgatory promotion path,
   restoring any holding/archive data needed for the same owner+identifier.

### Blacklist Recovery

When a repository is removed from the blacklist, startup behavior depends on
`NGIT_BLACKLIST_AUTO_RESTORE`:

**Disabled (default):**
- No startup restore sweep
- Repository remains in holding/archive unless recovered by another trigger

**Enabled:**
- Startup scans holding metadata with `holding-source=blacklist`
- Deduplicates owner+identifier scopes within retention
- Restores scopes that no longer match current blacklist
- Skips scopes still blacklisted

This keeps recovery opt-in and operator-controlled while removing manual restore
steps for common unblacklist workflows.

### Manual Ejection from Holding Area

Operators need ability to **force-delete** items from holding area before retention period expires:

**Use Cases:**
1. Large repositories consuming excessive storage
2. Confirmed malware/abuse that shouldn't be recoverable
3. Legal/compliance requirements for immediate permanent deletion

**Mechanism (implemented):**
- Admin CLI command: `ngit-grasp holding-eject --owner <npub|hex> --identifier <id>`
- Immediately delete from holding DB and archive filesystem
- Emits command output with deletion counts
- Metric: `ngit_manual_ejections_total`

**Current CLI limitations:**
- Manual ejection is permanent (no undo)
- It intentionally has no confirmation prompt, reason field, or operator field in
  the current CLI; richer operator UX is planned separately.

## Operator Curation Integration

### Overview

Blacklist- and whitelist-triggered removals use the **same infrastructure** as
NIP-09 deletion requests and NIP-62 vanish lifecycle removals:
- Same holding database for 90-day retention
- Same git archive mechanism
- Same cascade deletion logic
- Same recovery capabilities (if unblacklisted)

### Key Differences from NIP-09

| Aspect | NIP-09 Deletion | Blacklist Deletion |
|--------|----------------|-------------------|
| **Trigger** | Kind 5 event arrives | Startup scan of main DB |
| **Author validation** | Required (pubkey match) | Not applicable (operator decision) |
| **Disrespector mode** | Prevents deletion | Does NOT prevent deletion |
| **Purpose** | User agency | Moderation/safety |
| **Recovery** | Automatic (re-publish) | Startup auto-restore (optional) |
| **Metadata** | Links to Kind 5 event | Marks "blacklist-triggered" |

### Why Disrespector Doesn't Prevent Blacklist Deletion

**Design Decision:** The `deletion_request_disrespector` configuration ONLY
affects NIP-09/NIP-62 user-initiated deletions. It does NOT prevent
blacklist-triggered deletions.

**Rationale:**
1. **Different Policy Goals:**
   - NIP-09/NIP-62 = User agency (prevent left-pad)
   - Blacklist = Operator safety (prevent spam/malware/abuse)

2. **Archival Relays Need Moderation:**
   - Archive mode preserves valuable deleted content
   - But still must handle malicious content
   - Spam, malware, abuse require operator intervention

3. **Separate Concerns:**
   - Disrespector = "Don't honor user deletion requests"
   - Blacklist = "Don't accept these specific repos regardless of source"

### Detection and Timing

**Current Behavior (Startup Scan):**
```
1. Relay starts up
2. Load blacklist configuration
3. Scan main database for matching repos
4. For each match: archive → holding DB → delete from main
5. Continue normal operation
```

In the same startup parity pass, repository whitelist mismatches are also
reconciled (for announcements that list this relay service but no longer match
`repository_whitelist`).

When `NGIT_BLACKLIST_AUTO_RESTORE=true`, startup also runs a blacklist restore
pass between blacklist parity delete and whitelist parity delete.

Startup also runs a whitelist restore pass after whitelist parity delete. This
restores holding scopes tagged `holding-source=whitelist` when they now match
`repository_whitelist` (while still respecting blacklist precedence).

**Future Enhancement (Dynamic Updates):**
- Watch for configuration file changes
- Trigger deletion/restore immediately on blacklist addition/removal
- Requires careful design to avoid race conditions

## Cascade Deletion Strategy

When a repository announcement is deleted through a cascade-capable path
(NIP-09 `a`-coordinate deletion of a kind-30617 announcement, targeted NIP-62
vanish over the author's announcements, blacklist deletion, or whitelist
reconciliation), ngit-grasp cascade-deletes the main-DB events that lose their
accepted-reference path after that announcement is removed.

NIP-09 `e`-tag deletion has two important replaceable cases:

- Deleting the only valid active kind-30618 repository state can make the served
  announcement scope invalid. In that no-active-state case, ngit-grasp runs the
  announcement cascade, archives/removes live git data, and parks the scope in
  purgatory until a new valid state and git data arrive.
- Deleting a kind-30617 announcement by event id is narrower: it deletes the
  targeted announcement event and may restore a previous announcement from
  replaceable history, but it does not compute the generic announcement cascade
  when no history candidate exists.

### Basic Rules

Cascade deletion is graph analysis over the same reference shapes used for event
admission. It is not limited to a fixed list of repository event kinds.

1. **Start at the deleted announcement.** The seed is the deleted kind-30617
   announcement event id plus its address coordinate.
2. **Recursively load the affected main-DB graph.** From each discovered event,
   load events it references and events that reference it.
3. **Analyze the loaded graph after removing the announcement.** Events that
   still have a surviving accepted-repository path are retained. Events that only
   depended on the deleted announcement are moved to holding and removed from the
   main database.
4. **Do not promote unrelated graph regions into the cascade.** Another accepted
   repository announcement can anchor events already found in the affected graph,
   but a reference to that announcement is a boundary, not permission to retain
   or delete that repository's entire descendant graph.

The reference forms are:

```
`a` / `A` — address references
`e` / `E` — event-id references
`q`       — event-id or address references
```

The graph is built from the main database only. Holding, history, archive, and
internal metadata stores are not graph inputs.

### Retention Rule

After graph loading, the deleted announcement is excluded and retention is
computed as a fixed point:

1. Keep surviving independent anchors.
2. Keep events that reference kept events or kept addresses.
3. Keep events that are referenced by kept events.
4. Repeat until no additional events are kept.
5. Move every remaining non-special node in the component to holding and delete
   it from the main database.

Surviving anchors include remaining repository announcements, kind-10317 GRASP
lists, and independently valid GRASP-06 `/prs/` endpoint events. The deleted
announcement itself is never a surviving anchor.

This means a deleted repository's issue, comment, or arbitrary related event can
survive when it is still connected to another accepted repository/reference path.
The same event is deleted when the removed announcement was its only acceptance
path.

### Boundaries and Special Cases

Repository state events (`30618`) are not handled by the generic graph. They are
keyed by repository identifier, so ngit-grasp preserves the existing identifier
semantics:

- state survives while any repository announcement for the identifier remains;
- state is moved to holding when the last announcement for that identifier is
  removed.

Deletion requests, vanish requests, holding metadata, and history metadata do not
act as recursive graph frontiers. They are lifecycle/control records, not normal
repository content anchors.

PR and PR-update events have an additional invariant: served PR data must not
outlive the git data needed to broadcast it. Generic graph reachability may keep
them only when they still reference a kept repository announcement, or when they
are independently valid through the GRASP-06 `/prs/` flow. Otherwise they are
removed from the retained set and retention is recalculated.

GRASP-06 PRs are treated as their own anchored flow. They can survive repository
announcement deletion when the `/prs/` endpoint relationship still makes the PR
data independently valid.

If recursive graph expansion fails or exceeds internal safety caps, ngit-grasp
does not cascade-delete from a known-partial graph. It falls back to deleting the
requested announcement coordinate and then applies the normal identifier-level
state cleanup.

## Multi-Maintainer Scenarios

### Challenge

Multiple maintainers can have announcements for the same `identifier`:
- `npub1alice.../my-repo` 
- `npub1bob.../my-repo`

Git data is synced between their repositories. When ONE maintainer deletes, what happens?

### Solution: Graph Retention

```
When npub1alice deletes her announcement:

1. Archive HER git directory:
   .archive/npub1alice.../my-repo-<timestamp>.tar.gz

2. Recursively load the affected main-DB reference graph

3. Analyze the graph after removing alice's announcement:
   - WITHOUT alice's announcement
   - WITH bob's announcement still present
   
4. Retain events still anchored by bob's announcement:
   Event A kept because:
     - References bob's announcement ✓
   Event B kept because:
     - References Event A ✓
   Event C orphaned because:
     - Only referenced alice's announcement ✗

5. Delete orphaned events, keep retained events

6. Handle circular dependencies naturally:
   - Event X kept because references Event Y
   - Event Y kept because references Event X
   - Neither has external anchor → both deleted
```

### Graph Algorithm Details

**Recursive expansion:**
1. Seed from the deleted announcement event id and address.
2. Follow outgoing accepted-reference tags (`a`, `A`, `e`, `E`, and `q`).
3. Query incoming references using the same tag forms.
4. Treat other repository announcements as boundaries for unrelated graph
   expansion.
5. Deduplicate by event id/address and continue until no new main-DB nodes are
   discovered.

**Retention fixed point:**
1. Start from surviving independent anchors.
2. Propagate retention in both directions across accepted-reference edges.
3. Apply PR/PR-update git-data vetoes.
4. Delete the loaded nodes that remain unretained.

**Safety caps:**
- Internal node, edge, and orphan-delete caps bound worst-case graph work.
- Cap/query failures fall back to coordinate-only announcement deletion plus
  state cleanup rather than broad deletion from a partial graph.
- These limits are code-level safeguards, not user/operator configuration.

**Complexity:**
- Deletion events are rare (not performance critical)
- The graph is computed on demand from indexed main-DB reference queries
- No full relay dump, pre-computation, or cache is required at current scale

## Configuration

### deletion_request_disrespector

**Type:** `bool`  
**Default:** `false` (respects deletion requests)  
**CLI:** `--deletion-request-disrespector`  
**Env:** `NGIT_DELETION_REQUEST_DISRESPECTOR`

**Description:**
When `true`, relay ignores **NIP-09 deletion requests and NIP-62 vanish
requests** and acts as an archival server. Critical for preventing left-pad
scenarios by ensuring at least some relays preserve deleted content.

**IMPORTANT:** This setting does NOT prevent blacklist-triggered deletions. Blacklist is for operator moderation (spam/malware/abuse), which archival relays still need.

**Use Cases:**
- Community archival relays
- Research/historical preservation
- Backup/mirror relays
- GRASP-05 archive mode deployments

### holding_retention_secs

**Type:** `u64`
**Default:** `7776000` (90 days in seconds)
**CLI:** `--holding-retention-secs`
**Env:** `NGIT_HOLDING_RETENTION_SECS`

**Description:**
How long to retain archived events and git data before permanent deletion. Provides recovery window for accidental deletions.

**Recommended Values:**
- Development/Testing: `5` seconds (fast test cycles)
- Staging: `300` seconds (5 minutes)
- Production: `7776000` seconds (90 days, default)
- Archival Relay: `31536000` seconds (1 year) or higher

**Notes:**
- Configurable in seconds for testing flexibility
- Background cleanup task runs on `NGIT_HOLDING_CLEANUP_INTERVAL_SECS`
  (default daily)
- Check occurs on startup to handle offline periods
- **Testing Challenge:** Daily cleanup doesn't work well with 3-5 second retention for tests - alternative timing strategy needed

## NIP-11 Advertisement

Deletion support is **conditionally advertised** in NIP-11 relay information
(implemented in [`src/http/nip11.rs`](../../src/http/nip11.rs)):

- **When `deletion_request_disrespector = false`:** include `9` (`"deletion"`) and `62` (`"request to vanish"`) in the supported NIPs array
- **When `deletion_request_disrespector = true`:** do NOT include `9` or `62` (archival mode stores but does not honor deletion or vanish requests)

This allows clients to discover whether a relay respects deletion requests.

## Security Considerations

### Validation

1. **Author Matching:**
   - For `e` targets, deletion request author MUST match deleted event author
   - For `a` targets, only coordinates with matching author are acted on
   - This prevents malicious actors from deleting other people's repositories
   - Enforced before destructive deletion processing
2. **Signature Verification:** Handled by nostr-relay-builder (already implemented)
3. **Timestamp Check:** For addressable events, delete versions up to deletion `created_at`

### Attack Vectors

**Deletion-Request Storage Pressure:**
- Mitigation: bounded probation and unserved gating periods
- Mitigation: longer retention only after demonstrated local utility
- Mitigation: permanent expiry of unused request payloads and lifecycle metadata
- Mitigation: ownership checks, normal admission validation, and operator moderation

**Archive Disk Exhaustion:**
- Mitigation: Background cleanup enforces retention limits
- Mitigation: Compressed tar.gz archives
- Mitigation: Configurable retention period
- Mitigation: Manual ejection mechanism for emergency storage relief

**Recovery Abuse:**
- Mitigation: Recovery only within retention window
- Mitigation: Must be original owner (pubkey match)
- Mitigation: Normal announcement validation applies

**Blacklist Bypass:**
- Mitigation: Blacklist checked on startup (retroactive deletion)
- Mitigation: Blacklist checked during announcement validation (prevents new)
- Mitigation: Blacklist deletion not affected by disrespector mode
- Note: Manual ejection available for confirmed abuse

## Monitoring & Metrics

**Prometheus Metrics (Currently Exposed):**
- `ngit_blacklist_deletions_total{phase,result}`
- `ngit_blacklist_startup_restore_total{result,reason}`
- `ngit_holding_cleanup_runs_total`
- `ngit_holding_cleanup_deleted_total{type}`
- `ngit_holding_cleanup_last_run_deleted{type}`
- `ngit_deletion_request_cleanup_runs_total`
- `ngit_deletion_request_cleanup_removed_total{type}`
- `ngit_deletion_request_cleanup_outcomes_total{outcome}`
- `ngit_recovery_total{result}`
- `ngit_manual_ejections_total`
- `ngit_manual_ejection_deleted_total{type}`

## Related Documentation

- **NIP-09 Specification:** `/persistent/dcdev/clones/nips/09.md`
- **Architecture Overview:** `docs/explanation/architecture.md`
- **Configuration Reference:** `docs/reference/configuration.md`
- **Roadmap:** `README.md`

## Future Enhancements

Remaining enhancements (updated after subsequent deletion/archival and GRASP-05
work):

### Archive-mode policy extensions
- **Selective disrespect:** policy-based disrespect for specific criteria (e.g. popularity, community contribution, identifier allowlist).

### Blacklist lifecycle improvements
- **Dynamic blacklist updates:** apply blacklist additions/removals without restart.
- **Dedicated restore CLI:** explicit operator restore commands with clear scope selection and outcomes.

### Operator controls and UX
- **Holding-area management UI:** optional web/admin UX for archive and holding lifecycle operations.

### Repository maintenance cleanup replacement
- Replace the narrow legacy cleanup command with `ngit-grasp maintenance cleanup`
  as a deliberate full-state integrity sweep rather than a deletion-cascade
  helper.
- Functional intent: inspect the full relay/git data set, mark events rooted in
  accepted repository announcements, recursively retain valid dependent events,
  and independently retain GRASP-06 PR/PR-update events only when their backing
  git data is present and consistent.
- Sweep unmarked repository-related events, then reconcile repository git dirs,
  state events, PR git data, and PR/PR-update events so served nostr state and
  filesystem git data match.
- Keep the command dry-run by default, require explicit `--execute` for mutation,
  and report candidate deletions, degraded states, orphan git dirs, and PR/git
  mismatches before destructive cleanup.

### Delayed archival strategy (active repositories)
- Add optional grace/delay workflow for high-activity repositories before archival execution.
- Support cancellation windows, notification issue creation, and schedulable delayed archival operations.
- Expose policy knobs (notification delay, archive delay, activity/creator thresholds).

### Monitoring and integration follow-up
- Expand deletion/archival/recovery metrics and provide dashboard + alerting guidance.

## Conclusion

The deletion request system balances three competing needs:

1. **User Agency:** Owners can delete their repositories
2. **Community Protection:** Archival relays prevent left-pad scenarios  
3. **Recovery Grace Period:** Holding database prevents accidental permanent deletion

By making deletion behavior **configurable** rather than mandatory, we enable a heterogeneous relay network where some relays respect deletions (user privacy) while others preserve content (community resilience).
