# Repository Lifecycle (Deletion, Holding, Archive, and Recovery)

## Overview

ngit-grasp owns the lifecycle of repository-related nostr events and git data
when a served repository scope is removed, restored, or quarantined. This covers
NIP-09 deletion requests, NIP-62 request-to-vanish events, operator blacklist and
whitelist reconciliation, service de-listing, holding/archive retention, recovery,
and purgatory transitions.

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
2. Check idempotency:
   - if every actionable `e`/`a` target is already covered by an existing
     same-author kind-5 request, return a duplicate success response without
     storing the new deletion event
   - `e` targets are covered by any existing same-author deletion for that id
   - `a` targets are covered only when an existing same-author deletion for the
     same coordinate has `created_at >=` the new deletion request, preserving
     NIP-09 coordinate cutoff semantics
   ↓
3. Validate targets:
   - `e` targets found in the main DB must be authored by the deleter;
     cross-author main-DB targets reject the whole request
   - pre-emptive `e` deletes for unknown targets may be accepted, but if the
     target later arrives from a different author, the stale deletion request is
     removed from both tombstones and the served deletion-request stream
   - `a` coordinates are acted on only when coordinate pubkey matches deleter
   ↓
4. Record deletion tombstone so re-submission is gated
   ↓
5. Compact superseded deletion requests:
   - after the new tombstone is recorded, remove older same-author kind-5
     requests from the tombstone DB and served main DB when every actionable
     target in the older request is covered by the new request
   - a newer `a`-tag cutoff supersedes an older cutoff for the same coordinate;
     `e` targets must still be present in the new request
   - removal uses the database delete path so event-id/kind/tag indexes stay in
     sync with event storage
   ↓
6. Process targets:
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
7. Archive git repository to .archive/<npub>/<identifier>-<timestamp>.tar.gz
   when deleting a repository announcement with live git data
   ↓
8. Move deleted events to holding database:
   - Targeted events
   - Repository announcements, when announcement deletion is involved
   - All main-DB events that lose their accepted-reference path after cascade
     reevaluation, for cascade paths
   - Deletion metadata for retention/cleanup/recovery
   ↓
9. Delete events from main database
   ↓
10. Remove the live git repository when the owner+identifier announcement scope
   is no longer served
   ↓
11. Deleted/tombstoned targets no longer serve in queries
   ↓
12. Background task (daily):
    - Check holding database for expired entries
    - Delete events older than retention period
    - Delete corresponding archive files
```

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
2. Check idempotency:
   - if every actionable `e`/`a` target is already covered by an existing
     same-author kind-5 request, return a duplicate success response without
     storing the new deletion event
   ↓
3. Store deletion request event in main database
   ↓
4. Do NOT process deletion
   ↓
5. Repository and events remain fully accessible
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
ngit-grasp owns deletion handling in relay policy code, which short-circuits
already-covered NIP-09 deletions before the `deletion_request_disrespector`
archival-mode branch. When `deletion_request_disrespector` is set, new kind-5
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

**DoS via Deletion Spam:**
- Mitigation: ownership checks + normal admission validation
- Mitigation: idempotent delete paths for already-deleted targets

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
