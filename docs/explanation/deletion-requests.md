# Deletion Request Support (NIP-09)

## Overview

ngit-grasp implements optional support for NIP-09 deletion requests, allowing
repository owners to remove their repositories from the relay while giving
operators configurable archival behavior for left-pad resilience.

## Core consistency invariant

ngit-grasp enforces the following invariant across admission, serving, deletion,
and recovery:

> **Served nostr state must always match git refs we can actually serve.**

This invariant is the design center for deletion handling and a key rationale
for purgatory. If the currently served repository state is deleted and no valid
rollback state exists, the relay must stop serving that state, park the
announcement scope in purgatory, and wait for a promotable state before serving
again.

## Ownership of deletion behavior

ngit-grasp disables backend auto-processing and owns NIP-09/NIP-62 handling in
relay policy code:

- main DB uses `process_nip09(false)` and `process_nip62(false)`
  (`src/nostr/builder.rs`)
- tombstones DB uses `process_nip09(false)` and `process_nip62(false)`
  (`src/nostr/tombstones.rs`)
- holding DB uses `process_nip09(false)` and `process_nip62(false)`
  (`src/nostr/holding.rs`)

This keeps deletion behavior auditable and consistent across cascade, holding,
archive, and recovery flows.

## The Left-Pad Problem

The "left-pad problem" refers to a 2016 incident where a critical npm package was unpublished, breaking thousands of dependent projects. In the context of decentralized Git hosting, this translates to:

**Scenario:** A popular repository with many PRs, issues, and community contributions gets deleted by its owner. All dependent work (forks, patches, discussions) becomes inaccessible, potentially breaking workflows and losing community knowledge.

**Our Solution:** The `deletion-request-disrespector` configuration option allows operators to run **archival relays** that preserve deleted content, ensuring community work survives repository deletion while still respecting deletion requests on standard relays.

## Architecture

### Three-Database Design

The deletion system uses three relay databases plus archive filesystem storage:

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
│    + metadata.json                                     │
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
- **Move to holding:** NIP-09 deletions, blacklist deletions
- **Automatic recovery:** Re-publishing after NIP-09 deletion (within retention window)
- **Expiry cleanup:** Daily background task removes entries older than retention period

**Manual Operations:**
- **Manual ejection:** Operator force-deletes before retention expires
  - Use case: Large repos consuming excessive storage
  - Use case: Confirmed malware requiring immediate permanent deletion
  - Mechanism: `ngit-grasp holding-eject --owner <npub|hex> --identifier <id>`
  - Logged for audit trail
- **Manual restoration:** Operator restores blacklisted repo after removal from blacklist
  - Currently no dedicated restore CLI (restore happens through normal recovery paths)

## Deletion Flow

### Standard Mode (Respects Deletions)

#### NIP-09 Deletion Requests

```
1. Kind 5 deletion request arrives
   ↓
2. Validate targets:
   - `e` targets must be authored by deleter (cross-author delete rejected)
   - `a` coordinates are acted on only when coordinate pubkey matches deleter
   ↓
3. Query dependent events (PRs, issues, patches, comments)
   ↓
4. Archive git repository to .archive/<npub>/<identifier>-<timestamp>.tar.gz
   ↓
5. Move events to holding database:
   - Announcement
   - All dependent events (cascade delete)
   - Deletion metadata for retention/cleanup/recovery
   ↓
6. Delete events from main database
   ↓
7. Record deletion tombstone so re-submission is gated
   ↓
8. Events no longer served in queries
   ↓
9. Background task (daily):
   - Check holding database for expired entries
   - Delete events older than retention period
   - Delete corresponding archive files
```

Deletion gate checks tombstones before kind-specific admission and rejects:
- events from vanished pubkeys,
- re-submission of deleted event IDs,
- replaceable/addressable events covered by coordinate tombstones.

#### Blacklist-Triggered Deletion

When a repository is added to `NGIT_REPOSITORY_BLACKLIST`, the same deletion flow applies:

```
1. Startup: Scan main DB for repos matching blacklist
   ↓
2. For each matching repository:
   - Query dependent events (same cascade logic)
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
2. Store deletion request event in main database
   ↓
3. Do NOT process deletion
   ↓
4. Repository and events remain fully accessible
   ↓
Result: Archival relay preserves all content
```

**Important:** Disrespector mode ONLY affects NIP-09 user-initiated deletions. It does NOT prevent blacklist-triggered deletions.

**Rationale:**
- NIP-09 deletions are user agency decisions (left-pad protection needed)
- Blacklist deletions are operator moderation decisions (spam/malware/abuse)
- Archival relays still need ability to moderate malicious content
- Different policy goals: preservation vs. safety

**Implementation Note:** Implemented. The LMDB backend's automatic NIP-09
processing is disabled (`process_nip09(false)`); ngit-grasp owns deletion
handling in [`DeletionPolicy::handle`](../../src/nostr/policy/deletion.rs), which
short-circuits when `deletion_request_disrespector` is set — storing but not
acting on the kind-5 request. NIP-09 is omitted from the NIP-11
`supported_nips` list in this mode.

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
ngit-grasp's dedicated replaceable-history store (`src/nostr/history.rs`), not
backend internal replaceable compaction behavior.

The relay archives superseded 30617/30618 versions on write and uses that
history at deletion time to pick rollback candidates for active `e`-target
deletions (announcement + state).

### Blacklist Recovery

When a repository is removed from the blacklist:

**Option 1: Manual Restoration (Current Behavior)**
- Operator removes from blacklist config
- Operator manually restores from holding DB if desired
- Provides explicit control over recovery decisions

**Option 2: Automatic Restoration (Future Enhancement)**
- On startup, detect repos in holding area no longer blacklisted
- Automatically restore to main DB if within retention period
- Requires careful design to prevent unwanted restorations

**Current behavior:** manual restoration workflows only.

### Manual Ejection from Holding Area

Operators need ability to **force-delete** items from holding area before retention period expires:

**Use Cases:**
1. Large repositories consuming excessive storage
2. Confirmed malware/abuse that shouldn't be recoverable
3. Legal/compliance requirements for immediate permanent deletion

**Mechanism (implemented):**
- Admin CLI command: `ngit-grasp holding-eject --owner <npub|hex> --identifier <id>`
- Immediately delete from holding DB and archive filesystem
- Log operation for audit trail
- Metric: `ngit_manual_ejections_total`

**Safety Considerations:**
- Manual ejection is permanent (no undo)
- Should require confirmation for safety
- Should log npub, identifier, reason, operator
- Consider retention policy override vs immediate deletion

## Blacklist Deletion Integration

### Overview

Blacklist-triggered deletions use the **same infrastructure** as NIP-09 deletion requests:
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
| **Recovery** | Automatic (re-publish) | Manual (operator decision) |
| **Metadata** | Links to Kind 5 event | Marks "blacklist-triggered" |

### Why Disrespector Doesn't Prevent Blacklist Deletion

**Design Decision:** The `deletion_request_disrespector` configuration ONLY affects NIP-09 user-initiated deletions. It does NOT prevent blacklist-triggered deletions.

**Rationale:**
1. **Different Policy Goals:**
   - NIP-09 = User agency (prevent left-pad)
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

**Future Enhancement (Dynamic Updates):**
- Watch for configuration file changes
- Trigger deletion immediately on blacklist addition
- Requires careful design to avoid race conditions

## Cascade Deletion Strategy

When a repository announcement is deleted (NIP-09 or blacklist), we cascade delete **all dependent events**:

### Rationale

**Decision:** Delete all dependent events, not just owner's events.

**Why?**
1. **Deletion Intent:** Owner wants repository gone - includes all associated data
2. **Data Integrity:** Orphaned PRs/issues without context are confusing
3. **Consistency:** Matches user expectation that "delete repo" means "delete everything"
4. **Recovery Available:** Holding database preserves everything for recovery window

**Community Protection:**
- Archival relays (`deletion_request_disrespector = true`) preserve community work
- 90-day default retention allows time for recovery
- Other maintainers can continue repository with different identifier

### Event Cascade Hierarchy

```
Repository Announcement (30617)
    ↓ deleted
├─→ State Events (30618) - same identifier
├─→ Pull Requests (1618) - tag via 'a'
├─→ Issues (1621) - tag via 'a'  
├─→ Patches (1617) - tag via 'a'
├─→ Repository/Issue/PR/Patch status (1633/1630/1631/1632)
    ↓ all above deleted
    └─→ Comments (1111) - tag via 'e'
```

**Implementation:** Recursive dependency graph traversal starting from announcement.

## Multi-Maintainer Scenarios

### Challenge

Multiple maintainers can have announcements for the same `identifier`:
- `npub1alice.../my-repo` 
- `npub1bob.../my-repo`

Git data is synced between their repositories. When ONE maintainer deletes, what happens?

### Solution: Graph-Based Retention Algorithm

```
When npub1alice deletes her announcement:

1. Archive HER git directory:
   .archive/npub1alice.../my-repo-<timestamp>.tar.gz

2. Query all events that referenced her announcement

3. Re-evaluate each event through acceptance policy:
   - WITHOUT alice's announcement
   - WITH bob's announcement still present
   
4. Build retention graph:
   Event A kept because:
     - References bob's announcement ✓
   Event B kept because:
     - References Event A ✓
   Event C orphaned because:
     - Only referenced alice's announcement ✗

5. Delete orphaned events, keep retained events

6. Handle circular dependencies:
   - Event X kept because references Event Y
   - Event Y kept because references Event X
   - Neither has external anchor → both deleted
```

### Graph Algorithm Details

**Topological Traversal:**
1. Start from remaining announcements (roots)
2. Traverse dependency edges (a/e/q tags)
3. Mark reachable events as "keep"
4. Mark unreachable events as "delete"

**Max Depth Limit:**
- Internal maximum traversal depth guard (prevents infinite loops)
- Default: 100 levels
- Note: this is currently code-level, not a user/operator config option

**Complexity:**
- Deletion events are rare (not performance critical)
- Compute on-demand when deletion request arrives
- No pre-computation or caching needed at current scale
- Note: Will analyze large-scale scenarios in future

## Configuration

### deletion_request_disrespector

**Type:** `bool`  
**Default:** `false` (respects deletion requests)  
**CLI:** `--deletion-request-disrespector`  
**Env:** `NGIT_DELETION_REQUEST_DISRESPECTOR`

**Description:**
When `true`, relay ignores **NIP-09 deletion requests** and acts as an archival server. Critical for preventing left-pad scenarios by ensuring at least some relays preserve deleted content.

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
- **When `deletion_request_disrespector = true`:** do NOT include `9` or `62` (archival mode doesn't honor deletions)

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
- `ngit_holding_cleanup_runs_total`
- `ngit_holding_cleanup_deleted_total{type}`
- `ngit_holding_cleanup_last_run_deleted{type}`
- `ngit_recovery_total{result}`
- `ngit_manual_ejections_total`
- `ngit_manual_ejection_deleted_total{type}`

## Testing Strategy

### Unit Tests
- Kind 5 validation and parsing
- Author matching logic
- Cascade dependency query
- Graph traversal algorithm
- Recovery detection

### Integration Tests
- Cascade correctness (single-maintainer + multi-maintainer + state-event paths)
- Holding DB move semantics (subset of representative scenarios, not every test)
- Retention/expiry cleanup behavior (short-retention deterministic tests)
- Recovery mechanism
- Disrespector mode behavior

### Audit Tests
- NIP-09 compliance validation
- Event re-submission after deletion (rejected)
- Deletion request event itself (stored)
- Archival mode relay behavior

## Related Documentation

- **NIP-09 Specification:** `/persistent/dcdev/clones/nips/09.md`
- **Architecture Overview:** `docs/explanation/architecture.md`
- **Configuration Reference:** `docs/reference/configuration.md`
- **Roadmap:** `README.md` lines 198-206

## Future Enhancements

Remaining enhancements (updated after subsequent deletion/archival and GRASP-05
work):

### Archive-mode policy extensions
- **Selective disrespect:** policy-based disrespect for specific criteria (e.g. popularity, community contribution, identifier allowlist).
- **Distributed archive coordination:** cross-relay replication for redundancy of deleted content.

### Cleanup and deletion engine hardening
- **Cleanup timing strategy:** optimize cleanup behavior for both production cadence and short-retention test scenarios.
- **Backend/index behavior verification:** continue validating deletion behavior across backend upgrades, including index consistency when relay-owned deletion paths mutate served data.
- **Large-scale + edge-case analysis:** document/validate max-depth behavior, large dependency graphs, and memory/performance characteristics.
- **Concurrency/race handling:** deletion during active sync, concurrent shared-repo deletes, and archival locking strategy.

### Blacklist lifecycle improvements
- **Dynamic blacklist updates:** apply blacklist additions/removals without restart.
- **Automatic blacklist recovery (optional policy):** configurable auto-restore for unblacklisted repos within retention.
- **Dedicated restore CLI:** explicit operator restore commands with clear scope selection and outcomes.

### Operator controls and UX
- **Enhanced manual ejection:** batch operations, selective ejection (events vs git archive), export-before-eject, richer operator audit metadata.
- **Recovery notifications:** notify owner when content is restored, so they can confirm or re-delete.
- **Holding-area management UI:** optional web/admin UX for archive and holding lifecycle operations.

### Delayed archival strategy (active repositories)
- Add optional grace/delay workflow for high-activity repositories before archival execution.
- Support cancellation windows, notification issue creation, and schedulable delayed archival operations.
- Expose policy knobs (notification delay, archive delay, activity/creator thresholds).

### Advanced deletion semantics
- **Generalized replaceable/addressable rollback policy:** current `e`-target rollback covers repository announcement/state (30617/30618); evaluate whether additional kinds should adopt the same behavior.
- **PR deletion policy refinement:** define final behavior for deleting PR-related events without unintended dependent-data loss.

### Monitoring and integration follow-up
- Expand deletion/archival/recovery metrics and provide dashboard + alerting guidance.
- Re-verify compatibility as core relay features evolve.

## Conclusion

The deletion request system balances three competing needs:

1. **User Agency:** Owners can delete their repositories
2. **Community Protection:** Archival relays prevent left-pad scenarios  
3. **Recovery Grace Period:** Holding database prevents accidental permanent deletion

By making deletion behavior **configurable** rather than mandatory, we enable a heterogeneous relay network where some relays respect deletions (user privacy) while others preserve content (community resilience).
