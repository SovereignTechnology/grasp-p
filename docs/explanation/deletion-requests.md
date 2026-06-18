# Deletion Request Support (NIP-09)

## Overview

ngit-grasp will implement optional support for NIP-09 deletion requests, allowing repository owners to remove their repositories from the relay while providing safeguards against the "left-pad problem" through configurable archival behavior.

## The Left-Pad Problem

The "left-pad problem" refers to a 2016 incident where a critical npm package was unpublished, breaking thousands of dependent projects. In the context of decentralized Git hosting, this translates to:

**Scenario:** A popular repository with many PRs, issues, and community contributions gets deleted by its owner. All dependent work (forks, patches, discussions) becomes inaccessible, potentially breaking workflows and losing community knowledge.

**Our Solution:** The `deletion-request-disrespector` configuration option allows operators to run **archival relays** that preserve deleted content, ensuring community work survives repository deletion while still respecting deletion requests on standard relays.

## Architecture

### Three-Database Design

The deletion system uses three separate data stores:

```
┌─────────────────────────────────────────────────────────┐
│                    Main Database                        │
│         (Live events - actively served)                 │
│    LMDB/Memory backend                                 │
└─────────────────────────────────────────────────────────┘
                         ↓ deletion request
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
2. **Holding Database:** Recovery mechanism, prevents accidental permanent deletion
3. **Archive Filesystem:** Git data backup, compressed storage

### Holding Database Operations

**Automatic Operations:**
- **Move to holding:** NIP-09 deletions, blacklist deletions
- **Automatic recovery:** Re-publishing after NIP-09 deletion (within retention window)
- **Expiry cleanup:** Daily background task removes entries older than retention period

**Manual Operations:**
- **Manual ejection:** Operator force-deletes before retention expires
  - Use case: Large repos consuming excessive storage
  - Use case: Confirmed malware requiring immediate permanent deletion
  - Mechanism: CLI command or admin tool (design in Phase 6)
  - Logged for audit trail
- **Manual restoration:** Operator restores blacklisted repo after removal from blacklist
  - Future: May support automatic restoration

## Deletion Flow

### Standard Mode (Respects Deletions)

#### NIP-09 Deletion Requests

```
1. Kind 5 deletion request arrives
   ↓
2. Validate: author matches announcement pubkey
   ↓
3. Query dependent events (PRs, issues, patches, comments)
   ↓
4. Archive git repository to .archive/<npub>/<identifier>-<timestamp>.tar.gz
   ↓
5. Move events to holding database:
   - Announcement
   - All dependent events (cascade delete)
   ↓
6. Delete events from main database
   ↓
7. Events no longer served in queries
   ↓
8. Background task (daily):
   - Check holding database for expired entries
   - Delete events older than retention period
   - Delete corresponding archive files
```

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

**Future:** When dynamic blacklist updates are supported, deletion will trigger immediately on config change instead of waiting for restart.

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
`supported_nips` list in this mode. The git-archival / holding-DB pieces of the
broader design remain planned.

## Recovery Mechanism

The holding database enables **accidental deletion recovery**:

### Automatic Recovery (NIP-09 Deletions)

```
Scenario: Owner deletes repository, then changes their mind

1. Owner publishes new announcement with same identifier
   ↓
2. System detects matching entry in holding database
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

### Blacklist Recovery

When a repository is removed from the blacklist:

**Option 1: Manual Restoration (Initial Implementation)**
- Operator removes from blacklist config
- Operator manually restores from holding DB if desired
- Provides explicit control over recovery decisions

**Option 2: Automatic Restoration (Future Enhancement)**
- On startup, detect repos in holding area no longer blacklisted
- Automatically restore to main DB if within retention period
- Requires careful design to prevent unwanted restorations

**Decision:** Start with manual restoration, evaluate automatic restoration in Phase 6.

### Manual Ejection from Holding Area

Operators need ability to **force-delete** items from holding area before retention period expires:

**Use Cases:**
1. Large repositories consuming excessive storage
2. Confirmed malware/abuse that shouldn't be recoverable
3. Legal/compliance requirements for immediate permanent deletion

**Mechanism (TBD in Phase 6):**
- Admin CLI command: `ngit-grasp eject <npub>/<identifier>`
- Or database operation with proper tooling
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

**Initial Implementation (Startup Scan):**
```
1. Relay starts up
2. Load blacklist configuration
3. Scan main database for matching repos
4. For each match: archive → holding DB → delete from main
5. Continue normal operation
```

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
    ↓ all above deleted
    └─→ Comments (1111) - tag via 'e'
        ├─→ Reactions (7) - tag via 'e'
        └─→ Text Notes (1) - tag via 'e'
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
- Configurable maximum traversal depth (prevent infinite loops)
- Default: 100 levels
- Note: Will analyze edge cases where this limit matters

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
- GRASP-05 archive mode (future)

### archive_retention_secs

**Type:** `u64`  
**Default:** `7776000` (90 days in seconds)  
**CLI:** `--archive-retention-secs`  
**Env:** `NGIT_ARCHIVE_RETENTION_SECS`

**Description:**
How long to retain archived events and git data before permanent deletion. Provides recovery window for accidental deletions.

**Recommended Values:**
- Development/Testing: `5` seconds (fast test cycles)
- Staging: `300` seconds (5 minutes)
- Production: `7776000` seconds (90 days, default)
- Archival Relay: `31536000` seconds (1 year) or higher

**Notes:**
- Configurable in seconds for testing flexibility
- Background cleanup task runs daily (configuration for testing interval TBD in Phase 6)
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

1. **Author Matching:** Deletion request pubkey MUST match announcement pubkey
   - **Critical Requirement:** We ONLY honor deletion requests where the deletion request author is the same as the deleted event author
   - This prevents malicious actors from deleting other people's repositories
   - Enforced at validation layer before any deletion processing
2. **Signature Verification:** Handled by nostr-relay-builder (already implemented)
3. **Timestamp Check:** For addressable events, delete versions up to deletion `created_at`

### Attack Vectors

**DoS via Deletion Spam:**
- Mitigation: Deletion requests only processed if announcement exists
- Mitigation: Idempotent (deleting already-deleted announcement is no-op)

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

**Prometheus Metrics (Planned):**
- `ngit_deletion_requests_total` - Count of NIP-09 deletion requests received
- `ngit_deletion_requests_processed` - Count actually processed (disrespector mode = 0)
- `ngit_blacklist_deletions_total` - Count of blacklist-triggered deletions
- `ngit_holding_database_events` - Current event count in holding DB
- `ngit_holding_database_size_bytes` - Holding DB disk usage
- `ngit_archive_files_total` - Count of archive tar.gz files
- `ngit_archive_size_bytes` - Total archive disk usage
- `ngit_recoveries_total` - Count of successful automatic recoveries
- `ngit_permanent_deletions_total` - Count of events permanently deleted (post-retention)
- `ngit_manual_ejections_total` - Count of operator-initiated ejections from holding area

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

### GRASP-05 Archive Mode
Once GRASP-05 is specified, `deletion_request_disrespector` mode can form the foundation for archive relay requirements.

### Selective Disrespect
Allow configuration to disrespect deletions only for specific criteria:
- Popular repositories (e.g., >N PRs)
- Repositories with community contributions
- Specific identifiers (allowlist)

### Distributed Archive Network
Coordinate between archival relays to ensure redundant preservation of deleted content.

### Recovery Notifications
Notify repository owner when content is recovered from holding database, allowing them to confirm or re-delete.

### Dynamic Blacklist Updates
Currently blacklist changes only take effect on startup. Future enhancement:
- Monitor configuration file for changes
- Apply blacklist additions immediately (trigger deletion)
- Apply blacklist removals immediately (optional auto-recovery)
- Requires careful concurrency design

### Automatic Blacklist Recovery
Currently removing from blacklist requires manual restoration. Future enhancement:
- Detect unblacklisted repos in holding area on startup
- Automatically restore if within retention period
- Configurable policy: auto-restore vs manual-only

### Enhanced Manual Ejection
Current design includes basic manual ejection. Future enhancements:
- Web UI for holding area management
- Batch ejection operations
- Selective ejection (events only, keep git archive)
- Export before ejection (backup)
- Enhanced audit logging with operator identity

## Conclusion

The deletion request system balances three competing needs:

1. **User Agency:** Owners can delete their repositories
2. **Community Protection:** Archival relays prevent left-pad scenarios  
3. **Recovery Grace Period:** Holding database prevents accidental permanent deletion

By making deletion behavior **configurable** rather than mandatory, we enable a heterogeneous relay network where some relays respect deletions (user privacy) while others preserve content (community resilience).
