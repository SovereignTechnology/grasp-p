# Explanation: Inline Authorization

**Purpose:** Understand why ngit-grasp validates Git pushes inline rather than using Git hooks  
**Audience:** Developers and architects wanting to understand design decisions

---

## The Problem

Git hosting with authorization requires validating pushes before accepting them. The question is: **where** should this validation happen?

Two approaches exist:

1. **Git Hooks** (traditional): Use Git's pre-receive hook mechanism
2. **Inline Authorization** (our approach): Validate before spawning Git

This document explains why we chose inline authorization and what benefits it provides.

---

## Background: How Git Hooks Work

Git provides a **pre-receive hook** that runs during `git push`:

```
Client              Server
  |                   |
  |--- git push ----->|
  |                   |--- spawn git-receive-pack
  |                   |
  |                   |--- pre-receive hook runs
  |                   |    (reads stdin: old new ref)
  |                   |    (exit 0 = accept, 1 = reject)
  |                   |
  |<--- success ------| (if hook exits 0)
  |<--- error --------| (if hook exits 1)
```

**Pros:**

- Standard Git mechanism
- Language-agnostic (hook can be any executable)
- Well-documented

**Cons:**

- Hook output goes to stderr (client sees as `remote:` messages)
- Hard to provide structured error messages
- Requires hook installation and management
- Difficult to test (needs Git repository setup)
- Hook runs _after_ Git has started processing

---

## Background: How Inline Authorization Works

With inline authorization, we validate **before** spawning Git:

```
Client              Server (ngit-grasp)
  |                   |
  |--- git push ----->|--- HTTP handler receives request
  |                   |
  |                   |--- Parse ref updates from request
  |                   |--- Query database + purgatory for state
  |                   |--- Validate push against state
  |                   |
  |                   |--- If invalid: return HTTP error
  |                   |--- If valid: spawn git-receive-pack
  |                   |
  |<--- success ------| (if valid)
  |<--- HTTP error ---| (if invalid)
```

**Pros:**

- Full control over error messages (HTTP response)
- Can skip spawning Git entirely for invalid pushes
- Easier testing (pure Rust, no Git setup needed)
- Shared state between Git and Nostr components
- Better performance (early rejection)
- Can check both database and purgatory for authorization

**Cons:**

- Requires parsing Git protocol ourselves
- Less standard than hooks
- Tighter coupling to Git HTTP protocol

---

## Why Inline Authorization Is Better for GRASP

### 1. Purgatory Integration

**Critical advantage:** Inline authorization allows checking **both database and purgatory** during authorization:

```rust
// From src/git/authorization.rs
pub async fn authorize_push(
    database: &SharedDatabase,
    identifier: &str,
    owner_pubkey: &str,
    request_body: &Bytes,
    purgatory: &Arc<Purgatory>,  // Can check purgatory!
    repo_path: &std::path::Path,
) -> anyhow::Result<AuthorizationResult>
```

**Why this matters:** State events go to purgatory when git data doesn't exist yet. Without inline authorization checking purgatory, we'd have a deadlock:

1. State event arrives → No git data → Goes to **purgatory** (not database)
2. Git push arrives → Hook checks **database only** → No state found → **REJECTED** ❌

With inline authorization:

1. State event arrives → No git data → Goes to purgatory
2. Git push arrives → Checks **database + purgatory** → State found → **AUTHORIZED** ✅
3. After push succeeds → Save event to database → Remove from purgatory

See [`src/git/authorization.rs:342-400`](../../src/git/authorization.rs) for implementation.

otherwise we'd need another way of storing purgatory events.

### 2. Better Error Messages

**With hooks:**

```
$ git push
remote: error: Push rejected - not authorized for ref refs/heads/main
remote: See https://docs.gitnostr.com/errors/unauthorized
To https://gitnostr.com/alice/myrepo.git
 ! [remote rejected] main -> main (pre-receive hook declined)
```

**With inline authorization:**

```
$ git push
error: RPC failed; HTTP 403 Forbidden
error: Push rejected: No state event found in purgatory from authorized publishers
```

The inline approach provides clear, actionable error messages directly in the HTTP response.

### 3. Performance Benefits

**With hooks:**

- Git process spawns
- Git starts receiving pack data
- Hook runs (might query Nostr relay)
- If rejected, Git throws away received data

**With inline authorization:**

- Parse ref updates from HTTP request (pkt-line format)
- Validate against database + purgatory state
- If rejected, return HTTP error immediately
- Never spawn Git for invalid pushes

**Result:** Faster rejection, less resource usage, no wasted pack data transfer.

### 4. Easier Testing

**With hooks:**

```bash
# Test setup
mkdir -p /tmp/test-repo
cd /tmp/test-repo
git init --bare
cp pre-receive.sh hooks/pre-receive
chmod +x hooks/pre-receive

# Test execution
git push /tmp/test-repo main

# Cleanup
rm -rf /tmp/test-repo
```

**With inline authorization:**

```rust
#[tokio::test]
async fn test_unauthorized_push() {
    let relay = TestRelay::start().await;
    let result = validate_push(&state, "refs/heads/main", alice_pubkey).await;
    assert!(result.is_err());
    relay.stop().await;
}
```

**Result:** Pure Rust unit tests, no shell scripts, no Git setup.

See [`tests/push_authorization.rs`](tests/push_authorization.rs) for actual test examples.

### 5. Shared State and Types

**With hooks:**

- Hook is separate process
- Must query Nostr relay over WebSocket
- Can't share in-memory cache
- Can't access purgatory
- Separate error types

**With inline authorization:**

```rust
// From src/git/handlers.rs
pub async fn handle_receive_pack(
    repo_path: PathBuf,
    body: Bytes,
    database: Option<SharedDatabase>,  // Shared with Nostr relay!
    purgatory: Option<Arc<Purgatory>>, // Shared purgatory access!
    npub: &str,
    identifier: &str,
) -> Result<Response<Full<Bytes>>, GitError> {
    // Direct database + purgatory access for authorization
    let auth = authorize_push(
        &database,
        identifier,
        owner_pubkey,
        &body,
        &purgatory,  // Can check purgatory!
        &repo_path
    ).await?;
    // ...
}
```

**Result:** Better performance, type safety, simpler architecture, purgatory integration.

### 6. Simpler Deployment

**With hooks (ngit-relay):**

```
Docker container:
  - nginx (HTTP frontend)
  - git-http-backend (C binary)
  - pre-receive hook (Go binary)
  - Khatru relay (Go binary)
  - supervisord (process manager)

Setup steps:
  1. Install all components
  2. Configure nginx
  3. Install hook in each repository
  4. Set up supervisord
  5. Configure inter-process communication
```

**With inline authorization (ngit-grasp):**

```
Single Rust binary:
  - HTTP server (Hyper)
  - Git protocol handler
  - Nostr relay (nostr-relay-builder)
  - Authorization logic

Setup steps:
  1. Run binary
  2. Configure environment variables
```

**Result:** Simpler deployment, fewer moving parts.

---

## Technical Implementation

### How We Parse Ref Updates

The Git HTTP protocol sends ref updates in pkt-line format:

```
POST /alice/myrepo.git/git-receive-pack HTTP/1.1
Content-Type: application/x-git-receive-pack-request

00a5 0000...0000 abc123...def456 refs/heads/main\0 report-status\n
0000
PACK...
```

We parse this **before** spawning Git. See [`src/git/authorization.rs:695-778`](../../src/git/authorization.rs) for the implementation:

```rust
/// Parse the refs being updated from a Git pack
///
/// The receive-pack protocol sends ref updates in pkt-line format:
/// - 4-byte hex length prefix (e.g., "00a5")
/// - Payload: `<old-oid> <new-oid> <ref-name>\0<capabilities>\n`
/// - Flush packet "0000" terminates the list
pub fn parse_pushed_refs(data: &[u8]) -> Vec<(String, String, String)> {
    // Handles both pkt-line format (real Git clients)
    // and simple text format (for unit tests)
}
```

### How We Validate

The authorization flow (from [`src/git/authorization.rs:51-162`](../../src/git/authorization.rs)):

```rust
pub async fn authorize_push(
    database: &SharedDatabase,
    identifier: &str,
    owner_pubkey: &str,
    request_body: &Bytes,
    purgatory: &Arc<Purgatory>,
    repo_path: &std::path::Path,
) -> anyhow::Result<AuthorizationResult> {
    // 1. Parse refs from push request
    let pushed_refs = parse_pushed_refs(request_body);

    // 2. Separate refs/nostr/ refs from state refs
    let (nostr_refs, state_refs) = partition_refs(&pushed_refs);

    // 3. Handle refs/nostr/ refs (PR events)
    //    - Validate event ID format
    //    - Check purgatory for PR event
    //    - Create placeholder if git-data-first scenario

    // 4. Handle normal refs (state events)
    //    - Check database + purgatory for state events
    //    - Collect authorized maintainers
    //    - Find latest authorized state
    //    - Validate refs match state

    // 5. Return authorization result with purgatory events
}
```

**Key validation checks:**

1. **For state refs** (`refs/heads/*`, `refs/tags/*`):

   - Query database for announcements → collect authorized maintainers
   - Check **purgatory** for matching state events (critical for purgatory flow!)
   - Filter to events from authorized maintainers
   - Find latest state event
   - Validate pushed refs match state event refs

2. **For PR refs** (`refs/nostr/<event-id>`):
   - Validate event ID format
   - Check purgatory for PR event with matching commit
   - If no event found, create placeholder (git-data-first scenario)
   - Collect PR events from purgatory for post-push processing

**No-Op Push Acceptance:** Pushes where all refs have `old_oid == new_oid` are accepted without requiring a purgatory state event, matching Git's "Everything up-to-date" behavior and avoiding race condition rejections.

---

## State Event Authorization

State events (kind 30618) undergo authorization checks at three points (defense-in-depth):

### 1. On Arrival (StatePolicy)

When a state event arrives via WebSocket or sync:

```rust
// src/nostr/policy/state.rs
impl StatePolicy {
    async fn admit_event(&self, event: &Event) -> Result<Decision, Error> {
        // Check 1: Does announcement exist for this repository?
        let announcements = query_announcements(pubkey, identifier);
        if announcements.is_empty() {
            return Reject("No announcement exists for repository");
        }
        
        // Check 2: Is author in maintainer set?
        let maintainers = build_maintainer_set(announcements);
        if !maintainers.contains(&event.author) {
            return Reject("Author not in maintainer set");
        }
        
        // If git data doesn't exist yet, goes to purgatory
        // Otherwise, accepted to database
    }
}
```

### 2. On Announcement Acceptance (Purgatory Re-evaluation)

When a repository announcement is accepted, waiting state events are re-evaluated:

```rust
// After announcement is saved to database
for state_event in purgatory.get_state_events(identifier) {
    // Re-check authorization now that announcement exists
    if author_in_maintainer_set(state_event.author, identifier) {
        // If git data now exists, save to database
        // Otherwise, keep in purgatory
    } else {
        // Remove from purgatory - not authorized
    }
}
```

### 3. On Git Data Arrival (Purgatory Sync)

When git data is pushed, purgatory state events are validated before saving:

```rust
// src/git/handlers.rs - after successful git push
for state_event in purgatory.get_matching_state_events(identifier) {
    // Final authorization check before database save
    if author_in_maintainer_set(state_event.author, identifier) {
        database.save(state_event);
        purgatory.remove(state_event);
    } else {
        purgatory.remove(state_event); // Not authorized
    }
}
```

### Why Three Checkpoints?

**Defense-in-depth** ensures authorization is always validated:

1. **On arrival**: Prevents unauthorized events from entering the system
2. **On announcement acceptance**: Handles race condition where state arrives before announcement
3. **On git data arrival**: Final check before committing to database

This prevents scenarios where:
- Unauthorized state events are saved after maintainer changes
- Race conditions bypass authorization
- Purgatory holds events that will never be authorized

### Rejection Tracking

State events rejected during authorization are tracked in the rejected events index:

- **Reason: MaintainerNotYetValid** - Author not in maintainer set (may become valid later)
- **Reason: Other** - Other validation failures

When a repository announcement is accepted, rejected state events still present
in the hot cache are re-processed immediately. Reciprocal invitation
announcements can enter purgatory before their source state and Git data are
available. During that bootstrap flow, rejected state events are:

1. **Retained** in the cold index until policy processing succeeds
2. **Retrieved** from the hot cache and re-processed immediately when the full event is still available
3. **Fetched by exact event ID** from the recursive maintainer relay chain when the hot-cache copy has expired
4. **Removed from both tiers** only after the event is accepted, enters purgatory, or is already stored

Repository announcements are processed before dependent state events. Network
requests run outside the main sync-manager lock, and unsuccessful requests retain
their IDs for a throttled retry. This enables rapid recovery from arrival-order
races without reopening a broad synchronization query.

See [GRASP-02: Integration with Rejected Events Index](grasp-02-proactive-sync.md#integration-with-rejected-events-index)
for complete details on rejection tracking and re-processing.

---

## Comparison with Reference Implementation

| Aspect             | ngit-relay (hooks)                       | ngit-grasp (inline)    |
| ------------------ | ---------------------------------------- | ---------------------- |
| **Components**     | nginx + git-http-backend + hook + Khatru | Single Rust binary     |
| **Validation**     | Pre-receive hook (separate process)      | Inline HTTP handler    |
| **Error messages** | Hook stderr → `remote:`                  | HTTP response JSON     |
| **Performance**    | Spawns Git first                         | Validates first        |
| **Testing**        | Shell scripts + Go tests                 | Pure Rust tests        |
| **Deployment**     | Docker + supervisord                     | Single binary          |
| **State sharing**  | WebSocket query                          | Direct database access |

Both are GRASP-compliant, but inline authorization is simpler and more efficient.

---

## Trade-offs and Limitations

### What We Gain

- ✅ **Purgatory integration** - Can check database + purgatory during authorization
- ✅ **Prevents deadlock** - State events in purgatory can authorize pushes
- ✅ Better error messages
- ✅ Better performance (early rejection)
- ✅ Easier testing (pure Rust)
- ✅ Simpler deployment (single binary)
- ✅ Tighter integration (shared state)

### What We Lose

- ❌ Non-standard approach (not using Git's hook system)
- ❌ Tighter coupling to Git HTTP protocol
- ❌ Must parse pkt-line protocol ourselves

### Is It Worth It?

**Absolutely**, because:

1. **Purgatory integration is essential** - Without it, we'd have a deadlock where state events in purgatory can't authorize pushes
2. Protocol parsing is isolated in [`src/git/authorization.rs`](../../src/git/authorization.rs)
3. GRASP is already non-standard (Nostr authorization)
4. Benefits far outweigh the coupling cost
5. We can still add hook support later if needed (but purgatory checking would still need inline access)

---

## Implementation References

Key files in the ngit-grasp implementation:

| Component               | Location                                                                  |
| ----------------------- | ------------------------------------------------------------------------- |
| HTTP routing            | [`src/http/mod.rs`](../../src/http/mod.rs)                                |
| Git handlers            | [`src/git/handlers.rs`](../../src/git/handlers.rs)                        |
| Push authorization      | [`src/git/authorization.rs`](../../src/git/authorization.rs)              |
| Pkt-line parsing        | [`src/git/authorization.rs:695-778`](../../src/git/authorization.rs)      |
| Subprocess management   | [`src/git/subprocess.rs`](../../src/git/subprocess.rs)                    |
| Purgatory integration   | [`src/purgatory/mod.rs`](../../src/purgatory/mod.rs)                      |
| Event acceptance policy | [`src/nostr/builder.rs`](../../src/nostr/builder.rs) - `Nip34WritePolicy` |

---

## Future Considerations

### If We Need Hooks Later

We can add hook support without removing inline validation:

```rust
pub struct GitConfig {
    inline_validation: bool,  // Default: true
    hook_validation: bool,    // Default: false
}
```

This would allow:

- Migration path for hook-based systems
- Extra validation for paranoid deployments
- Compatibility with other Git tools

### If Git Protocol Changes

The protocol parsing is isolated in [`src/git/protocol.rs`](src/git/protocol.rs). If the Git protocol changes:

- Update the protocol module
- Tests will catch any breakage

---

## Conclusion

**Inline authorization is the right choice for ngit-grasp** because:

1. **Purgatory integration** - Without inline authorization, state events in purgatory couldn't authorize pushes, creating a deadlock
2. **Better error messages** - Direct HTTP responses with clear rejection reasons
3. **Better performance** - Early rejection before spawning Git
4. **Easier testing** - Pure Rust unit tests, no Git setup needed
5. **Simpler deployment** - Single binary with shared state
6. **Shared database + purgatory** - Both authorization sources accessible during validation

The trade-off (coupling to Git HTTP protocol) is acceptable because:

- The pkt-line protocol is stable and well-specified
- Protocol parsing is isolated in [`src/git/authorization.rs`](../../src/git/authorization.rs)
- Purgatory integration requires inline access anyway
- Benefits far outweigh the cost

This decision aligns with our goal of creating a **developer-friendly, production-ready GRASP implementation** that properly handles the event-git-data ordering problem via purgatory.

---

## Related Documentation

- [Architecture Overview](architecture.md) - Full system design
- [Design Decisions](decisions.md) - All architectural choices
- [Comparison with ngit-relay](comparison.md) - Detailed comparison
- [Git Protocol Reference](../reference/git-protocol.md) - Protocol details
- [Test Strategy](../reference/test-strategy.md) - How we test this

---

_Part of the [ngit-grasp explanation docs](./)_
