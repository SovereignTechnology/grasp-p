# ngit-grasp Architecture

Transient collections, queues, tasks, and peer-selected identifiers follow the
ownership and cleanup invariants in
[Peer-controlled state ownership](peer-controlled-state.md).

## Executive Summary

`ngit-grasp` implements the GRASP protocol in Rust with **inline authorization** rather than Git hooks. Git push operations are intercepted and validated at the HTTP handler level before reaching the Git repository, eliminating the need for pre-receive hooks.

Git object storage is organized into identifier families shared by the
owner-specific and GRASP-06 repository views. The local filesystem remains the
default durable backend; S3-compatible storage is opt-in. See
[Identifier-family Git object storage](git-family-object-storage.md) for the
storage, durability, no-GC, and startup-migration invariants.

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        ngit-grasp                           │
│                     (Single Rust Binary)                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────┐              ┌──────────────────┐   │
│  │   HTTP Router    │              │  Nostr Relay     │   │
│  │     (Hyper)      │              │  (nostr-relay-   │   │
│  │                  │              │   builder)       │   │
│  └────────┬─────────┘              └────────┬─────────┘   │
│           │                                 │             │
│           │                                 │             │
│  ┌────────▼──────────────────────────────────▼─────────┐  │
│  │           Shared State & Storage                    │  │
│  │  ┌──────────────┐  ┌──────────────┐                │  │
│  │  │  Repository  │  │  Event Store │                │  │
│  │  │  Manager     │  │  (LMDB/NDB)  │                │  │
│  │  └──────────────┘  └──────────────┘                │  │
│  └─────────────────────────────────────────────────────┘  │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │            Git Protocol Handler                      │  │
│  │                                                      │  │
│  │  1. Receive git-receive-pack request                │  │
│  │  2. Parse ref updates from request                  │  │
│  │  3. Query Nostr relay for state event               │  │
│  │  4. Validate refs against state                     │  │
│  │  5. If valid: spawn git-receive-pack                │  │
│  │  6. If invalid: return HTTP error                   │  │
│  │                                                      │  │
│  └──────────────────────────────────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
         │                                      │
         │ HTTP/Git                             │ WebSocket/Nostr
         ▼                                      ▼
    Git Clients                            Nostr Clients
```

## Component Design

### 1. Main Server ([`src/main.rs`](src/main.rs) + [`src/server.rs`](src/server.rs))

Server startup is split across two layers: `main.rs` owns binary-only
concerns, while `RelayServer` in `server.rs` owns the reusable relay
runtime:

**[`src/main.rs`](src/main.rs) — binary-only concerns:**

- Initialize configuration from CLI/environment (clap + dotenvy)
- Install the global tracing subscriber
- Load/generate the relay owner key file (`.relay-owner.nsec`)
- Translate OS signals (SIGINT/SIGTERM) into a shutdown future

**[`src/server.rs`](src/server.rs) — `RelayServer`, the shared runtime:**

- Bind the TCP listener (supports `:0` for kernel-assigned ports; the
  resolved address back-fills `bind_address` and, if empty, `domain`)
- Disable Nagle on accepted sockets so small EVENT/EOSE and streaming Git
  writes do not wait for the peer's delayed acknowledgements, including
  when the immediate peer is a local reverse proxy
- Render metrics on a blocking worker, serializing concurrent scrapes before
  spawning filesystem scans so monitoring cannot occupy the network executor
- Initialize Nostr relay builder with custom [`Nip34WritePolicy`](src/nostr/builder.rs:51)
- Set up shared storage (LMDB or Memory), purgatory, sync manager, and
  background maintenance tasks
- Seed the relay owner's minimal kind-0 bot profile and single-relay
  kind-10002 read/write list when absent — stored identity events are never
  overwritten, and a kind with no local copy is seeded only once a
  configured user-index relay is reachable and confirms it holds no identity
  of that kind — then publish in the background: no identity event, stored
  or generated, is sent before at least one user-index relay has been
  checked for its kind, every send is preceded by a per-relay re-check, and
  an identity found on an index is adopted locally instead of overwritten.
  Among verified owner events of a kind, the newest timestamp wins; equal
  timestamps select the lowest event ID.
  Transient failures retry with a capped backoff, and in private mode the
  identity stays local so the relay's existence is never advertised
- Atomically checkpoint purgatory and rejected-event recovery state every 60
  seconds without consuming the checkpoint during restore. Serialization and
  durable filesystem writes run on a blocking worker, with at most one
  checkpoint active and the next interval measured from completion. Shutdown
  joins any active checkpoint before writing the final snapshot, preventing
  an older background write from replacing it
- Start non-blocking storage-integrity and authorization-integrity passes after
  database initialization. The former checks family objects and thin-view
  wiring; the latter reconciles each served ref against accepted State, PR,
  and PR Update events. Owner-view PR refs require confirmed-maintainer overlap
  or an exact service-local standard clone coordinate; GRASP-06 views retain
  their stricter signer and `/prs/` coordinate checks. The pass auto-repairs
  only unambiguous differences and logs preserved evidence for manual
  inspection. Both cover all families by default, with a shared temporary
  identifier scope for staged validation; durable manual requests run the same
  pair in check-only or repair mode
- Serve HTTP + WebSocket until a caller-supplied shutdown future
  resolves, then stop background mutation, persist a final state snapshot
  (purgatory and rejected-events cache), and clean up placeholder refs

**Key Dependencies:**

```rust
hyper = "1"
tokio = { version = "1", features = ["full"] }
nostr-sdk = { version = "0.45.3", features = ["local-relay"] }
nostr-lmdb = "0.45.3"
```

### 2. HTTP Module ([`src/http/mod.rs`](src/http/mod.rs))

**Responsibilities:**

- Route HTTP requests to appropriate handlers
- WebSocket upgrade for the Nostr relay at the configured `NGIT_BASE_PATH`
- Git Smart HTTP endpoints below
  `<base-path>/<npub>/<identifier>.git/*`
- Prefix-scoped landing, metrics, icon, Git, GRASP-06, NIP-11, and WebSocket
  routing. The NIP-05 `_@domain` mapping is served and advertised only when
  `NGIT_BASE_PATH=/`; path-mounted owner profiles also omit `nip05`.
- CORS headers on all responses (GRASP-01 requirement)

**Key Implementation Details:**

```rust
// CORS headers required by GRASP-01 specification
const CORS_ALLOW_ORIGIN: &str = "*";
const CORS_ALLOW_METHODS: &str = "GET, POST";
const CORS_ALLOW_HEADERS: &str = "Content-Type";

/// Add CORS headers to a response builder
fn add_cors_headers(builder: http::response::Builder) -> http::response::Builder {
    builder
        .header("Access-Control-Allow-Origin", CORS_ALLOW_ORIGIN)
        .header("Access-Control-Allow-Methods", CORS_ALLOW_METHODS)
        .header("Access-Control-Allow-Headers", CORS_ALLOW_HEADERS)
}
```

See [`src/http/mod.rs:29-84`](src/http/mod.rs:29-84) for the full CORS implementation.

The relay-owner key is also a trusted service author in `Nip34WritePolicy`,
with deliberately narrow scope. Owner-signed events skip the event blacklist
but still pass the NIP-09/NIP-62 deletion gate, so a replayed copy of a
retracted owner event cannot undo its tombstone, and every kind with a
dedicated admission policy takes its normal path: owner-signed NIP-34
announcements, state events, and PRs are validated, ref-aligned, and routed
through purgatory exactly like anyone else's, while the relay's own kind
0/10002 identity is always accepted. Trust applies only to owner-signed
kinds that would otherwise fall through to the generic related-event
rejection — `ngit-ci` coordinator advertisements, for example, intentionally
have no repository root tag. Owner-authored NIP-09/NIP-62 requests still run
through their normal lifecycle handlers so CI status retractions and other
deletions retain their protocol effects. Because the blacklist cannot block
the owner key, the only remediation for a compromised relay-owner nsec is
rotating the key.

### 3. Git Module ([`src/git/`](src/git/))

#### [`handlers.rs`](src/git/handlers.rs) - Git HTTP Handlers

Implements handlers for Git Smart HTTP protocol:

```rust
/// Handle GET /info/refs?service=git-{upload,receive}-pack
pub async fn handle_info_refs(
    repo_path: PathBuf,
    service: GitService,
) -> Result<Response<Full<Bytes>>, GitError>

/// Handle POST /git-upload-pack (clone/fetch)
pub async fn handle_upload_pack(
    repo_path: PathBuf,
    body: Bytes,
) -> Result<Response<Full<Bytes>>, GitError>

/// Handle POST /git-receive-pack (push)
/// THIS IS WHERE THE MAGIC HAPPENS - validates against state before accepting
pub async fn handle_receive_pack(
    repo_path: PathBuf,
    body: Bytes,
    database: SharedDatabase,
    npub: &str,
    identifier: &str,
) -> Result<Response<Full<Bytes>>, GitError>
```

See [`src/git/handlers.rs:22-98`](src/git/handlers.rs:22-98) for the info-refs implementation.

The upload-pack streaming task retains a repository tracing span. Unexpected
process failures include the exit status and stream outcome even when Git
produces no stderr. A disconnected HTTP client cancels the child and is logged
at debug level; the operation remains unsuccessful in clone metrics.

#### [`authorization.rs`](src/git/authorization.rs) - Push Validation

**Core Logic:**

```rust
/// Get authorization for the repository coordinate selected by the URL
pub async fn get_state_authorization_for_selected_repo(
    database: &SharedDatabase,
    selected_pubkey: &str,
    identifier: &str,
) -> Result<AuthorizationResult, AuthorizationError>

/// Validate that pushed refs match the authorized state
pub fn validate_push_refs(
    pushed_refs: &[PushedRef],
    state: &RepositoryState,
) -> Result<(), AuthorizationError>

/// Validate refs/nostr/<event-id> pushes
pub fn validate_nostr_ref_pushes(
    pushed_refs: &[PushedRef],
    database: &SharedDatabase,
) -> Result<(), AuthorizationError>
```

### 4. Nostr Module ([`src/nostr/`](src/nostr/))

#### [`builder.rs`](src/nostr/builder.rs) - Relay Configuration

The [`Nip34WritePolicy`](src/nostr/builder.rs:51) is the core event validation logic:

```rust
/// NIP-34 Write Policy with Full GRASP-01 Event Validation
///
/// Validates all events according to GRASP-01 specification:
/// - Repository announcements must list service in clone and relays tags
///   EXCEPTION: Maintainer-discovery candidates are accepted even without
///   listing the service; this admits dependencies but grants no state authority
/// - Repository state announcements must have valid structure
/// - Other events must reference accepted repositories or events
/// - Forward references are supported (events referenced by accepted events)
/// - Orphan events with no valid references are rejected
pub struct Nip34WritePolicy {
    ctx: PolicyContext,
    announcement_policy: AnnouncementPolicy,
    state_policy: StatePolicy,
    pr_event_policy: PrEventPolicy,
    related_event_policy: RelatedEventPolicy,
    deletion: DeletionService,
}
```

See [`src/nostr/builder.rs:38-78`](src/nostr/builder.rs:38-78) for the full policy struct.

#### [`lifecycle.rs`](src/nostr/lifecycle.rs) - Repository Lifecycle Coordination

`RepositoryLifecycle` is the shared facade for per-repository lifecycle locks.
Git Smart HTTP serving takes shared read locks through this facade, while
deletion and recovery take exclusive write locks through the same facade. The
lock map and lock-file support are owned by the lifecycle module itself, so
repository runtime coordination is independent of holding/deletion storage.

```text
HTTP git serving  -> RepositoryLifecycle
Deletion/recovery -> RepositoryLifecycle
Holding cleanup   -> RepositoryLifecycle
Manual ejection   -> RepositoryLifecycle
RepositoryLifecycle -> RepositoryLifecycleLocks
```

#### [`lifecycle/deletion/`](src/nostr/lifecycle/deletion/) - Deletion Lifecycle

Deletion handling is owned by ngit-grasp policy code rather than backend
auto-processing. NIP-09 deletion requests, NIP-62 request-to-vanish events,
repository blacklist/whitelist parity, and runtime service de-listing all flow
through the same lifecycle: gate future writes with tombstones where applicable,
move removed events into holding, cascade-delete repository-related events that
lose their accepted-reference path, archive/remove the related git repositories
when a served scope disappears, and keep nostr state aligned with git data.
Operators can opt into archival behaviour with
`NGIT_DELETION_REQUEST_DISRESPECTOR`, which stores but does not act on user
deletion/vanish requests.

Full details: [Repository Lifecycle](repository-lifecycle.md).

#### [`events.rs`](src/nostr/events.rs) - Event Parsing

Provides structures for parsing NIP-34 events:

```rust
/// Parsed repository announcement (Kind 30617)
pub struct RepositoryAnnouncement { ... }

/// Parsed repository state (Kind 30618)
pub struct RepositoryState { ... }
```

#### Maintainer Membership Model

The cross-project behavior is defined by the
[maintainer protocol for AI implementers](https://ngit.dev/protocol/nip-34/maintainers/ai-implementers).
This section describes the relay-specific read-side implementation.

Announcements carry maintainer listings in two formats:

- **Indexed role tags** (`M` lead, `m` co-maintainer). A tag may record
  history as alternating numeric start/end timestamps; `defer` is valid only
  as the final end boundary. It is currently active when it has no boundaries
  or its final valid boundary is a start. Ended, deferred, and malformed
  entries grant no authority - the history is only used to conclude a role
  has *ended*, never to grant authority for a past period. Both `M` and `m`
  grant maintainer authority, while active `M` records also form the lead
  path that roots the selected repository view. A pubkey may appear in
  multiple role tags: one of each letter records a role transition, and
  out-of-spec duplicates under the same letter are tolerated. Histories are
  consolidated - the pubkey is a maintainer while any valid `M`/`m` entry is
  active. An author who appears in no role tag is implicitly a maintainer for
  the repository's entire history.
- **Deprecated `maintainers` tag** (fallback). Ignored when `M`/`m` tags
  are present. Without any listing tags the author is the sole maintainer.
  A `u` (subordinate fork) tag has no effect on maintainership.

The moderator tag (`o`) grants no maintainership: moderators only affect
status-event authority, which this relay does not enforce (see
[decisions.md](decisions.md)). An `o` tag still counts as a role tag - it
suppresses the deprecated `maintainers` fallback, and a self-`o` entry is
a self-role, so a moderator-only author is not implicitly a maintainer.
`o` listings do not create maintainer invitations.

Authorization follows a reciprocal membership rule, computed per selected
announcement coordinate by
[`compute_membership`](src/git/authorization.rs):

Here, **selected coordinate** is the authorization term. **Owner view** remains
the storage term for the physical `<announcement-pubkey>/<identifier>.git`
repository selected by a URL; it does not imply that signer retains authority.

- A pubkey listed as a maintainer is only **invited** until its own
  announcement for the same identifier lists back an existing confirmed
  maintainer. Invited pubkeys' announcements are still fetched and accepted
  (that is how acceptance is noticed), but none of their events are
  authoritative.
- Confirmation is a fixpoint, so maintainers listed by other confirmed
  maintainers are reached recursively.
- The acknowledging announcement must assert an active role for its own
  author: an ended `M`/`m` self-entry means the pubkey has left, which
  takes precedence over assignments in other announcements. An author who
  appears in no role tag implicitly asserts maintainership.
- A valid active `M` path is followed to a terminal self-`M` before the
  reciprocal fixpoint is seeded. Without an active `M`, the selected author
  roots a legacy or deliberately leadless view while their own role is active.
  Missing, ambiguous, and cyclic explicit paths grant no state authority, and
  a former maintainer's forwarding coordinate does not restore that signer to
  the confirmed set.
- Parsing retains only a present-tense role view: current `M`/`m`
  maintainers, current `M` lead targets, and whether the announcement author
  currently claims maintainership. History markers are validated and consumed
  to derive that view, then discarded.
- Lead resolution records why a coordinate failed (missing selected or lead
  announcement, inactive selected author, incomplete or ambiguous path, or
  cycle). Authorization callers deliberately collapse every failure to an
  empty set while diagnostics and tests retain the distinction.

#### [`policy/state.rs`](src/nostr/policy/state.rs) - State Event Authorization

State events undergo authorization checks at multiple points:

```rust
/// State event authorization checks:
/// 1. Announcement must exist for the repository identifier
/// 2. Author must be a confirmed maintainer of an accepted announcement -
///    invited pubkeys are rejected
/// 3. Validated on arrival, announcement acceptance, and git data arrival
```

**Defense-in-depth authorization:**
- **On arrival** (StatePolicy): Initial authorization check
- **On announcement acceptance**: Purgatory re-evaluation of waiting state events
- **On git data arrival**: Final authorization before database save

### 5. Purgatory System ([`src/purgatory/`](../../src/purgatory/))

The purgatory system solves two related problems:

1. **"Which arrives first?"** — Either nostr events or git pushes can arrive in any order. Purgatory holds events awaiting their git data counterparts.
2. **Misleading empty repository announcements** — New announcements are held in purgatory until git data arrives, ensuring clients are never served announcements for repos with no content.

**Design Document**: See [`purgatory-design.md`](purgatory-design.md) for complete design specifications.

PR and PR-update events must include a commit value in their signed `c` tag.
Missing metadata is rejected as `invalid` before Git checks, so sync treats the
event as terminally accounted rather than repeatedly retrying an apparent
server failure. Events with commit metadata but unavailable Git objects remain
eligible for purgatory; Git and database failures remain retryable.

#### Architecture

```rust
/// Main purgatory structure with separate stores per event type
pub struct Purgatory {
    /// Announcement events (kind 30617) indexed by (owner, identifier)
    /// Held until git data proves content exists
    announcement_purgatory: DashMap<(PublicKey, String), AnnouncementPurgatoryEntry>,

    /// State events (kind 30618) indexed by repository identifier
    state_events: DashMap<String, Vec<StatePurgatoryEntry>>,
    
    /// PR events (kind 1617/1618) or placeholders indexed by event ID
    pr_events: DashMap<String, PrPurgatoryEntry>,
}
```

**Key Design Principles:**

1. **Separate Storage**: Each event type uses a different indexing strategy
   - Announcements: Indexed by `(pubkey, identifier)` (unique per owner)
   - State events: Indexed by `identifier` (multiple events can wait for same repo)
   - PR events: Indexed by `event_id` (one-to-one mapping)

2. **Announcement Purgatory**: New announcements are held until git data arrives
   - Bare repo created immediately so pushes can succeed
   - Announcement promoted to database only when git data proves content exists
   - Two-phase soft expiry: bare repo deleted at 30 min, event retained 24h for revival
   - De-list replacements evict an owner's entry only when they win NIP-01
     ordering: later timestamp, or lower event ID at the same timestamp.

3. **Late Binding**: State event refs are extracted at git push time, not event arrival
   - Enables flexible matching when pushes arrive out-of-order
   - Among matching states from authorized authors, push authorization selects
     the latest timestamp, breaking ties with the lowest event ID.
   - Helper functions in [`helpers.rs`](../../src/purgatory/helpers.rs) handle ref extraction

4. **Bidirectional Waiting**: Either side can arrive first
   - **Event-first**: Event waits for git push
   - **Git-first**: Placeholder created, waits for event

5. **Automatic Expiry**: 30-minute default expiry, extensible during processing
   - Background cleanup task runs every 60 seconds
   - Removes expired entries from all stores
   - Defers matching expiry while a concrete background Git sync is actively
     running; queued/backoff work receives no extension

6. **Pressure-aware Background Git Fan-out**: event-directed recovery begins
   with a one-second probe allowance of two remote Git passes per effective CPU
   - Healthy observation windows grow the allowance by 20% or one pass,
     whichever is greater, avoiding a lasting cap while giving the
     retrospective pressure signal time to reflect each preceding step
   - New CPU throttling or memory-high pressure reduces new admission to one
     pass while already-running work drains naturally
   - Linux services read their cgroup v2 constraints and pressure counters;
     other environments fall back to processor count and healthy-window growth
   - Existing per-domain limits remain responsible for being polite to each
     remote server
   - The probe and pressure gate prevent a cold sync spanning many domains from
     spawning enough Git processes to starve this relay's HTTP and WebSocket
     service
   - Foreground Git requests do not draw from this background-only limit

#### Data Types

See [`types.rs`](../../src/purgatory/types.rs) for complete definitions:

- **[`RefPair`](../../src/purgatory/types.rs:16)**: Ref name + object SHA pair
- **[`AnnouncementPurgatoryEntry`](../../src/purgatory/types.rs)**: Announcement with bare repo path, relays, and expiry
- **[`StatePurgatoryEntry`](../../src/purgatory/types.rs:29)**: State event with metadata
- **[`PrPurgatoryEntry`](../../src/purgatory/types.rs:52)**: PR event or placeholder with metadata

#### Integration Points

**Write Policy** ([`src/nostr/policy/`](../../src/nostr/policy/)):
- Announcement policy routes new announcements to purgatory; replacements accepted immediately
- State policy checks git data existence before adding to purgatory; checks purgatory announcements for authorization
- PR policy checks for placeholders before adding to purgatory
- Events return "purgatory: will not be served until git data arrives" message

**Git Handlers** ([`src/git/handlers.rs`](../../src/git/handlers.rs)):
- On git push: Promote announcement from purgatory to database if present
- On git push: Check purgatory for matching state events
- On refs/nostr/* push: Check purgatory for PR events or create placeholders
- Release events from purgatory when git data arrives
- Save released events to database

**Main.rs** ([`src/main.rs`](../../src/main.rs)):
- Creates `Arc<Purgatory>` at startup
- Passes purgatory to both write policy and git handlers
- Passes `RepositoryLifecycle` directly to HTTP git serving and deletion/recovery
- Spawns background cleanup task (60-second interval)

#### Thread Safety

- Uses `Arc<DashMap>` for lock-free concurrent access
- Safe to share between HTTP handlers, WebSocket handlers, and background tasks
- No blocking locks in hot paths

### 6. Configuration ([`src/config.rs`](src/config.rs))

```rust
pub struct Config {
    pub domain: String,
    pub owner_npub: String,
    pub relay_name: String,
    pub relay_description: String,
    pub git_data_path: PathBuf,
    pub relay_data_path: PathBuf,
    pub bind_address: SocketAddr,
    pub database_backend: DatabaseBackend,
}

pub enum DatabaseBackend {
    Lmdb,    // Default, production use
    NostrDb, // Alternative
    Memory,  // Testing
}
```

Configuration is loaded via **clap CLI > environment variables > .env > defaults**.

## Data Flow

### Push Operation Flow

```
1. Git Client → POST /<npub>/<id>.git/git-receive-pack
                ↓
2. HttpService routes to git::handlers::handle_receive_pack()
                ↓
3. Parse ref updates from request body (pkt-line format)
                ↓
4. Extract npub and identifier from URL
                ↓
5. authorization::get_state_authorization_for_selected_repo()
   ├─ Query database for announcements
   ├─ Resolve selected coordinate through its active lead path
   ├─ Compute confirmed maintainer set (reciprocal fixpoint)
   └─ Get latest authorized state
                ↓
6. authorization::validate_push_refs()
   ├─ Check each ref matches state
   └─ Validate refs/nostr/ pushes
                ↓
7. If VALID:
   ├─ Spawn git-receive-pack subprocess
   ├─ Stream request body to git stdin
   └─ Stream git stdout back to client
                ↓
8. If INVALID:
   └─ Return HTTP 403 with error message
```

### Repository Announcement Flow

```
1. Nostr Client → EVENT (Kind 30617)
                ↓
2. Nostr relay receives event
                ↓
3. Nip34WritePolicy::admit_event()
   ├─ Check if instance in clone tags
   ├─ Check if instance in relays tags
   ├─ OR: author is listed as a maintainer in a known announcement
   │       (invited maintainers accepted for acceptance discovery)
   └─ Accept or reject
                ↓
4. If ACCEPTED:
   ├─ Is there an active announcement for (pubkey, identifier) in DB?
   │  ├─ YES → Accept immediately (replacement, repo already proven)
   │  └─ NO  → Route to announcement purgatory
                ↓
5. Announcement Purgatory path:
   ├─ Bare Git repository created immediately at
   │  <git_data_path>/<npub>/<identifier>.git
   ├─ Announcement held in purgatory (not served to clients)
   └─ Awaiting git data to prove content exists
                ↓
6. When git data arrives (push or background sync):
   ├─ Announcement promoted from purgatory to database
   ├─ Event now served to clients
   └─ SyncManager upgrades to Full sync level
                ↓
7. If no git data within 30 minutes:
   ├─ Bare repo deleted (soft expiry)
   ├─ Event retained 24h for potential revival
   └─ Eventually discarded if no git data arrives
```

### State Event Flow

```
1. Nostr Client → EVENT (Kind 30618)
                ↓
2. Nostr relay receives event
                ↓
3. Nip34WritePolicy::admit_event()
   ├─ Check author is a confirmed maintainer (DB + purgatory announcements)
   ├─ Validate state structure
   └─ Accept or reject
                ↓
4. If ACCEPTED:
   ├─ Does git data already exist for this state?
   │  ├─ YES → Save to database immediately
   │  └─ NO  → Add to state purgatory
                ↓
5. State Purgatory path:
   ├─ Event held in purgatory (not served to clients)
   ├─ Enqueued for background git data sync (3 min delay)
   └─ Awaiting git push or background sync
                ↓
6. When git push arrives:
   ├─ Authorization checks both database AND purgatory
   ├─ If authorized via purgatory state: push proceeds
   ├─ After successful push: state event saved to database
   └─ Removed from purgatory
```

## Testing Strategy

See [test-strategy.md](../reference/test-strategy.md) for comprehensive testing documentation.

### Quick Overview

**Integration Tests** ([`tests/`](tests/)):

- Use [`TestRelay`](tests/common/relay.rs:14) fixture for automatic relay lifecycle
- Each test file in [`tests/`](tests/) covers a GRASP-01 requirement

**Audit Tests** ([`grasp-audit/`](grasp-audit/)):

- Reusable compliance testing for any GRASP implementation
- Spec-mirrored structure in [`grasp-audit/src/specs/grasp01/`](grasp-audit/src/specs/grasp01/)

```rust
// Example: tests/nip01_compliance.rs
#[tokio::test]
async fn test_nip01_websocket_connection() {
    let relay = TestRelay::start().await;
    // Test NIP-01 compliance...
    relay.stop().await;
}
```

## Performance Considerations

### 1. Async All The Way

- Use `tokio` for all I/O
- Non-blocking Git subprocess spawning via [`GitSubprocess`](src/git/subprocess.rs)
- Stream large pack files without buffering

### 2. Shared Database

- Single database instance shared between relay and Git handlers
- Direct queries for push authorization (no WebSocket round-trip)

### 3. Write Policy Caching

- Maintainer sets computed once per event validation
- State lookups use database indexes

## Proactive Sync (GRASP-02)

The ngit-grasp relay implements **Proactive Sync of Nostr Events**, which synchronizes repository data from external relays listed in 30617 repository announcements. This enables the relay to maintain complete repository graphs even when events are published to other listed relays.

**Key Features:**

- **Self-subscription** discovery - monitors own relay for announcements and
  root events to follow, attached in-process to the embedded relay rather than
  dialling the public listener (works identically under GRASP-08 private mode,
  whose auth gate would refuse a self-dial)
- **Startup reconstruction** stages persisted announcements and roots privately,
  then publishes complete Full entries before requesting sync. Purgatory
  cleanup cannot prune a partially reconstructed repository.
- **Three-way diff** (`compute_actions`) determines new subscriptions needed
- **Smart reconnection** - uses `since` filter for quick reconnects (<15 min), fresh sync otherwise
- **Health tracking** with exponential backoff for failing relays
- **Bounded connection workers** keep slow DNS and websocket handshakes out of
  the sync actor while limiting network pressure to eight concurrent attempts,
  with actual starts spaced at least 250 ms apart (no catch-up bursts)
- **Background history admission** keeps reconciliation, paced history groups,
  pagination and hydration retries outside the sync actor. At most eight jobs
  run globally and one per relay; live startup on other relays proceeds while
  a large source catches up. Pending batches register request IDs before sends
  and retain an admission barrier until the worker finishes, so early EOSE
  cannot confirm partial coverage. Reset/disconnect cancels stale jobs
- **Local reconciliation inventory** comes from the policy-controlled database
  and is passed explicitly to the intended relay's NIP-77 dry run. The SDK's
  separate seen-ID tracker remains isolated: reconciliation neither persists
  incoming payloads nor publishes local events
- **Hydration completion** accounts for local copies and retained dependencies
  even when the SDK suppresses repeat event notifications. Local lookups use
  bounded ID chunks without holding the pending-batch lock; absent IDs and
  failed storage lookups remain eligible for recovery
- **Missing-ID budgets** expire each ID after twelve unsuccessful fetches.
  Per-relay requests rotate pending IDs fairly and retain backoff for unresolved
  IDs even when unrelated IDs recover; expiry cannot falsely restore health
- **Daily sync** with random 23-25h timer to detect state drift
- **Filter consolidation** when incremental fragmentation exceeds the desired
  live-filter baseline by 70; rebuilds are deferred until in-flight batches
  drain so EOSE and purgatory work remain responsive
- **Rejected events index** - prevents wasteful broad re-fetching while retaining exact IDs for dependency recovery
- **Desired-source retention** keeps listed GRASP-02 relays retryable until
  repository work is actually confirmed, including StateOnly invitation sync
- **Bounded recursive related-event coverage** turns accepted descendants into
  the next remote query frontier through event and address references, with an
  eight-generation traversal and a configurable soft limit, defaulting to 500,
  for each subtree rooted at an event which directly tags a repository root.
  The local database deterministically reconstructs saturated branches after
  restart; relay connections retain independent progress and require no shared
  admission coordinator

**Architecture:**

```
┌─────────────────────────────────────────────────────────────┐
│                       SyncManager                            │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────┐              ┌──────────────────┐    │
│  │  SelfSubscriber  │──actions──▶  │  Main Event Loop │    │
│  │  (own relay)     │              │  (Arc<Mutex>)    │    │
│  └──────────────────┘              └────────┬─────────┘    │
│                                             │              │
│  ┌──────────────────┐              ┌────────▼─────────┐    │
│  │  Daily Timer     │──────────────▶  RelayConnection │    │
│  │  (23-25h random) │              │  per external    │    │
│  └──────────────────┘              │  relay           │    │
│                                    └──────────────────┘    │
│  ┌──────────────────┐                                      │
│  │  Health Tracker  │  Exponential backoff, dead detection │
│  │  (DashMap)       │                                      │
│  └──────────────────┘                                      │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Rejected Events Index (Two-Tier)                   │  │
│  │  ┌────────────────┐    ┌──────────────────────┐    │  │
│  │  │  Hot Cache     │    │  Cold Index          │    │  │
│  │  │  (2 min)       │    │  (7 days)            │    │  │
│  │  │  Full events   │    │  IDs + metadata      │    │  │
│  │  └────────────────┘    └──────────────────────┘    │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**Source Code:** [`src/sync/`](../../src/sync/)

For full design details, see [grasp-02-proactive-sync.md](grasp-02-proactive-sync.md).

GRASP-03 Sync+ is a default-on mailbox-discovery overlay on this manager. Set
`NGIT_SYNC_PLUS_ENABLED=false` to retain GRASP-02 sync without discovering
accepted root and descendant participants' NIP-65 read/write mailboxes; NIP-11
advertises `GRASP-03` only while the overlay is enabled. Exact thread
provenance scopes each mailbox to its accepted roots. Every peer-advertised
NIP-65 relay URL passes single-URL target hygiene
(`src/sync/target_hygiene.rs`), is canonicalized with the shared relay-key
semantics, and is deduplicated before selection; each author then contributes
at most four relays per purpose in published tag order, a hard internal
constant. Accepted root authors'
read/unmarked inboxes retain ordinary live/rotating GRASP-02 coverage. Wider
participant mailboxes use independent, history-only `fetch_events` workers:
at most one per relay, 32 process-wide, and one newly admitted relay per
maintenance pass. Once admitted, a successful relay drains its own stable
filter cursor without waiting for a global relay rotation. They reuse the
connection's ordinary pacing, subscription ledger, pagination and 30-second
per-page terminal timeout without installing permanent participant
subscriptions or coupling progress between relays. On public instances, each
accepted repository owner's and declared maintainer's bounded, sanitized
read/unmarked NIP-65 inboxes receive repository-scoped historical mailbox
probes covering their exact repositories and all locally known roots. This
discovers previously unknown roots and descendants that exist only on a
maintainer mailbox without broadening an ordinary participant mailbox, and it
is deliberately historical-only: owning or maintaining a repository never adds
that author's inbox relays to ordinary persistent live repository targets.
Private instances omit repository-coordinate mailbox expansion.

Descendant fallback drains one group per maintenance turn, then waits 60
seconds after completing the cycle (or a failed query) before starting again.
The delay uses a monotonic clock; successful cursors retain the 15-minute
overlap. A changed frontier is immediately eligible for its baseline. Routine
batch-completion details are debug logs so successful background polling does
not dominate the production journal.

The final connection admission check enforces both rate-limit and policy
pauses, including work queued by mailbox workers. Definitive policy CLOSED
responses update the shared pause on the independent control stream, without
waiting for event processing. Historic batches interrupted during admission
retire their started subscriptions and leave the complete set unconfirmed for
later recovery; completing a subset is not evidence of complete coverage.

Discovery source and mailbox scope also own connection retry state. The empty
relay checker and reconnect scheduler include that scope, including in-flight
fetches and future probe deadlines, without adding persistent subscriptions.
Healthy idle discovery sessions can retire after their fetch; failed or
policy-limited sessions retain their backoff until recovery or scope removal.
This prevents cleanup from erasing a failure every two seconds and allowing
discovery to dial the same unavailable endpoint from a fresh retry history.

### Rejected Events Index

The rejected events index solves two critical problems during sync:

1. **Negentropy sync efficiency**: Prevents repeatedly downloading events that will be rejected again
2. **Race condition resolution**: Enables immediate hot-cache re-processing or an exact-ID fetch after the full event expires

**Bounded Architecture:**

| Tier | Duration | Storage | Purpose |
|------|----------|---------|---------|
| Hot Cache | 2 minutes | Full events | Immediate re-processing when dependencies arrive |
| Cold Index | 7 days | Metadata only | Prevent re-fetch during negentropy sync |
| Related Dependency Index | 7 days | Full events + reference keys + relay hints | Retry policy orphans when either side of their relationship is accepted |

**Event Flow:**

```
Event Rejected (e.g., maintainer before owner announcement)
    │
    ├──▶ Store full event in Hot Cache (2 min expiry)
    └──▶ Store metadata in Cold Index (7 day expiry)
    
Reciprocal Invitation Arrives (owner announcement enters purgatory)
    │
    ├──▶ Keep dependency-resolvable IDs in Cold Index
    ├──▶ Re-process from Hot Cache when the full event remains available
    └──▶ Otherwise fetch only the retained IDs from the maintainer relay chain

Exact-ID Recovery
    │
    ├──▶ Connect to relay hints before starting recovery
    ├──▶ Query all connected maintainer-chain relays in parallel
    ├──▶ Process announcements before dependent state events
    └──▶ Remove IDs only after policy processing succeeds

Negentropy Sync
    │
    ├──▶ Exclude Cold Index IDs from "missing events" calculation
    └──▶ Count delivered dependency-pending events without removing their cache entries

Related Event Rejected as an Orphan
    │
    ├──▶ Retain the full event in the crash-safe checkpoint
    ├──▶ Match later accepted IDs and addresses in both directions
    ├──▶ Re-process an iterative closure of newly unblocked events
    └──▶ Keep retryable results pending; remove terminal outcomes
```

Exact-ID recovery runs as bounded background work, so a slow relay does not hold
the main sync-manager lock. Failed or empty requests retain their IDs and are
retried no more than once every 30 seconds. Each relay request has a five-second
timeout.

**Tracked Events:**

- Repository announcements (kind 30617) rejected for not listing this service or a dependency-resolvable maintainer validation failure
- State events (kind 30618) rejected for missing announcements or dependency-resolvable authorization failures
- Permanently invalid events classified as `Other` remain excluded and are not exact-refetched
- Related comments, reactions, zap requests, and other policy orphans are
  retained under fixed limits: 1,024 entries, 8 MiB total, 128 KiB per event,
  and 512 attempts per triggered closure

**Source Code:** [`src/sync/rejected_index.rs`](../../src/sync/rejected_index.rs)

## Contributor PR Submission (GRASP-06)

Optional endpoint at `/prs/<npub>/<identifier>.git`, gated on `NGIT_GRASP06_ENABLE` (default off). Contributors push `refs/nostr/<event-id>` for PR and PR Update events targeting any repository — even repos this relay has no accepted announcement for. The endpoint is unauthenticated at the HTTP level; validity is established by the signed PR / PR Update event and inline acceptance rules.

**Module layout:**

- [`src/grasp06/endpoint.rs`](../../src/grasp06/endpoint.rs) — URL parsing.
- [`src/grasp06/paths.rs`](../../src/grasp06/paths.rs) — on-disk path conventions under `<git_data_path>/prs/<hex>/<identifier>.git`.
- [`src/grasp06/fetch.rs`](../../src/grasp06/fetch.rs) — empty thin-view synthesis for `info/refs` and `git-upload-pack` against routes that do not yet exist on disk. Named refs stay empty while an existing identifier family supplies anonymous receive negotiation bases.
- [`src/grasp06/receive.rs`](../../src/grasp06/receive.rs) — `git-receive-pack` with thin-view init-on-push, strict `refs/nostr/<event-id>` ref-name validation, and per-ref post-push validation against the database and purgatory. A per-`(submitter, identifier)` `PrsPathState` protects view creation/removal; a per-family lease serializes object-producing work across related views. The same path state is consulted by PR-event policy and purgatory expiry, which only remove a `/prs/` ref or zero-ref view when `in_flight == 0`.
- [`src/grasp06/policy.rs`](../../src/grasp06/policy.rs) — strict clone-tag URL comparator used by the PR-event acceptance relaxation.
- [`src/grasp06/cleanup.rs`](../../src/grasp06/cleanup.rs) — one-shot startup scan over `<git_data_path>/prs/` that removes zero-ref bare repos left behind by a previous run (crash mid-push, crash mid-cleanup, or shutdown with unresolved scoped placeholders). Runs before the HTTP server starts accepting requests; no locking is needed because nothing else is touching `/prs/` yet.

`/prs/` repos are intentionally isolated from other subsystems: empty-repo cleanup skips the `/prs/` subtree, the proactive-sync subsystem never discovers them because subscriptions are built from DB-resident announcements, and the standard repo landing page guards against ever matching a `/prs/` path. Full design: [GRASP-06 Contributor Pull Request Submission](grasp-06-contributor-pr-submission.md). Operator how-to: [Enable GRASP-06](../how-to/enable-grasp-06.md).

## Private Service Authentication (GRASP-08)

Private mode is an optional access layer around the normal GRASP runtime. A
single `PrivateAccess` set is shared by the HTTP and WebSocket services and
the announcement admission policy. Push authorization remains the GRASP-01
policy; a private credential proves service membership but never grants push
rights. The effective set combines operator-configured members with NIP-11
owner pubkeys learned for relays referenced by accepted announcements,
provided those relays' NIP-11 also advertises GRASP-08 (a public relay's
owner gains nothing legitimate from private membership).
Purgatory-only announcements are excluded. Reconciliation reuses the accepted
repository index and the NIP-11 fetch already performed once per connection
session, so private mode adds neither outbound connections nor subscriptions.

Because accepted announcements drive membership, announcement admission is
itself membership-gated in private mode: a kind-30617 event is only admitted
when its author is a current effective member at admission time, on every
arrival path (direct publish, sync import, purgatory promotion). Non-member
announcements are rejected through the normal announcement rejection
machinery. State events (kind 30618) keep the GRASP-01 maintainer rules, and
removal is non-retroactive — repositories admitted while their author was a
member remain hosted until the operator curates them.

For Nostr, Hyper completes the public WebSocket upgrade and a message-level
proxy sends and validates NIP-42 authentication before a connection reaches
`LocalRelay`. Missing authentication uses the `auth-required:` prefix and a
valid authentication by a nonmember uses `restricted:`. Once authenticated,
the proxy bridges messages through an in-memory WebSocket pair to
`LocalRelay`. Keeping the access check outside `nostr-relay-builder` is
necessary because its query and write policies do not receive the
authenticated session pubkey.

For Git, authentication runs before repository existence checks or request
body collection. The signed NIP-98 event names the canonical repository root
and method `GET`; that credential is reusable for GET, HEAD, and POST requests
to the repository root and Smart HTTP subpaths for its 60-second validity
window. Payload tags and replay protection are intentionally not applied.
Every authentication failure is the same empty `401 Unauthorized` response,
preventing unauthenticated repository enumeration.

Private mode advertises GRASP-08 plus NIP-42 and NIP-98 in NIP-11. It is
incompatible with GRASP-06 because that extension deliberately exposes an
unauthenticated contributor write surface. It also suppresses relay-owner
identity publication: the kind 0/10002 events are seeded and served locally
but never sent to the configured user-index relays, so a private relay does
not advertise its existence.

Outbound, every sync connection (public or private instance) answers NIP-42
challenges with the relay owner key when available; a `restricted:` refusal
after authentication parks the subscription via the existing policy-refusal
machinery. Peers advertising GRASP-08 in NIP-11 split by our own mode: a
public instance detects them with a pre-dial NIP-11 fetch and parks them
without ever opening the WebSocket, while a private instance treats them as
peers — NIP-42 on the WebSocket plus the GRASP-08 repository-root NIP-98
credential on purgatory Git fetches from that peer's host, both signed with
the relay owner key. Relays without a readable `supported_grasps` are
ordinary sync targets. See
[GRASP-08 design](grasp-08-private-service.md#outbound-authentication-and-sync-policy).

One process currently represents one private collaborator service. Operators
can run several independently configured instances for different groups. Fleet
provisioning and lifecycle automation are deliberately left to a later change;
they are deployment conveniences rather than part of the authentication
boundary implemented here.

## Future Extensions

### GRASP-02: Proactive Sync

GRASP-02 is only partially implemented. still outstanding is the proactive sync of git data for 1. state event and 2. PRs / PR Update refs.

### GRASP-05: Archive

Relax the write policy to accept all repository announcements regardless of clone/relays tags.

## Deployment

The runtime remains one binary plus Git, but persistence, identity, proxying,
and single-writer behavior are part of the production boundary. The normative
[deployment contract](../reference/deployment-contract.md) owns those shared
requirements.

Supported artifacts are maintained alongside their operating guides:

- the root `Dockerfile` and Compose configurations;
- `deploy/systemd/ngit-grasp.service` for conventional Linux;
- `nix/module.nix` for declarative NixOS instances; and
- managed-host templates for single-instance deployments.

See the [deployment chooser](../how-to/deploy.md) rather than copying an
illustrative container or service definition from this architecture document.

## Security Considerations

1. **Input Validation**: All npub/identifier inputs must be validated
2. **Path Traversal**: Prevent directory traversal in repository paths
3. **DoS Protection**: Rate limiting on both HTTP and WebSocket
4. **Resource Limits**: Limit pack file sizes, event sizes
5. **Nostr Event Validation**: Strict signature verification (handled by nostr-relay-builder)

## Conclusion

ngit-grasp uses inline authorization at the HTTP handler level, giving full control over request handling, WebSocket upgrades, and CORS headers while maintaining full GRASP-01 compliance. The purgatory system ensures that only repositories with actual git content are served to clients, and that events and git data are always consistent when released to the database.

## Related Documentation

- [Inline Authorization Explanation](inline-authorization.md) - Why we chose this approach
- [GRASP-02 Proactive Sync Design](grasp-02-proactive-sync.md) - Current production sync implementation
- [Test Strategy](../reference/test-strategy.md) - Comprehensive testing documentation
- [GRASP-01 Implementation Learnings](../learnings/grasp-01-implementation.md) - Patterns and lessons learned
