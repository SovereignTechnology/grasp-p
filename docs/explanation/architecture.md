# ngit-grasp Architecture

## Executive Summary

`ngit-grasp` implements the GRASP protocol in Rust with **inline authorization** rather than Git hooks. Git push operations are intercepted and validated at the HTTP handler level before reaching the Git repository, eliminating the need for pre-receive hooks.

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
- Initialize Nostr relay builder with custom [`Nip34WritePolicy`](src/nostr/builder.rs:51)
- Set up shared storage (LMDB or Memory), purgatory, sync manager, and
  background maintenance tasks
- Serve HTTP + WebSocket until a caller-supplied shutdown future
  resolves, then persist state (purgatory, rejected-events cache,
  placeholder ref cleanup) and stop background tasks

**Key Dependencies:**

```rust
hyper = "1"
tokio = { version = "1", features = ["full"] }
nostr-relay-builder = "0.45.0-alpha.3"
nostr-sdk = "0.45.0-alpha.3"
nostr-lmdb = "0.45.0-alpha.3"
```

### 2. HTTP Module ([`src/http/mod.rs`](src/http/mod.rs))

**Responsibilities:**

- Route HTTP requests to appropriate handlers
- WebSocket upgrade for Nostr relay at `/`
- Git Smart HTTP endpoints at `/<npub>/<identifier>.git/*`
- Landing pages and NIP-11 document serving
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

#### [`authorization.rs`](src/git/authorization.rs) - Push Validation

**Core Logic:**

```rust
/// Get authorization info for a repository owner
pub async fn get_authorization_for_owner(
    database: &SharedDatabase,
    pubkey: &PublicKey,
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
///   EXCEPTION: Recursive maintainer announcements are accepted even without
///   listing the service, to enable maintainer chain discovery and GRASP-02 sync
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

#### [`policy/state.rs`](src/nostr/policy/state.rs) - State Event Authorization

State events undergo authorization checks at multiple points:

```rust
/// State event authorization checks:
/// 1. Announcement must exist for the repository identifier
/// 2. Author must be in maintainer set of accepted announcement
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

3. **Late Binding**: State event refs are extracted at git push time, not event arrival
   - Enables flexible matching when pushes arrive out-of-order
   - Helper functions in [`helpers.rs`](../../src/purgatory/helpers.rs) handle ref extraction

4. **Bidirectional Waiting**: Either side can arrive first
   - **Event-first**: Event waits for git push
   - **Git-first**: Placeholder created, waits for event

5. **Automatic Expiry**: 30-minute default expiry, extensible during processing
   - Background cleanup task runs every 60 seconds
   - Removes expired entries from all stores

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
5. authorization::get_authorization_for_owner()
   ├─ Query database for announcements
   ├─ Build recursive maintainer set
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
   ├─ OR: Check if recursive maintainer
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
   ├─ Check author is in maintainer set (DB + purgatory announcements)
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

- **Self-subscription** discovery - monitors own relay for announcements and root events to follow
- **Three-way diff** (`compute_actions`) determines new subscriptions needed
- **Smart reconnection** - uses `since` filter for quick reconnects (<15 min), fresh sync otherwise
- **Health tracking** with exponential backoff for failing relays
- **Daily sync** with random 23-25h timer to detect state drift
- **Filter consolidation** when count exceeds 70 to prevent subscription
  explosion; rebuilds are deferred until in-flight batches drain so EOSE and
  purgatory work remain responsive
- **Rejected events index** - prevents wasteful broad re-fetching while retaining exact IDs for dependency recovery
- **Desired-source retention** keeps listed GRASP-02 relays retryable until
  repository work is actually confirmed, including StateOnly invitation sync

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

For full design details, see [grasp-02-proactive-sync-v4.md](grasp-02-proactive-sync-v4.md).

### Rejected Events Index

The rejected events index solves two critical problems during sync:

1. **Negentropy sync efficiency**: Prevents repeatedly downloading events that will be rejected again
2. **Race condition resolution**: Enables immediate hot-cache re-processing or an exact-ID fetch after the full event expires

**Two-Tier Architecture:**

| Tier | Duration | Storage | Purpose |
|------|----------|---------|---------|
| Hot Cache | 2 minutes | Full events | Immediate re-processing when dependencies arrive |
| Cold Index | 7 days | Metadata only | Prevent re-fetch during negentropy sync |

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
    └──▶ Exclude Cold Index IDs from "missing events" calculation
```

Exact-ID recovery runs as bounded background work, so a slow relay does not hold
the main sync-manager lock. Failed or empty requests retain their IDs and are
retried no more than once every 30 seconds. Each relay request has a five-second
timeout.

**Tracked Events:**

- Repository announcements (kind 30617) rejected for not listing this service or a dependency-resolvable maintainer validation failure
- State events (kind 30618) rejected for missing announcements or dependency-resolvable authorization failures
- Permanently invalid events classified as `Other` remain excluded and are not exact-refetched

**Source Code:** [`src/sync/rejected_index.rs`](../../src/sync/rejected_index.rs)

## Contributor PR Submission (GRASP-06)

Optional endpoint at `/prs/<npub>/<identifier>.git`, gated on `NGIT_GRASP06_ENABLE` (default off). Contributors push `refs/nostr/<event-id>` for PR and PR Update events targeting any repository — even repos this relay has no accepted announcement for. The endpoint is unauthenticated at the HTTP level; validity is established by the signed PR / PR Update event and inline acceptance rules.

**Module layout:**

- [`src/grasp06/endpoint.rs`](../../src/grasp06/endpoint.rs) — URL parsing.
- [`src/grasp06/paths.rs`](../../src/grasp06/paths.rs) — on-disk path conventions under `<git_data_path>/prs/<hex>/<identifier>.git`.
- [`src/grasp06/fetch.rs`](../../src/grasp06/fetch.rs) — empty-repo synthesis for `info/refs` and `git-upload-pack` against repos that don't yet exist on disk.
- [`src/grasp06/receive.rs`](../../src/grasp06/receive.rs) — `git-receive-pack` with init-on-push, strict `refs/nostr/<event-id>` ref-name validation, and per-ref post-push validation against the database and purgatory. Uses a per-`(submitter, identifier)` `PrsPathState` (mutex + `in_flight` counter) so concurrent pushes to the same path proceed in parallel: the mutex is held only for init+register and decrement+end-of-push cleanup, not across `git-receive-pack` itself. The same state is consulted (with `try_lock` in synchronous contexts) by the PR-event policy and the purgatory expiry sweep, which only remove a `/prs/` ref or zero-ref bare repo when `in_flight == 0`.
- [`src/grasp06/policy.rs`](../../src/grasp06/policy.rs) — strict clone-tag URL comparator used by the PR-event acceptance relaxation.
- [`src/grasp06/cleanup.rs`](../../src/grasp06/cleanup.rs) — one-shot startup scan over `<git_data_path>/prs/` that removes zero-ref bare repos left behind by a previous run (crash mid-push, crash mid-cleanup, or shutdown with unresolved scoped placeholders). Runs before the HTTP server starts accepting requests; no locking is needed because nothing else is touching `/prs/` yet.

`/prs/` repos are intentionally isolated from other subsystems: empty-repo cleanup skips the `/prs/` subtree, the proactive-sync subsystem never discovers them because subscriptions are built from DB-resident announcements, and the standard repo landing page guards against ever matching a `/prs/` path. Full design: [GRASP-06 Contributor Pull Request Submission](grasp-06-contributor-pr-submission.md). Operator how-to: [Enable GRASP-06](../how-to/enable-grasp-06.md).

## Future Extensions

### GRASP-02: Proactive Sync

GRASP-02 is only partially implemented. still outstanding is the proactive sync of git data for 1. state event and 2. PRs / PR Update refs.

### GRASP-05: Archive

Relax the write policy to accept all repository announcements regardless of clone/relays tags.

## Deployment

### Single Binary

```bash
cargo build --release
./target/release/ngit-grasp --domain example.com --owner-npub npub1...
```

### Docker

```dockerfile
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/ngit-grasp /usr/local/bin/
EXPOSE 7334
CMD ["ngit-grasp"]
```

### Systemd

```ini
[Unit]
Description=ngit-grasp GRASP server
After=network.target

[Service]
Type=simple
User=git
WorkingDirectory=/opt/ngit-grasp
EnvironmentFile=/opt/ngit-grasp/.env
ExecStart=/usr/local/bin/ngit-grasp
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

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
- [GRASP-02 Proactive Sync v4 Design](grasp-02-proactive-sync-v4.md) - Current production sync implementation
- [Test Strategy](../reference/test-strategy.md) - Comprehensive testing documentation
- [GRASP-01 Implementation Learnings](../learnings/grasp-01-implementation.md) - Patterns and lessons learned
