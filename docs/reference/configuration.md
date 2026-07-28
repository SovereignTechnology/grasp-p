# Reference: Configuration

**Purpose:** Complete reference for all ngit-grasp configuration options  
**Audience:** Operators and developers

---

## Configuration Methods

ngit-grasp can be configured via:

1. **Environment variables** (recommended for deployment)
2. **`.env` file** (recommended for development)
3. **Command-line arguments** (planned, not yet implemented)

Configuration is loaded at startup and validated before the server starts.

---

## Environment Variables

### Server Configuration

#### `NGIT_BIND_ADDRESS`

**Description:** Address and port for the HTTP server to bind to  
**Type:** String (IP:PORT format)  
**Default:** `127.0.0.1:7334`  
**Required:** No

**Examples:**

```bash
# Localhost only (development)
NGIT_BIND_ADDRESS=127.0.0.1:7334

# All interfaces (production)
NGIT_BIND_ADDRESS=0.0.0.0:7334

# IPv6
NGIT_BIND_ADDRESS=[::1]:7334

# Custom port
NGIT_BIND_ADDRESS=127.0.0.1:3000
```

**Notes:**

- Use `127.0.0.1` for local development
- Use `0.0.0.0` for production (behind reverse proxy)
- Ensure firewall rules allow the port

---

#### `NGIT_DOMAIN`

**Description:** Public domain name for this GRASP instance  
**Type:** String (domain name)  
**Default:** None  
**Required:** Yes

**Examples:**

```bash
NGIT_DOMAIN=gitnostr.com
NGIT_DOMAIN=git.example.org
NGIT_DOMAIN=localhost:7334  # Development only
```

**Used for:**

- NIP-11 relay information document
- Generating repository URLs
- CORS configuration
- Webhook URLs (future)

**Notes:**

- Must be accessible from the internet for production
- Include port if non-standard (e.g., `localhost:7334`)
- Used in repository clone URLs: `https://{NGIT_DOMAIN}/{npub}/{repo}.git`
- **GRASP-P exact-host checks (Phase-4b A3, src/private/host.rs):** a
  **port-less** `NGIT_DOMAIN` matches registration `relays`/`server` tag
  URLs on **any** port (host alone). Consequence: a `server` tag carrying
  the wrong port on this host still counts as "listing this node" at
  admission and is then **self-excluded from this node's mirror peer set** —
  if every listed tag resolves to this node, the mirror has no peer
  (`ngit_private_mirror_failed_total{reason="no_peer"}`, backlog visible via
  the `ngit_private_mirror_lag_blobs` gauge) instead of a fetch attempt
  failing. Spell the port explicitly (`host:port`) when the blob endpoint
  is not the scheme default; a ported `NGIT_DOMAIN` requires tag URLs to
  match that effective port exactly.
- **IPv6:** always use the bracketed form (`[::1]`, `[2001:db8::1]:7334`).
  A bare unbracketed IPv6 `NGIT_DOMAIN` (e.g. `::1`) is degenerate — the
  authority splitter misparses it into a garbage host/port pair and the
  exact-host checks never match.

---

### Nostr Relay Configuration

#### `NGIT_OWNER_NPUB`

**Description:** Nostr public key (npub format) of the relay operator  
**Type:** String (npub1... format)  
**Default:** None  
**Required:** Yes

**Examples:**

```bash
NGIT_OWNER_NPUB=npub1alice...
```

**Used for:**

- NIP-11 relay information document
- Contact information
- Administrative operations (future)

**Notes:**

- Must be valid npub format (starts with `npub1`)
- Can be generated with Nostr tools
- Publicly visible in relay metadata

---

#### `NGIT_RELAY_NAME`

**Description:** Human-readable name for this relay  
**Type:** String  
**Default:** `"ngit-grasp relay"`  
**Required:** No

**Examples:**

```bash
NGIT_RELAY_NAME="GitNostr Community Relay"
NGIT_RELAY_NAME="Alice's GRASP Server"
```

**Used for:**

- NIP-11 relay information document
- Client display
- Relay discovery

---

#### `NGIT_RELAY_DESCRIPTION`

**Description:** Description of this relay's purpose and policies  
**Type:** String  
**Default:** `"A GRASP-compliant Git relay"`  
**Required:** No

**Examples:**

```bash
NGIT_RELAY_DESCRIPTION="Public GRASP relay for open source projects"
NGIT_RELAY_DESCRIPTION="Private relay for ACME Corp repositories"
```

**Used for:**

- NIP-11 relay information document
- User information
- Relay selection

---

### Storage Configuration

#### `NGIT_GIT_DATA_PATH`

**Description:** Directory path for storing Git repositories  
**Type:** String (filesystem path)  
**Default:** `./data/git`  
**Required:** No

**Examples:**

```bash
# Relative path (development)
NGIT_GIT_DATA_PATH=./data/git

# Absolute path (production)
NGIT_GIT_DATA_PATH=/var/lib/ngit-grasp/git

# Custom location
NGIT_GIT_DATA_PATH=/mnt/storage/git-repos
```

**Storage structure:**

```
{NGIT_GIT_DATA_PATH}/
  ├── {npub1}/
  │   ├── {repo1}.git/
  │   │   ├── objects/
  │   │   ├── refs/
  │   │   └── ...
  │   └── {repo2}.git/
  └── {npub2}/
      └── ...
```

**Notes:**

- Directory must be writable by ngit-grasp process
- Ensure sufficient disk space
- Consider backup strategy
- Use fast storage for better performance

---

#### `NGIT_RELAY_DATA_PATH`

**Description:** Directory path for storing Nostr events and relay data  
**Type:** String (filesystem path)  
**Default:** `./data/relay`  
**Required:** No

**Examples:**

```bash
# Relative path (development)
NGIT_RELAY_DATA_PATH=./data/relay

# Absolute path (production)
NGIT_RELAY_DATA_PATH=/var/lib/ngit-grasp/relay

# Separate disk
NGIT_RELAY_DATA_PATH=/mnt/ssd/relay-data
```

**Storage structure:**

```
{NGIT_RELAY_DATA_PATH}/
  ├── events/
  │   └── {event-id}.json
  ├── indexes/
  │   ├── by-kind/
  │   ├── by-author/
  │   └── by-tag/
  └── metadata/
```

**Notes:**

- Directory must be writable
- Consider SSD for better query performance
- Size grows with event count
- Implement retention policy for production

---

#### `NGIT_DATABASE_BACKEND`

**Description:** Database backend type for storing Nostr events
**Type:** String (enum: memory, lmdb)
**Default:** `lmdb`
**Required:** No

**Valid Values:**

- `lmdb` - LMDB backend (persistent, general purpose)
- `memory` - In-memory database (fastest, no persistence)

**Examples:**

```bash
# Production (default, persistent)
NGIT_DATABASE_BACKEND=lmdb

# Development/testing (no persistence)
NGIT_DATABASE_BACKEND=memory
```

**Comparison:**

| Backend | Persistence | Performance | Use Case                     |
| ------- | ----------- | ----------- | ---------------------------- |
| lmdb    | Yes         | High        | Production (general purpose) |
| memory  | No          | Fastest     | Development, testing         |

**Notes:**

- `memory` backend loses all data on restart
- `lmdb` backend uses `NGIT_RELAY_DATA_PATH` for storage
- Default `memory` backend suitable for development and testing only
- Production deployments should use `lmdb`

---

### Proactive Sync Configuration (GRASP-02)

These options configure the proactive sync feature that synchronizes events from other relays.

#### `NGIT_SYNC_BOOTSTRAP_RELAY_URL`

**Description:** URL of the bootstrap relay to initially sync events from
**Type:** String (WebSocket URL)
**Default:** None (relay discovery only)
**Required:** No

**Examples:**

```bash
# Sync from a public relay
NGIT_SYNC_BOOTSTRAP_RELAY_URL=wss://relay.example.com

# Sync from another GRASP relay
NGIT_SYNC_BOOTSTRAP_RELAY_URL=wss://git.nostr.dev

# Local testing
NGIT_SYNC_BOOTSTRAP_RELAY_URL=ws://127.0.0.1:8081
```

**Notes:**

- Bootstrap relay provides initial sync source on startup
- Additional relays are **automatically discovered** from repository announcements that list our service
- Even without a bootstrap relay, sync will discover relays from stored announcements
- Synced events go through the same validation as directly-submitted events
- Use WebSocket protocol (`ws://` or `wss://`) or defaults to wss://

---

#### `NGIT_SYNC_MAX_BACKOFF_SECS`

**Description:** Maximum backoff time in seconds for sync relay reconnection
**Type:** Integer (seconds)
**Default:** `3600` (1 hour)
**Required:** No

**Examples:**

```bash
# Default: 1 hour max backoff
NGIT_SYNC_MAX_BACKOFF_SECS=3600

# Aggressive: 5 minute max backoff
NGIT_SYNC_MAX_BACKOFF_SECS=300

# Conservative: 2 hour max backoff
NGIT_SYNC_MAX_BACKOFF_SECS=7200
```

**Notes:**

- Backoff starts at 5 seconds and doubles on each failure
- Capped at this maximum value
- After 24 hours of failures, relay is marked "dead" and retried daily
- Lower values mean more reconnection attempts

---

#### `NGIT_SYNC_STARTUP_DELAY_SECS`

**Description:** Delay in seconds before running startup catchup
**Type:** Integer (seconds)
**Default:** `30`
**Required:** No

**Examples:**

```bash
# Default: 30 second delay
NGIT_SYNC_STARTUP_DELAY_SECS=30

# Quick startup (testing)
NGIT_SYNC_STARTUP_DELAY_SECS=5

# Production: longer warm-up
NGIT_SYNC_STARTUP_DELAY_SECS=60
```

**Notes:**

- Allows connections to stabilize before catchup
- Reduces load on remote relays at startup
- Set to 0 for immediate catchup (not recommended)

---

#### `NGIT_SYNC_RECONNECT_DELAY_SECS`

**Description:** Delay in seconds before running catchup after reconnection
**Type:** Integer (seconds)
**Default:** `10`
**Required:** No

**Examples:**

```bash
# Default: 10 second delay
NGIT_SYNC_RECONNECT_DELAY_SECS=10

# Quick reconnect catchup
NGIT_SYNC_RECONNECT_DELAY_SECS=5

# Conservative
NGIT_SYNC_RECONNECT_DELAY_SECS=30
```

**Notes:**

- Prevents rate limiting from remote relays
- Applied after each successful reconnection
- Only catches up on recent events (see lookback days)

---

#### `NGIT_SYNC_RECONNECT_LOOKBACK_DAYS`

**Description:** Number of days to look back for reconnect catchup
**Type:** Integer (days)
**Default:** `3`
**Required:** No

**Examples:**

```bash
# Default: 3 days lookback
NGIT_SYNC_RECONNECT_LOOKBACK_DAYS=3

# Short lookback (frequent reconnects expected)
NGIT_SYNC_RECONNECT_LOOKBACK_DAYS=1

# Extended lookback
NGIT_SYNC_RECONNECT_LOOKBACK_DAYS=7
```

**Notes:**

- Limits catchup queries to recent events only
- Reduces load compared to full historical sync
- Balance between completeness and performance
- Longer lookback useful for less reliable connections

---

### Rejected Events Index Configuration

These options configure the two-tier rejected events index that prevents wasteful re-fetching during sync and enables race condition resolution.

#### `NGIT_REJECTED_HOT_CACHE_DURATION_SECS`

**Description:** Duration in seconds to retain full events in hot cache for immediate re-processing
**Type:** Integer (seconds)
**Default:** `120` (2 minutes)
**Required:** No

**Examples:**

```bash
# Default: 2 minute hot cache
NGIT_REJECTED_HOT_CACHE_DURATION_SECS=120

# Shorter window (1 minute)
NGIT_REJECTED_HOT_CACHE_DURATION_SECS=60

# Longer window (5 minutes)
NGIT_REJECTED_HOT_CACHE_DURATION_SECS=300
```

**Notes:**

- Hot cache stores full event objects for immediate re-processing when dependencies arrive
- Events expire from hot cache after this duration and move to cold index
- Shorter durations reduce memory usage but may miss dependency arrivals
- Longer durations increase memory but improve race condition resolution
- Memory impact: ~200 KB typical, ~20 MB worst case

---

#### `NGIT_REJECTED_COLD_INDEX_EXPIRY_SECS`

**Description:** Duration in seconds to retain event metadata in cold index for negentropy sync exclusion
**Type:** Integer (seconds)
**Default:** `604800` (7 days)
**Required:** No

**Examples:**

```bash
# Default: 7 day cold index
NGIT_REJECTED_COLD_INDEX_EXPIRY_SECS=604800

# Shorter retention (3 days)
NGIT_REJECTED_COLD_INDEX_EXPIRY_SECS=259200

# Longer retention (14 days)
NGIT_REJECTED_COLD_INDEX_EXPIRY_SECS=1209600
```

**Notes:**

- Cold index stores only metadata (event ID, pubkey, identifier, rejection reason)
- Prevents re-downloading rejected events during negentropy sync
- Entries automatically cleaned up daily
- Longer durations prevent more wasteful re-fetching but use slightly more memory
- Memory impact: ~1 MB typical

---

### Holding DB and Deletion-Request Cleanup Configuration

These options control retention for deleted events archived in the holding database and the shared cleanup cadence for holding and deletion-request retention records.

#### `NGIT_HOLDING_RETENTION_SECS`

**Description:** How long deleted events are retained in the holding DB before expiration cleanup removes them
**Type:** Integer (seconds)
**Default:** `7776000` (90 days)
**Required:** No

**Examples:**

```bash
# Default: 90 days
NGIT_HOLDING_RETENTION_SECS=7776000

# Short retention (30 days)
NGIT_HOLDING_RETENTION_SECS=2592000
```

**Notes:**

- Must be greater than 0
- Used by both startup catch-up cleanup and periodic cleanup passes

---

#### `NGIT_HOLDING_CLEANUP_INTERVAL_SECS`

**Description:** Interval between periodic holding DB expiration cleanup passes and deletion-request retention cleanup passes
**Type:** Integer (seconds)
**Default:** `86400` (24 hours)
**Required:** No

**Examples:**

```bash
# Default: daily cleanup
NGIT_HOLDING_CLEANUP_INTERVAL_SECS=86400

# Every 6 hours
NGIT_HOLDING_CLEANUP_INTERVAL_SECS=21600
```

**Notes:**

- Must be greater than 0
- Smaller values clean up expired records sooner at the cost of more background work
- This interval determines how soon expired records are observed and physically removed. A deletion request may remain queryable from Main until the next cleanup pass, but admission-gate eligibility still ends at its timestamp-derived deadline; this cleanup latency does not reset or extend the lifecycle.

---

### GRASP-05 Archive Configuration

These options enable archive/mirror/backup mode per the GRASP-05 specification.

#### `NGIT_ARCHIVE_ALL`

**Description:** Accept all repository announcements regardless of whether they list this instance  
**Type:** Boolean  
**Default:** `false`  
**Required:** No

**Examples:**

```bash
# Enable archive-all mode (⚠️  WARNING: Storage risk)
NGIT_ARCHIVE_ALL=true

# Disable (default - GRASP-01 strict mode)
NGIT_ARCHIVE_ALL=false
```

**Security Warning:** When enabled, any repository can be mirrored to this relay, potentially causing storage and bandwidth exhaustion. Only enable if you have unlimited resources and trust the relay network.

**Notes:**

- Archived repositories are read-only (pushes rejected)
- Full sync enabled (both git data and Nostr events)
- Takes precedence over whitelist (accepts everything)

---

#### `NGIT_ARCHIVE_WHITELIST`

**Description:** Comma-separated list of repositories/pubkeys/identifiers to archive  
**Type:** String (comma-separated)  
**Default:** (empty)  
**Required:** No

**Formats:**

- `<npub>` - Archive all repos from this pubkey
- `<npub>/<identifier>` - Archive specific repo from specific pubkey
- `<identifier>` - Archive repos with this identifier from any pubkey

**Examples:**

```bash
# Archive all repos from Alice
NGIT_ARCHIVE_WHITELIST=npub1alice23

# Archive specific repos
NGIT_ARCHIVE_WHITELIST=npub1alice23/linux,npub1bob23/bitcoin-core

# Archive by identifier (any pubkey)
NGIT_ARCHIVE_WHITELIST=bitcoin-core,linux,rust

# Mixed formats
NGIT_ARCHIVE_WHITELIST=npub1alice23...,npub1bob23.../linux,bitcoin-core
```

**Validation:**

- Npub entries are validated at startup (invalid npub = server fails to start)
- Identifier entries accept any string
- Whitespace is trimmed
- Empty entries are ignored

**Security Notes:**

- Identifier-only format (`bitcoin-core`) matches ANY pubkey
- Use `npub/identifier` format for high-value archives
- Whitelist is static (restart required to change)
- Future: Dynamic management via API

---

#### `NGIT_ARCHIVE_GRASP_SERVICES`

**Description:** Comma-separated list of GRASP server domains to archive  
**Type:** String (comma-separated domain names)  
**Default:** (empty)  
**Required:** No

**Format:**
- `<domain>` - Archive all repositories from this GRASP server domain
- **Must be bare domains only** (e.g., `git.example.com`, NOT `wss://git.example.com`)
- Matching extracts domains from announcement clone URLs and compares them exactly (case-sensitive)

**Examples:**

```bash
# Archive all repos from a single GRASP server
NGIT_ARCHIVE_GRASP_SERVICES=git.example.com

# Archive repos from multiple GRASP servers
NGIT_ARCHIVE_GRASP_SERVICES=git.example.com,git.nostr.dev,relay.gitnostr.com

# Archive from localhost (testing)
NGIT_ARCHIVE_GRASP_SERVICES=localhost:7334
```

**Validation:**

- Domain entries must be bare domains without scheme prefixes (ws://, wss://, https://, etc.)
- Whitespace is trimmed
- Empty entries are ignored
- **Mutually exclusive** with `NGIT_ARCHIVE_ALL` and `NGIT_ARCHIVE_WHITELIST`

**Security Notes:**

- Archives ALL repositories from the specified GRASP server domains
- Use with caution - ensure you trust the GRASP servers you're archiving from
- Storage requirements depend on the size of repositories on the archived servers
- Automatically sets `NGIT_ARCHIVE_READ_ONLY=true` by default

**Error Conditions:**

```bash
# ERROR: Cannot use with NGIT_ARCHIVE_ALL
NGIT_ARCHIVE_GRASP_SERVICES=git.example.com
NGIT_ARCHIVE_ALL=true
# → Server fails to start: "NGIT_ARCHIVE_GRASP_SERVICES cannot be used with
#    NGIT_ARCHIVE_ALL=true. These options are mutually exclusive."

# ERROR: Cannot use with NGIT_ARCHIVE_WHITELIST
NGIT_ARCHIVE_GRASP_SERVICES=git.example.com
NGIT_ARCHIVE_WHITELIST=npub1alice...
# → Server fails to start: "NGIT_ARCHIVE_GRASP_SERVICES cannot be used with
#    NGIT_ARCHIVE_WHITELIST. These options are mutually exclusive."
```

**Use Cases:**

```bash
# Backup/mirror a specific GRASP server
NGIT_ARCHIVE_GRASP_SERVICES=git.example.com
NGIT_ARCHIVE_READ_ONLY=true  # Default

# Archive multiple trusted GRASP servers
NGIT_ARCHIVE_GRASP_SERVICES=git.nostr.dev,relay.gitnostr.com
```

---

#### `NGIT_ARCHIVE_READ_ONLY`

**Description:** Configure relay as read-only sync of archived repositories  
**Type:** Boolean  
**Default:** `true` if `NGIT_ARCHIVE_ALL`, `NGIT_ARCHIVE_WHITELIST`, or `NGIT_ARCHIVE_GRASP_SERVICES` is set, `false` otherwise  
**Required:** No

**Examples:**

```bash
# Explicitly enable (requires archive mode)
NGIT_ARCHIVE_READ_ONLY=true

# Explicitly disable (writable archive repos)
NGIT_ARCHIVE_READ_ONLY=false

# Automatic (default behavior)
# - If NGIT_ARCHIVE_ALL, NGIT_ARCHIVE_WHITELIST, or NGIT_ARCHIVE_GRASP_SERVICES is set → true
# - Otherwise → false
# NGIT_ARCHIVE_READ_ONLY=
```

**Behavior:**

- When `true`:
  - NIP-11 document includes `GRASP-05` in `supported_grasps`
  - NIP-11 `curation` field describes the archive scope
  - Repository announcements not listing this service are accepted per whitelist/archive-all
- When `false`:
  - Archive mode disabled (standard GRASP-01 operation)
- When unset (default):
  - Automatically `true` if archive mode configured
  - Automatically `false` otherwise

**Error Conditions:**

```bash
# ERROR: Cannot set read-only without archive config
NGIT_ARCHIVE_READ_ONLY=true
NGIT_ARCHIVE_ALL=false
NGIT_ARCHIVE_WHITELIST=
NGIT_ARCHIVE_GRASP_SERVICES=
# → Server fails to start: "NGIT_ARCHIVE_READ_ONLY=true requires either 
#    NGIT_ARCHIVE_ALL=true, NGIT_ARCHIVE_WHITELIST, or NGIT_ARCHIVE_GRASP_SERVICES to be set"

# ERROR: Cannot use repository whitelist with archive read-only
NGIT_ARCHIVE_READ_ONLY=true
NGIT_ARCHIVE_WHITELIST=npub1alice...
NGIT_REPOSITORY_WHITELIST=npub1bob...
# → Server fails to start: "NGIT_REPOSITORY_WHITELIST cannot be used with
#    NGIT_ARCHIVE_READ_ONLY=true"
```

**NIP-11 Impact:**

When `NGIT_ARCHIVE_READ_ONLY=true`:
- `supported_grasps`: includes `"GRASP-05"`
- `curation`: Set to one of:
  - `"Read-only sync of all repositories found on network"` (if `NGIT_ARCHIVE_ALL=true`)
  - `"Read-only sync of whitelisted repositories and maintainers"` (if `NGIT_ARCHIVE_WHITELIST` set)
  - `"Read-only sync of repositories from specified GRASP servers"` (if `NGIT_ARCHIVE_GRASP_SERVICES` set)

**Use Cases:**

```bash
# Public archive of entire ecosystem
NGIT_ARCHIVE_ALL=true
NGIT_ARCHIVE_READ_ONLY=true  # Default

# Selective backup of critical projects
NGIT_ARCHIVE_WHITELIST=npub1torvalds.../linux,npub1satoshi.../bitcoin
NGIT_ARCHIVE_READ_ONLY=true  # Default

# Writable mirror (advanced, not typical)
NGIT_ARCHIVE_WHITELIST=npub1alice...
NGIT_ARCHIVE_READ_ONLY=false

# Archive specific GRASP servers
NGIT_ARCHIVE_GRASP_SERVICES=git.example.com,git.nostr.dev
NGIT_ARCHIVE_READ_ONLY=true  # Default
```

---

### GRASP-06 Contributor PR Submission

These options control the optional `/prs/<npub>/<identifier>.git` contributor pull-request submission endpoint per the [GRASP-06 specification](https://github.com/DanConwayDev/grasp/blob/main/06.md).

#### `NGIT_GRASP06_ENABLE`

**Description:** Enable the GRASP-06 contributor PR submission endpoint at `/prs/<npub>/<identifier>.git`  
**Type:** Boolean  
**Default:** `false`  
**Required:** No

**Examples:**

```bash
# Enable GRASP-06 (opt-in)
NGIT_GRASP06_ENABLE=true

# Disable (default)
NGIT_GRASP06_ENABLE=false
```

**Behavior:**

- When `true`:
  - `/prs/<npub>/<identifier>.git` accepts unauthenticated pushes of `refs/nostr/<event-id>`
  - NIP-11 `supported_grasps` includes `"GRASP-06"`
  - PR / PR-Update events naming this relay's `/prs/` endpoint in their `clone` tag are accepted to purgatory even without a matching accepted repository announcement
  - Standard `<npub>/<identifier>.git` endpoint behaviour is unchanged
- When `false` (default):
  - `/prs/*` returns HTTP 404
  - Event-acceptance is unchanged (standard GRASP-01 rules apply)

**Security Model:**

The `/prs/` endpoint is intentionally unauthenticated — there is no NIP-98 auth, no allowlist, no quota, and no proof-of-work in v1. Validity is enforced by:

- The signed PR / PR-Update Nostr event the pushed `refs/nostr/<event-id>` references
- Per-submitter / per-identifier scoping enforced when the event arrives
- Inline ref-name validation (only `refs/nostr/<64-hex-event-id>` accepted)
- Periodic cleanup of orphan repositories with zero refs

Operators should review the design tradeoffs in [`docs/explanation/grasp-06-contributor-pr-submission.md`](../explanation/grasp-06-contributor-pr-submission.md) before enabling.

---

### Repository Whitelist

#### `NGIT_REPOSITORY_WHITELIST`

**Description:** Whitelist specific repositories/pubkeys/identifiers for GRASP-01 acceptance  
**Type:** Comma-separated list  
**Default:** Empty (all repos listing our service are accepted)  
**Required:** No

**Format:** Same as `NGIT_ARCHIVE_WHITELIST`:
- `npub1...` - Accept all repos from this pubkey (if they list our service)
- `npub1.../identifier` - Accept specific repo (if it lists our service)
- `identifier` - Accept repos with this identifier (if they list our service)

**Difference from Archive Whitelist:**
- **Repository whitelist**: Announcements **MUST** list our service **AND** match whitelist
- **Archive whitelist**: Announcements don't need to list our service, just match whitelist

**Examples:**

```bash
# Accept only repos from specific pubkey (that list our service)
NGIT_REPOSITORY_WHITELIST=npub1alice23

# Accept specific repos only
NGIT_REPOSITORY_WHITELIST=npub1alice23/linux,npub1bob23/bitcoin-core

# Accept repos with specific identifiers
NGIT_REPOSITORY_WHITELIST=bitcoin-core,linux,rust

# Combined whitelist
NGIT_REPOSITORY_WHITELIST=npub1alice23...,npub1bob23.../linux,bitcoin-core
```

**Behavior:**

- When set:
  - Announcements **must** list our service in both `clone` and `relays` tags (GRASP-01 requirement)
  - Announcements **must** match the whitelist (pubkey, repo, or identifier)
  - NIP-11 `curation` field set to: `"Accepts only whitelisted repositories and maintainers that list this service"`
- When empty (default):
  - All announcements listing our service are accepted (standard GRASP-01 behavior)

**Error Conditions:**

```bash
# ERROR: Cannot use with archive read-only mode
NGIT_ARCHIVE_READ_ONLY=true
NGIT_ARCHIVE_WHITELIST=npub1archive...
NGIT_REPOSITORY_WHITELIST=npub1bob...
# → Server fails to start: "NGIT_REPOSITORY_WHITELIST cannot be used with
#    NGIT_ARCHIVE_READ_ONLY=true. Either set NGIT_ARCHIVE_READ_ONLY=false
#    or use NGIT_ARCHIVE_WHITELIST instead"
```

**NIP-11 Impact:**

When `NGIT_REPOSITORY_WHITELIST` is set:
- `curation`: `"Accepts only whitelisted repositories and maintainers that list this service"`
- `supported_grasps`: Does **not** include `GRASP-05` (still GRASP-01 compliant)

**Use Cases:**

```bash
# Curated relay for specific projects (GRASP-01 mode)
NGIT_REPOSITORY_WHITELIST=bitcoin-core,linux,rust

# Personal relay for self and trusted collaborators
NGIT_REPOSITORY_WHITELIST=npub1me...,npub1alice...,npub1bob...

# Project-specific relay (e.g., Rust ecosystem)
NGIT_REPOSITORY_WHITELIST=rust,cargo,rustc,tokio,serde

# Hybrid: specific projects AND specific maintainer's repos
NGIT_REPOSITORY_WHITELIST=bitcoin-core,npub1alice...
```

**Comparison Table:**

| Configuration | Lists Service? | Matches Whitelist? | Result |
|---------------|----------------|-------------------|---------|
| No whitelist | Yes | N/A | ✅ Accept (GRASP-01) |
| No whitelist | No | N/A | ❌ Reject |
| Repository whitelist | Yes | Yes | ✅ Accept (GRASP-01) |
| Repository whitelist | Yes | No | ❌ Reject (not whitelisted) |
| Repository whitelist | No | Yes | ❌ Reject (doesn't list service) |
| Archive whitelist (read-only=true) | No | Yes | ✅ Accept (GRASP-05) |
| Archive whitelist (read-only=false) | Yes | N/A | ✅ Accept (GRASP-01) |
| Archive whitelist (read-only=false) | No | Yes | ✅ Accept (GRASP-05) |

---

### Repository Blacklist

#### `NGIT_REPOSITORY_BLACKLIST`

**Description:** Blacklist specific repositories/pubkeys/identifiers to reject  
**Type:** Comma-separated list  
**Default:** Empty (no repositories are blacklisted)  
**Required:** No

**Format:** Same as whitelist formats:
- `npub1...` - Block all repos from this pubkey
- `npub1.../identifier` - Block specific repo
- `identifier` - Block repos with this identifier (any pubkey)

**Precedence:** Blacklist takes precedence over **ALL** whitelists:
- Blacklisted repos are rejected even if they match archive or repository whitelists
- Blacklisted repos are rejected even if they list our service
- Blacklist is checked **first** before any other validation

**Examples:**

```bash
# Block all repos from specific pubkey
NGIT_REPOSITORY_BLACKLIST=npub1spam...

# Block specific repo
NGIT_REPOSITORY_BLACKLIST=npub1alice.../malware-repo

# Block repos with specific identifiers
NGIT_REPOSITORY_BLACKLIST=malware,spam,phishing

# Combined blacklist
NGIT_REPOSITORY_BLACKLIST=npub1spam...,npub1alice.../bad-repo,malware
```

**Rejection Reasons:**

The blacklist provides specific rejection reasons based on the match type:

- **Npub format:** `"Repository owner <npub> is blacklisted"`
- **Npub/identifier format:** `"Repository <npub>/<identifier> is blacklisted"`
- **Identifier format:** `"Repository identifier <identifier> is blacklisted"`

These reasons help operators understand why a repository was rejected without needing to flag it in curation metadata.

**Behavior:**

Blacklist is checked **before** all other validation:
1. Check blacklist → Reject if matched
2. Check if lists service → Accept if matches repository whitelist (if enabled)
3. Check archive config → Accept if matches archive whitelist (if enabled)
4. Reject otherwise

**Use Cases:**

```bash
# Block spam/malware repos
NGIT_REPOSITORY_BLACKLIST=malware,spam,phishing

# Block abusive users
NGIT_REPOSITORY_BLACKLIST=npub1spammer...,npub1abuser...

# Block specific problematic repos
NGIT_REPOSITORY_BLACKLIST=npub1alice.../copyright-violation,npub1bob.../illegal-content

# Temporary block for investigation
NGIT_REPOSITORY_BLACKLIST=npub1suspicious.../repo-under-review
```

**Comparison with Whitelists:**

| Configuration | Blacklisted? | Matches Whitelist? | Lists Service? | Result |
|---------------|--------------|-------------------|----------------|---------|
| Blacklist only | Yes | N/A | N/A | ❌ Reject (blacklisted) |
| Blacklist only | No | N/A | Yes | ✅ Accept (GRASP-01) |
| Blacklist + Repository whitelist | Yes | Yes | Yes | ❌ Reject (blacklist wins) |
| Blacklist + Archive whitelist | Yes | Yes | No | ❌ Reject (blacklist wins) |
| Blacklist + Both whitelists | Yes | Yes | Yes | ❌ Reject (blacklist wins) |
| Blacklist only | No | N/A | No | ❌ Reject (no whitelist match) |

**NIP-11 Impact:**

Blacklist does **not** affect NIP-11 metadata:
- No `curation` field changes (blacklist is operational, not curation policy)
- Blacklist is transparent to clients (rejected with specific reason)
- Operators can use blacklist without advertising curation

#### `NGIT_BLACKLIST_AUTO_RESTORE`

**Description:** On startup, restore repositories previously deleted by blacklist parity when they are no longer blacklisted and still within holding retention
**Type:** Boolean
**Default:** `false`
**Required:** No
**CLI:** `--blacklist-auto-restore`

**Behavior:**

- When `false` (default): startup does not run blacklist-source auto-restore; unblacklisted repositories in holding are restored only by existing recovery triggers (for example re-announcement).
- When `true`: startup also scans holding metadata with `holding-source=blacklist`, deduplicates owner+identifier scopes, and attempts restore for scopes that:
  - are still within `NGIT_HOLDING_RETENTION_SECS`, and
  - no longer match `NGIT_REPOSITORY_BLACKLIST`.
- Scopes that are still blacklisted are skipped (not restored).

**Related startup behavior (always on when repository whitelist is enabled):**

- Startup scans holding metadata with `holding-source=whitelist` and attempts restore for scopes that are within retention, now match `NGIT_REPOSITORY_WHITELIST`, and are not blacklisted.
- Scopes still not matching `NGIT_REPOSITORY_WHITELIST` are skipped.

**Startup ordering:**

1. Blacklist parity delete
2. Blacklist auto-restore (if enabled)
3. Whitelist parity delete
4. Whitelist restore (for scopes now matching `NGIT_REPOSITORY_WHITELIST`)

This ordering keeps startup reconciliation deterministic when multiple policies interact.

**Examples:**

```bash
# Enable startup auto-restore for unblacklisted repos
NGIT_BLACKLIST_AUTO_RESTORE=true

# Default behavior
NGIT_BLACKLIST_AUTO_RESTORE=false
```

---

### Event Blacklist

#### `NGIT_EVENT_BLACKLIST`

**Description:** Blacklist events from specific authors (npubs)  
**Type:** Comma-separated list of npubs  
**Default:** Empty (no events are blacklisted by author)  
**Required:** No

**Format:**
- `npub1...` - Block all events from this author

**Precedence:** Event blacklist takes precedence over **ALL** other validation:
- Blacklisted events are rejected **before** any other policy checks
- Applies to all event types (announcements, state events, PRs, etc.)
- Events never reach purgatory (rejected immediately)
- Overrides repository blacklist, whitelists, and all other policies

**Examples:**

```bash
# Block all events from specific author
NGIT_EVENT_BLACKLIST=npub1spam...

# Block events from multiple authors
NGIT_EVENT_BLACKLIST=npub1spam...,npub1abuser...,npub1troll...
```

**Rejection Reason:**

The event blacklist provides a specific rejection reason:
- **Format:** `"Event author <npub> is blacklisted"`

This reason helps operators understand why an event was rejected without needing to flag it in metadata.

**Behavior:**

Event blacklist is checked **first** before all other validation:
1. Check event blacklist → Reject if author is blacklisted
2. Check repository blacklist (for announcements) → Reject if matched
3. Check event-type specific policies → Accept/Reject based on policy
4. Process event normally

**Use Cases:**

```bash
# Block spam/abusive users
NGIT_EVENT_BLACKLIST=npub1spammer...,npub1abuser...

# Block malicious actors
NGIT_EVENT_BLACKLIST=npub1malware...,npub1phisher...

# Temporary block for investigation
NGIT_EVENT_BLACKLIST=npub1suspicious...
```

**Comparison with Repository Blacklist:**

| Configuration | Scope | Checked When | Applies To |
|---------------|-------|--------------|------------|
| Event Blacklist | Author-based | **First** (before all policies) | **All events** from author |
| Repository Blacklist | Repo-based | Second (announcements only) | Specific repositories |

**Event Blacklist vs Repository Blacklist:**

```bash
# Scenario: npub1alice is event-blacklisted
NGIT_EVENT_BLACKLIST=npub1alice...

# Result:
# - ALL events from npub1alice are rejected (announcements, PRs, etc.)
# - Events never reach relay or purgatory
# - Rejection: "Event author npub1alice... is blacklisted"

# Scenario: npub1alice/repo is repository-blacklisted
NGIT_REPOSITORY_BLACKLIST=npub1alice.../malware

# Result:
# - Only announcements for npub1alice.../malware are rejected
# - Other events from npub1alice are still processed normally
# - PRs/state events for different repos from npub1alice are accepted
```

**NIP-11 Impact:**

Event blacklist does **not** affect NIP-11 metadata:
- No `curation` field changes (blacklist is operational, not policy)
- Blacklist is transparent to clients (rejected with specific reason)
- Operators can use blacklist without advertising moderation

---

### Deletion Requests (NIP-09 and NIP-62)

#### `NGIT_DELETION_REQUEST_DISRESPECTOR`

**Description:** Ignore NIP-09 deletion requests and NIP-62 request-to-vanish events and act as an archival server
**Type:** Boolean
**Default:** `false` (deletion requests are honoured)
**Required:** No
**CLI:** `--deletion-request-disrespector`

**Behavior:**

- When `false` (default):
  - NIP-09 (kind 5) deletion requests and NIP-62 request-to-vanish events are
    honoured: their targets are
    hard-deleted from the relay, matching purgatory entries are evicted, and a
    persistent tombstone is recorded so re-submission of the deleted event stays
    rejected across restarts.
  - NIP-11 `supported_nips` includes `9` (deletion) and `62` (request to vanish).
- When `true`:
  - Incoming NIP-09 deletion requests and NIP-62 request-to-vanish events are
    still **stored** (the client receives an OK), but they are **not acted
    upon**. Their targets remain fully accessible. This makes the relay an
    archival server, preserving content and preventing "left-pad" scenarios.
  - NIP-11 `supported_nips` does **not** include `9` or `62`, so clients can
    discover that this relay does not honour deletions.

**IMPORTANT:** This setting ONLY affects NIP-09 and NIP-62 user-initiated
requests. It does **NOT** prevent blacklist-triggered deletions, which are an
operator moderation mechanism (spam/malware/abuse) that archival relays still
need.

**Use Cases:**

- Community archival relays
- Research / historical preservation
- Backup / mirror relays

**Examples:**

```bash
# Archival relay: preserve targets of NIP-09 and NIP-62 requests
NGIT_DELETION_REQUEST_DISRESPECTOR=true

# Standard relay: honour deletion requests (default)
NGIT_DELETION_REQUEST_DISRESPECTOR=false
```

See [`docs/explanation/repository-lifecycle.md`](../explanation/repository-lifecycle.md)
for the full lifecycle design rationale.

---

### Deletion-Request Retention (NIP-09 and NIP-62)

These options govern the bounded lifecycle of accepted NIP-09 deletion requests and NIP-62 request-to-vanish events. All values are integer seconds. The used-request defaults express months as fixed 30-day periods, not calendar months.

The relay derives unused deadlines from relay-observed `first_seen_at`, never from the client-controlled event `created_at`. It derives used deadlines from `last_used_at`. Each `...ADDITIONAL...` option begins only after its corresponding served period ends; it is not a total retention duration.

Seconds are used for configuration consistency and short automated tests. In production, configure every period to at least one day and keep each total lifecycle comfortably longer than the worst-case deletion processing time, including repository archival and cascade work. Sub-day values are intended only for tests.

#### `NGIT_DELETION_REQUEST_RETENTION_UNUSED_SERVED_SECS`

- **Description:** How long an unused deletion or vanish request remains served from relay-observed `first_seen_at`
- **Type:** Positive integer (seconds)
- **Default:** `2592000` (30 days)
- **Required:** No
- **CLI:** `--deletion-request-retention-unused-served-secs`

```bash
# Default: serve an unused request for 30 days from first_seen_at
NGIT_DELETION_REQUEST_RETENTION_UNUSED_SERVED_SECS=2592000
```

After this served period, an unused request enters its additional unserved/gating period.

---

#### `NGIT_DELETION_REQUEST_RETENTION_UNUSED_UNSERVED_GATING_ADDITIONAL_SECS`

- **Description:** Additional time after unused serving ends that an unused deletion or vanish request remains unserved but eligible to gate admission
- **Type:** Positive integer (seconds)
- **Default:** `15552000` (180 days)
- **Required:** No
- **CLI:** `--deletion-request-retention-unused-unserved-gating-additional-secs`

```bash
# Default: retain an unused request as an unserved gate for a further 180 days
NGIT_DELETION_REQUEST_RETENTION_UNUSED_UNSERVED_GATING_ADDITIONAL_SECS=15552000
```

The unused request expires after `unused served + this additional period` from `first_seen_at`. Retained disrespector and non-targeting NIP-62 records do not enforce a local admission gate. When an archival relay starts, it reclassifies an expired unused targeting request as used if its target is present before cleanup runs; this preserves the used request indefinitely.

---

#### `NGIT_DELETION_REQUEST_RETENTION_USED_SERVED_AFTER_LAST_USED_SECS`

- **Description:** In normal mode, how long a used deletion or vanish request remains served after `last_used_at`
- **Type:** Positive integer (seconds)
- **Default:** `23328000` (270 days; 9 fixed 30-day months)
- **Required:** No
- **CLI:** `--deletion-request-retention-used-served-after-last-used-secs`

```bash
# Default: serve a used request for 270 days after last_used_at
NGIT_DELETION_REQUEST_RETENTION_USED_SERVED_AFTER_LAST_USED_SECS=23328000
```

Every successful use resets `last_used_at` and restarts this served period. When `NGIT_DELETION_REQUEST_DISRESPECTOR=true`, used requests remain served indefinitely, so this normal-mode duration does not expire them.

---

#### `NGIT_DELETION_REQUEST_RETENTION_USED_UNSERVED_GATING_ADDITIONAL_SECS`

- **Description:** Additional normal-mode time after used serving ends that a used deletion or vanish request remains unserved but continues gating admission
- **Type:** Positive integer (seconds)
- **Default:** `7776000` (90 days; 3 fixed 30-day months)
- **Required:** No
- **CLI:** `--deletion-request-retention-used-unserved-gating-additional-secs`

```bash
# Default: continue gating for a further 90 days after used serving ends
NGIT_DELETION_REQUEST_RETENTION_USED_UNSERVED_GATING_ADDITIONAL_SECS=7776000
```

The used request expires after `used served + this additional period` from `last_used_at`. When `NGIT_DELETION_REQUEST_DISRESPECTOR=true`, used requests remain served indefinitely, so this normal-mode additional period does not expire their local record.

**Validation:** Each deletion-request retention duration must be greater than zero. Each served and additional-gating pair must also fit in an unsigned 64-bit second duration when combined.

**Cleanup cadence:** `NGIT_HOLDING_CLEANUP_INTERVAL_SECS` schedules both holding DB and deletion-request retention cleanup passes. Cleanup evaluates deadlines derived from `first_seen_at` and `last_used_at`; changing its cadence never changes those deadlines.

---

### Rate Limiting & DoS Protection

#### `NGIT_MAX_CONNECTIONS`

**Description:** Maximum total connections to the relay. When unset, connections are unlimited, deferring to OS fd limits and infrastructure-level controls.  
**Type:** Integer  
**Default:** unlimited  
**Required:** No

**Examples:**

```bash
# Cap connections for a resource-constrained deployment
NGIT_MAX_CONNECTIONS=4096

# Higher limit for large public relay
NGIT_MAX_CONNECTIONS=8000

# Lower limit for private relay
NGIT_MAX_CONNECTIONS=100
```

**Notes:**

- When unset, the relay imposes no connection limit (`Semaphore::MAX_PERMITS`); OS fd limits and infrastructure controls apply
- Set this only if you need an explicit cap; otherwise leave unset
- Works in conjunction with per-connection limits (500 subscriptions, 60 events/min)
- When limit is reached, new connections are rejected
- Existing connections continue to work normally

**Related Limits:**

Per-connection limits (built-in to relay-builder, not configurable):
- Max subscriptions per connection: 500
- Max events per minute per connection: 60
- Max subscription ID length: 250 characters
- Max results per filter: 500

---

### GRASP-P Private Repositories (Phase 1–2)

Multi-tenant private repository hosting: kind-30640 registrations, 30641
state roots, 1059/21059 wraps, Blossom-style blob routes, and the quota
ledger. Every `NGIT_PRIVATE_*` knob is a no-op unless
`NGIT_PRIVATE_REPOS_ENABLE=true`.

The admission-affecting knobs (mode, pow bits, whitelist, event/blob caps,
the three quota scopes, alias/key limits, and the Phase-4b
replacement-cadence pair) form the `policy_fingerprint` preimage
(`grasp-p-policy-v3`): paired nodes MUST run identical values or
registrations accepted on one node can be silently rejected on the other.
Compare fingerprints via NIP-11 `private_repos.policy_fingerprint` or the
startup log line.

#### `NGIT_PRIVATE_REPOS_ENABLE`

**Description:** Master switch for GRASP-P private repository hosting. When `false` (default) the relay is byte-identical to a public-only relay: 30640/30641 are orphan-rejected, the blob routes 404, and NIP-11 carries no `private_repos` section.  
**Type:** Boolean  
**Default:** `false`  
**Required:** No

#### `NGIT_PRIVATE_MAX_BLOB_BYTES`

**Description:** Per-blob size cap in bytes, enforced pre-stream (upload preflight) and mid-stream (chunked PUT aborts). Part of the `policy_fingerprint` preimage.  
**Type:** Integer  
**Default:** `268435456` (256 MiB)  
**Required:** No

#### `NGIT_PRIVATE_MAX_EVENT_BYTES`

**Description:** Serialized-JSON size cap in bytes for private-repo events (30640/30641/1059/21059). Part of the `policy_fingerprint` preimage.  
**Type:** Integer  
**Default:** `131072` (128 KiB)  
**Required:** No

#### `NGIT_PRIVATE_QUOTA_TENANT_BYTES`

**Description:** Per hosting-npub total quota in bytes (events + blobs) tracked by the private ledger. Must be greater than `0` and no larger than `NGIT_PRIVATE_GLOBAL_BUDGET_BYTES`. Part of the `policy_fingerprint` preimage.  
**Type:** Integer  
**Default:** `1073741824` (1 GiB)  
**Required:** No

#### `NGIT_PRIVATE_QUOTA_REPO_BYTES`

**Description:** Per-alias total quota in bytes (events + blobs). Must be greater than `0` and no larger than `NGIT_PRIVATE_QUOTA_TENANT_BYTES`. Part of the `policy_fingerprint` preimage.  
**Type:** Integer  
**Default:** `536870912` (512 MiB)  
**Required:** No

#### `NGIT_PRIVATE_GLOBAL_BUDGET_BYTES`

**Description:** Whole private-subsystem storage cap in bytes; the ledger refuses charges that would exceed it (HTTP 507 on the blob path). Part of the `policy_fingerprint` preimage.  
**Type:** Integer  
**Default:** `53687091200` (50 GiB)  
**Required:** No

#### `NGIT_PRIVATE_MAX_ALIASES_PER_TENANT`

**Description:** Maximum registrations (aliases) per hosting npub (anti-sybil). Conflict-merge winners are exempt from the check (never from the accounting) so node-local occupancy cannot flip the deterministic merge. Part of the `policy_fingerprint` preimage.  
**Type:** Integer  
**Default:** `64`  
**Required:** No

#### `NGIT_PRIVATE_MAX_WRITE_KEYS_PER_ALIAS`

**Description:** Maximum `w` + `aux` write keys per alias registration. Part of the `policy_fingerprint` preimage.  
**Type:** Integer  
**Default:** `64`  
**Required:** No

#### `NGIT_PRIVATE_STATE_HISTORY_EDITIONS`

**Description:** Kind-30641 edition ring depth kept in the private meta store (superseded editions stay fetchable this many deep). Must be at least `1`.  
**Type:** Integer  
**Default:** `16`  
**Required:** No

#### `NGIT_PRIVATE_GC_GRACE_SECS`

**Description:** Grace period in seconds before an unreferenced blob may be deleted by the GC pass (denylisted blobs bypass the grace).  
**Type:** Integer  
**Default:** `86400` (24 hours)  
**Required:** No

#### `NGIT_PRIVATE_GC_INTERVAL_SECS`

**Description:** Interval in seconds between private blob GC passes.  
**Type:** Integer  
**Default:** `3600` (1 hour)  
**Required:** No

#### `NGIT_PRIVATE_OFFBOARD_RETENTION_SECS`

**Description:** Tombstoned-alias purge delay in seconds.  
**Type:** Integer  
**Default:** `2592000` (30 days)  
**Required:** No

#### `NGIT_PRIVATE_BLOB_DATA_PATH`

**Description:** Blob store root directory. When unset the relay derives `<relay_data_path>/blobs`. Must not be empty when set.  
**Type:** String (path)  
**Default:** unset (`<relay_data_path>/blobs`)  
**Required:** No

#### `NGIT_PRIVATE_META_DATA_PATH`

**Description:** Private meta store (heed/LMDB env) root holding registrations, key claims, and the quota ledger. When unset the relay derives `<relay_data_path>/private-meta`. Must not be empty when set.  
**Type:** String (path)  
**Default:** unset (`<relay_data_path>/private-meta`)  
**Required:** No

#### `NGIT_PRIVATE_MIRROR_ENABLE`

**Description:** Enable the Phase-2 blob mirror: this node fetches blobs referenced by synced 30641 editions from peer blob servers so a pair converges on bytes as well as events.  
**Type:** Boolean  
**Default:** `false`  
**Required:** No

#### `NGIT_PRIVATE_MIRROR_PEER_URLS`

**Description:** Comma-separated peer blob-server base URLs for the mirror. When unset, peers are derived from each registration's `server` tags (minus this node's own domain).  
**Type:** String (CSV URLs)  
**Default:** unset (derive from `server` tags)  
**Required:** No

#### `NGIT_PRIVATE_MIRROR_MAX_CONCURRENCY`

**Description:** Maximum concurrent blob mirror fetches. Must be greater than `0` when the mirror is enabled.  
**Type:** Integer  
**Default:** `4`  
**Required:** No

#### `NGIT_PRIVATE_MIRROR_FETCH_TIMEOUT_SECS`

**Description:** Per-blob mirror fetch timeout in seconds. Must be greater than `0` when the mirror is enabled.  
**Type:** Integer  
**Default:** `120`  
**Required:** No

#### `NGIT_PRIVATE_SYNC_PEER_URLS`

**Description:** Comma-separated operator-approved peer relay URLs for private-repo sync. Outbound private-sync WebSocket connections are made ONLY to this allowlist — tenant 30640 `relays` tags are advisory metadata and never trigger a connection (SSRF / membership-map-leak guard). When unset, no private-sync peer connections are initiated (bootstrap relays still carry the private filters).  
**Type:** String (CSV URLs)  
**Default:** unset (no private-sync peers)  
**Required:** No

#### `NGIT_PRIVATE_MIRROR_ALLOW_PRIVATE_IPS`

**Description:** SSRF guard override: when `true`, the blob mirror may fetch from peers resolving to loopback/private/link-local IPs (and over plain `http`), and private-sync peer relays may use plain `ws://` or internal IPs. The default `false` drops such peers — production fetches only over `https`/`wss` from public hosts. Set `true` only for local testing (e.g. a `127.0.0.1` node pair).  
**Type:** Boolean  
**Default:** `false`  
**Required:** No

#### `NGIT_PRIVATE_ACCEPT_DIRECT_INVITES`

**Description:** Accept kind-3313 direct invites for storage. Currently only `false` is honored (invites are rejected).  
**Type:** Boolean  
**Default:** `false`  
**Required:** No

#### `NGIT_PRIVATE_ACCEPT_LEGACY_WRAP_KIND`

**Description:** Also accept the **legacy** stream-wrap kinds `1059`/`21059` alongside the dedicated CORD stream-wrap kinds `3359`/`23359`. GRASP-P stream wraps were never NIP-59 gift wraps (no `p` tag, no kind-13 seal, symmetric AEAD, derived deterministic signer), so they moved to their own kind. The default `true` is the migration window: a node must accept `3359` **before** any client emits it, and wraps already published on `1059` (or held for out-of-order reprocess) must keep draining. Set `false` only once every client writing to this node has migrated — the legacy kinds are then **retired**: while private repos are enabled, a `1059`/`21059` is refused outright with `restricted: legacy stream-wrap kind is not accepted on this node`. It is deliberately **not** reclassified onto the public related-event path. That path stores any event carrying an `a`/`e` tag that references accepted content, from **any** key — no §3.2 registered-key gate, no `NGIT_PRIVATE_MAX_EVENT_BYTES` cap, no private quota charge, and never swept by the private GC — which would make the `false` position of this knob *wider* than the default (where an unregistered `1059` is rejected outright). Nodes with `NGIT_PRIVATE_REPOS_ENABLE=false` are unaffected: `1059` keeps its vanilla public related-event handling there. Genuine NIP-59 gift-wrapped invites are unaffected either way: they go to inbox relays, not the git node. This is a **cross-node acceptance** knob — it feeds the `policy_fingerprint` (`v3`), so both nodes of a pair must agree on it or wraps accepted on one are rejected on the other; flip it on both nodes in a single maintenance window (see the ops runbook §2).

**Clients must emit exactly one wrap kind per logical wrap.** Dual-accept exists so a client can *switch* kinds, not *duplicate* them: the quota charge is keyed on `event.id` and the kind is part of the id preimage, so the same plaintext published as both `1059` and `3359` is two ids — charged twice and stored twice, with no credit path (wrap event bytes are released only when the registration dies).  
**Type:** Boolean  
**Default:** `true`  
**Required:** No

#### `NGIT_PRIVATE_PER_TENANT_METRICS`

**Description:** Opt in to per-tenant metric labels. The default `false` exposes aggregate metrics only, keeping Prometheus label cardinality bounded regardless of tenant count.  
**Type:** Boolean  
**Default:** `false`  
**Required:** No

---

### GRASP-P Registration Admission Mode (WP-E)

These knobs gate kind-30640 **new-alias** registrations when
`NGIT_PRIVATE_REPOS_ENABLE=true`. (The master switch and the quota,
storage, GC, and mirror/sync knobs are documented in the Phase 1–2
section above.)

#### `NGIT_PRIVATE_REGISTRATION_MODE`

**Description:** Admission mode for **new** private-repo aliases: `open` (any tenant), `whitelist` (only `NGIT_PRIVATE_TENANT_WHITELIST` npubs), `pow` (NIP-13 proof of work on the 30640), `paid` (reserved — fails `Config::validate()`). The mode gate applies to NEW aliases only: same-tenant replacements/rotations of an existing alias and cross-tenant conflict-merge survivors are never re-gated.  
**Type:** Enum (`open` \| `whitelist` \| `pow` \| `paid`)  
**Default:** `whitelist`  
**Required:** No

**Notes:**

- **Default changed in WP-E (was `open` in Phase 1–4b).** The locked operator decision: launch posture is whitelist — in open mode every fresh key receives the full per-tenant blob quota, so ~50 pseudonymous tenants can lawfully exhaust the whole-subsystem storage budget (server issue !7). `open` is intended for staging/self-use only and must now be selected explicitly.
- **`policy_fingerprint` change on upgrade.** The mode is part of the `grasp-p-policy-v3` fingerprint preimage. An operator who never set the mode explicitly will see their fingerprint change on upgrade (`open` → `whitelist`): paired nodes must upgrade together (or set the mode explicitly on both) to keep fingerprints — and therefore cross-node acceptance — in parity.
- **Empty whitelist = accept-nothing (safe default).** `whitelist` mode with an empty `NGIT_PRIVATE_TENANT_WHITELIST` rejects every new registration; startup emits a loud `tracing::warn!` ("all new private-repo registrations will be rejected") so an operator who expected open mode sees it immediately.

**Boot-time re-enforcement (exact behavior, pinned by the exit12 integration test):**

On boot, stored kind-30640 events are replayed through the registration handler only when the private meta index is missing or holds a different edition (`boot_reconcile`). Mode changes are re-enforced **only** where a replay is a *fresh* admission — a meta-index rebuild after a wipe, or a cross-tenant conflict winner. Crucially this is **non-destructive**:

- An operator who accumulated registrations under `open` and upgrades to the `whitelist` default keeps every existing tenant across reboots: the meta record matches the stored event, no replay happens, and tenants keep serving (30640 REQ, blob GET, new 30641 editions, rotations).
- A replay that no longer passes registration checks is **warn-logged only** — no meta mutation, no eviction, no relay-DB coordinate pruned. Mode enforcement belongs at admission time, never as retroactive eviction.
- Exception to be aware of: after a **meta-store wipe** (disaster recovery from the relay DB), replays *are* fresh admissions, so a stricter mode blocks the rebuild. Remedy: temporarily set `open` (or list the affected npubs), restart to rebuild the index, then flip back.

#### `NGIT_PRIVATE_POW_BITS`

**Description:** NIP-13 leading-zero bits required on kind-30640 registrations when `NGIT_PRIVATE_REGISTRATION_MODE=pow`.  
**Type:** Integer  
**Default:** `20`  
**Required:** No (must be 1–40 when private repos are enabled)

#### `NGIT_PRIVATE_TENANT_WHITELIST`

**Description:** Comma-separated npubs (bech32) allowed to register new aliases when `NGIT_PRIVATE_REGISTRATION_MODE=whitelist`. Part of the `policy_fingerprint` preimage — paired nodes must run identical lists.  
**Type:** String (CSV)  
**Default:** `""` (empty — rejects all new registrations)  
**Required:** No

---

### GRASP-P Private Repository Rate Limits (Phase 4b)

These knobs tune the per-write-key token bucket for **client-submitted**
private writes. They only have an effect when `NGIT_PRIVATE_REPOS_ENABLE=true`.
Synced/replayed traffic (loopback sync delivery, hot-cache reprocess) always
bypasses this limiter — it is node-local DoS protection with no cross-node
convergence impact, and is therefore deliberately NOT part of the
`policy_fingerprint` preimage. (The master switch, quota/storage, and
mirror/sync knobs are documented in the Phase 1–2 section above.)

#### `NGIT_PRIVATE_WRITE_RATE_CAPACITY`

**Description:** Per-write-key token bucket capacity for client-submitted private writes: kind 30641/1059/21059 events (1 token per event) and blob PUTs (1 token per request). `0` = unlimited (limiter disabled). The default is deliberately generous: legitimate client flows — including cord-git widen→narrow key rotations — must never trip it; only abuse floods (e.g. quota-uncharged 21059 spam, which is never quota-charged) get capped. Exceeding clients receive NIP-20 OK false with `rate-limited; retry later` (blob PUT: HTTP 429 with `Retry-After`).  
**Type:** Integer  
**Default:** `120`  
**Required:** No

#### `NGIT_PRIVATE_WRITE_RATE_REFILL_PER_MIN`

**Description:** Refill rate (tokens per minute) for the per-write-key client write bucket. Must be greater than `0` when `NGIT_PRIVATE_WRITE_RATE_CAPACITY` is non-zero.  
**Type:** Integer  
**Default:** `60`  
**Required:** No

**Metrics:**

- `ngit_private_rate_limited_total{path}` — rejections by path (`state_root`, `wrap`, `ewrap`, `upload`)

**Churn caveat (per-KEY, not per-IP):** the bucket is keyed by the event's
write pubkey, so an attacker cycling fresh keys gets a fresh bucket per key
and is NOT bounded by this limiter — the effective per-IP bounds are the
generic connection limit (`NGIT_MAX_CONNECTIONS`) plus the nginx rate zones
(docs/grasp-p/ops/nginx-upload-zones.conf). The bucket's real value is
bounding **registered** keys gone rogue (a compromised w-key can't exceed
its capacity/refill) and making quota-uncharged kind-21059 spam cost a key
per bucket instead of being free.

---

### GRASP-P Registration Replacement Cadence (Phase 4b)

Kind-30640 is addressable, so replacements are free — and each one
re-triggers sync index rebuilds plus derived-filter re-issues to all peers
within seconds. These knobs bound the same-tenant replacement rate per
`(tenant, alias)`. Unlike the write-rate bucket above, these knobs affect
**cross-node acceptance** (a same-tenant newer edition can be accepted on
one node and cadence-rejected on another), so they are part of the
`policy_fingerprint` preimage (label `grasp-p-policy-v3`) — paired nodes
MUST run identical values.

Rejected replacements are HELD by the relay and retried without any client
republish (FS-2/R2-1): the newest cadence-rejected edition per
`(tenant, alias)` bucket is kept in the rejected index — newest-only, so a
strictly newer edition replaces the held one and an older-or-equal one is
id-only dropped — and the 5s registration-sync timer re-offers it once the
wall-clock bucket has refilled (refill-aware eligibility: the per-token
refill period, clamped to [60s, 1h], with ±20% per-hold jitter). The hold
is bounded by a 1024-entry registrations sub-cap within the 4096-entry
global rejected-event hold and drains at most 64 retries per tick (FIFO,
oldest-insertion first). A retry still over cadence is re-held; an edition
that went stale while held is absorbed by the anchor-repair accept-no-op;
the hourly full re-issue (below) is the backstop healer for holds that
expire or overflow.

#### `NGIT_PRIVATE_REGISTRATION_REPLACE_CAPACITY`

**Description:** Per-`(tenant, alias)` token bucket capacity for same-tenant kind-30640 replacements. `0` = unlimited. Keep the burst at `>= 4`: a revocation rotation is widen→narrow = 2 replacements in quick succession, plus client error retries. Only same-tenant newer replacements are gated — new-alias registrations, stale editions (anchor repair), cross-tenant conflict merges (§3.2 hard invariant), and boot replays are exempt. Exceeding tenants receive NIP-20 OK false with `replacement rate-limited; retry later`.  
**Type:** Integer  
**Default:** `8`  
**Required:** No

#### `NGIT_PRIVATE_REGISTRATION_REPLACE_REFILL_PER_HOUR`

**Description:** Refill rate (replacements per hour) for the per-`(tenant, alias)` replacement bucket — bounds sustained replacement floods. Must be greater than `0` when `NGIT_PRIVATE_REGISTRATION_REPLACE_CAPACITY` is non-zero.  
**Type:** Integer  
**Default:** `4`  
**Required:** No

---

### GRASP-P Periodic Full Re-issue (Phase 4b)

Live delivery plus the index-change re-issue path cannot heal every gap:
rejected-hot-cache entries expire, negentropy reconciliation has blind
spots, and held cadence-limited kind-30640 rejections (above) can leave
the hold unaccepted (expiry/overflow). This timer re-issues the **current** private sync filters —
the Layer-1 kind-30640 registration filter plus the derived 30641 `#d` /
1059 author filters — to every live peer with `since=None` (full
backfill), with ±10% jitter so paired nodes do not fire in lockstep. With
an empty index (zero aliases) the bare 30640 filter is still re-issued as
a cheap self-heal for missed registrations. Public subscriptions are never
torn down (that remains `daily_sync` territory).

This is a node-local recovery knob: it does not affect acceptance, so it
is **not** part of the `policy_fingerprint` preimage and paired nodes may
run different values.

#### `NGIT_PRIVATE_FULL_REISSUE_INTERVAL_SECS`

**Description:** Interval in seconds between full re-issue rounds. `0` = disabled (not recommended outside single-node deployments: redelivery-dependent gaps then only heal on reconnect or the daily fresh sync).  
**Type:** Integer  
**Default:** `3600`  
**Required:** No

**Metrics:**

- `ngit_private_full_reissue_total` — rounds that ACTUALLY re-issued at least one live peer
- `ngit_private_full_reissue_skipped_total` — rounds where EVERY live relay was skipped (health-tracker rate-limit cooldown or the FS-3 re-issue floor below)

Alert only when BOTH stop increasing while private repos are enabled: a
flat delivered counter with a rising skipped counter means a
chronically-skipped peer (check the FS-3 floor value and peer health), not
a dead timer.

---

### GRASP-P Re-issue Floor (Phase 4b)

#### `NGIT_PRIVATE_REISSUE_MIN_INTERVAL_SECS`

**Description:** Minimum interval (seconds) between private sync-filter re-issues to the same peer, across BOTH triggers (PrivateSyncIndex-change-derived filter pushes and the `NGIT_PRIVATE_FULL_REISSUE_INTERVAL_SECS` full re-issue above). Past the 70-filter consolidation threshold, a churning derived-filter set would otherwise force a full consolidate (unsubscribe-all + resubscribe + since=None backfill) on every index-dirty 5s tick — at 128 aliases × the 4/hour replacement-cadence budget that is a dirty tick every ~7s, i.e. near-continuous consolidation. A re-issue skipped by this floor is retried once the interval lapses (deferred, never dropped). Node-local recovery knob only — acceptance is unaffected, so paired nodes may run different values (NOT part of the `policy_fingerprint` preimage).  
**Type:** Integer (seconds)  
**Default:** `30`  
**Required:** No  
**Special values:** `0` = unlimited (pre-FS-3 behavior).

---

### GRASP-P Blob Mirror Retry Backoff (Phase 4b)

The blob mirror classifies every fetch failure and gates **transient**
classes per blob with an exponential backoff (`base * 2^(attempt-1)`,
capped at `max`, ±20% jitter): transport errors, peer HTTP 5xx, no
available peer, and `404` on all peers — the latter always retries at the
max interval because a late upload is legitimate. **Deterministic**
classes (`quota`, `too_large`, `verify:`, `store:`, `blocked`, `reserve:`,
`sink:`, `write:`) are NOT gated: they keep the flat repair-scan cadence
and only succeed once the underlying condition changes (GC frees space,
config changes, …). Backoff-gated blobs stay counted in
`ngit_private_mirror_lag_blobs` — the gate suppresses re-enqueue, never
the gauge. There is no give-up: a referenced blob may legitimately appear
late. Retry state is in-memory only; a restart resets every blob to the
base interval (the boot repair scan re-derives all wants anyway).

These are node-local recovery knobs: they do not affect acceptance, so
they are **not** part of the `policy_fingerprint` preimage.

#### `NGIT_PRIVATE_MIRROR_RETRY_BASE_SECS`

**Description:** Base delay in seconds for the per-blob exponential retry backoff. Must be greater than `0` when `NGIT_PRIVATE_MIRROR_ENABLE=true`.  
**Type:** Integer  
**Default:** `60`  
**Required:** No

#### `NGIT_PRIVATE_MIRROR_RETRY_MAX_SECS`

**Description:** Cap in seconds for the retry backoff; also the fixed retry interval for blobs the peers answer `404` (possible late upload). Must be greater than or equal to `NGIT_PRIVATE_MIRROR_RETRY_BASE_SECS`.  
**Type:** Integer  
**Default:** `3600`  
**Required:** No

---

### GRASP-P Blob Denylist / Takedown (Phase 4b)

The denylist is the node-local legal takedown mechanism: blob sha256
digests this node must not serve (`GET`/`HEAD` → `451`), not accept
(upload preflight → `451`; in-flight uploads whose hash becomes denylisted
mid-stream fail at commit with `451`), not store (hashes newly present
after a reload are purged immediately — all claims freed, ledger charges
released, bytes unlinked), and not mirror (all mirror enqueue/fetch/lag
paths skip denylisted shas).

Paired nodes in different jurisdictions may legitimately run different
lists: the denylist is deliberately **not** part of the
`policy_fingerprint` preimage, and its enforcement never changes event
acceptance.

#### `NGIT_PRIVATE_DENYLIST_PATH`

**Description:** Comma-separated list of denylist files (per-node / per-jurisdiction lists), each containing one sha256 hex digest per line (trimmed, lowercased; blank/comment/garbage lines ignored). A **missing** file is tolerated (warning + treated as empty); a **present-but-unreadable** file is a hard boot error (fail loud on misconfiguration). Each file is capped at **64 MiB / 1M lines** (FS-6): exceeding either cap is a hard boot error, and on reload the file keeps its last-known entries with an error log every tick — the same boot-loud / reload-keep semantics as an unreadable file. Writers MUST update files **atomically** (write a temp file, then rename over the live path): the reload keys off mtime, and a torn write is a known staleness window. Unset = empty denylist.  
**Type:** String (comma-separated paths)  
**Default:** unset  
**Required:** No

#### `NGIT_PRIVATE_DENYLIST_RELOAD_SECS`

**Description:** Interval in seconds between denylist file reloads. Only changed files are re-read; the live set is swapped atomically. Hashes **newly present** after a reload are purged immediately (see above); hashes **removed** from the files unblock reads, but bytes already purged stay gone — clients must re-upload. `0` = reload disabled (the boot-time set is kept). During reload a present-but-unreadable file keeps its last-known entries and is retried every tick (a transient read error must not silently unblock taken-down content).  
**Type:** Integer  
**Default:** `60`  
**Required:** No

**Metrics:**

- `ngit_private_denylist_entries` — live denylist size (set at boot and on every reload swap); alert on an unexpected drop to 0
- `ngit_private_denylist_purged_total` — blobs purged because their sha256 is denylisted (reload purge-on-add + GC denylist sweep)

---

### Logging Configuration

#### `NGIT_LOG_LEVEL`

**Description:** Logging level and filters for application logging  
**Type:** String (log level or filter expression)  
**Default:** `info`  
**Required:** No

**Examples:**

```bash
# Simple levels
NGIT_LOG_LEVEL=error    # Errors only
NGIT_LOG_LEVEL=warn     # Warnings and errors
NGIT_LOG_LEVEL=info     # Info, warnings, errors (default)
NGIT_LOG_LEVEL=debug    # Debug and above
NGIT_LOG_LEVEL=trace    # Everything (very verbose)

# Module-specific filtering
NGIT_LOG_LEVEL=ngit_grasp=debug,actix_web=info

# Complex filters
NGIT_LOG_LEVEL=debug,hyper=info,tokio=warn
```

**Log levels (most to least verbose):**

1. `trace` - Very detailed, performance impact
2. `debug` - Detailed debugging information
3. `info` - General information (default)
4. `warn` - Warnings about potential issues
5. `error` - Errors only

**CLI flag:**

```bash
ngit-grasp --log-level trace
```

**Production recommendation:**

```bash
NGIT_LOG_LEVEL=info
```

**Notes:**

- Uses Rust's `tracing` crate filter syntax
- Supports module-level filtering (e.g., `ngit_grasp=debug,hyper=info`)
- `trace` level can significantly impact performance
- For production, `info` or `warn` is recommended

---

### Security Configuration (Planned)

#### `NGIT_AUTH_REQUIRED`

**Description:** Require authentication for all operations  
**Type:** Boolean  
**Default:** `false`  
**Status:** 🔜 Planned

**Examples:**

```bash
NGIT_AUTH_REQUIRED=true   # Require auth
NGIT_AUTH_REQUIRED=false  # Public relay
```

---

#### `NGIT_RATE_LIMIT_ENABLED`

**Description:** Enable rate limiting  
**Type:** Boolean  
**Default:** `true`  
**Status:** 🔜 Planned

**Examples:**

```bash
NGIT_RATE_LIMIT_ENABLED=true
NGIT_RATE_LIMIT_ENABLED=false
```

---

## Configuration File (.env)

For development, create a `.env` file in the project root:

```bash
# .env file example
NGIT_DOMAIN=localhost:7334
NGIT_OWNER_NPUB=npub1alice...
NGIT_RELAY_NAME="Development Relay"
NGIT_RELAY_DESCRIPTION="Local development instance"
NGIT_GIT_DATA_PATH=./data/git
NGIT_RELAY_DATA_PATH=./data/relay
NGIT_BIND_ADDRESS=127.0.0.1:7334
RUST_LOG=debug
```

**Notes:**

- Never commit `.env` to version control
- Use `.env.example` as a template
- Environment variables override `.env` values

---

## Validation

Configuration is validated at startup:

```rust
// Example validation errors:
Error: Invalid configuration
  - NGIT_DOMAIN is required
  - NGIT_OWNER_NPUB must start with 'npub1'
  - NGIT_GIT_DATA_PATH is not writable
```

**Validation checks:**

- Required fields are present
- Values have correct format
- Paths are accessible and writable
- Ports are available
- npub keys are valid

---

## Production Configuration Example

```bash
# Production .env
NGIT_DOMAIN=gitnostr.com
NGIT_OWNER_NPUB=npub1alice...
NGIT_RELAY_NAME="GitNostr Public Relay"
NGIT_RELAY_DESCRIPTION="Public GRASP relay for open source projects"
NGIT_GIT_DATA_PATH=/var/lib/ngit-grasp/git
NGIT_RELAY_DATA_PATH=/var/lib/ngit-grasp/relay
NGIT_BIND_ADDRESS=0.0.0.0:7334
RUST_LOG=info,ngit_grasp=debug
```

**Additional production considerations:**

- Use reverse proxy (nginx, Caddy) for HTTPS
- Set up log rotation
- Configure monitoring
- Implement backup strategy
- Use dedicated user account
- Set file permissions properly

---

## Development Configuration Example

```bash
# Development .env
NGIT_DOMAIN=localhost:7334
NGIT_OWNER_NPUB=npub1test...
NGIT_RELAY_NAME="Dev Relay"
NGIT_RELAY_DESCRIPTION="Local development"
NGIT_GIT_DATA_PATH=./data/git
NGIT_RELAY_DATA_PATH=./data/relay
NGIT_BIND_ADDRESS=127.0.0.1:7334
RUST_LOG=debug
```

---

## Testing Configuration Example

```bash
# Testing .env
NGIT_DOMAIN=localhost:9999
NGIT_OWNER_NPUB=npub1test...
NGIT_RELAY_NAME="Test Relay"
NGIT_RELAY_DESCRIPTION="Automated testing"
NGIT_GIT_DATA_PATH=/tmp/ngit-test/git
NGIT_RELAY_DATA_PATH=/tmp/ngit-test/relay
NGIT_BIND_ADDRESS=127.0.0.1:9999
RUST_LOG=debug
```

**Testing notes:**

- Use temporary directories
- Use non-standard ports
- Clean up after tests
- Isolate from development data

---

## Configuration Priority

When multiple configuration sources exist:

1. **Command-line arguments** (highest priority, planned)
2. **Environment variables**
3. **`.env` file**
4. **Default values** (lowest priority)

**Example:**

```bash
# .env file
NGIT_BIND_ADDRESS=127.0.0.1:7334

# Environment variable (overrides .env)
NGIT_BIND_ADDRESS=0.0.0.0:3000 cargo run

# Result: binds to 0.0.0.0:3000
```

---

## Related Documentation

- [Deployment How-To](../how-to/deploy.md) - Production deployment
- [Getting Started Tutorial](../tutorials/getting-started.md) - Initial setup
- [Architecture Overview](../explanation/architecture.md) - System design

---

_Part of the [ngit-grasp reference documentation](./)_
