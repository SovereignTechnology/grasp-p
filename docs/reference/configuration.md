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
