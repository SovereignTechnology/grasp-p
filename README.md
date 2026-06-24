# ngit-grasp

A [GRASP](https://gitworkshop.dev/danconwaydev.com/grasp) (Git Relays Authorized via Signed-Nostr Proofs) implementation in Rust.

## Overview

`ngit-grasp` is a Rust-based implementation of the GRASP protocol, which enables decentralized Git repository hosting with Nostr-based authorization. This implementation combines:

- **Git Smart HTTP Backend**: Serves Git repositories over HTTP
- **Nostr Relay**: Stores and validates repository announcements and state events
- **Integrated Authorization**: Validates Git pushes against Nostr state events without requiring external hooks

Unlike the reference implementation ([ngit-relay](https://gitworkshop.dev/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-relay)) which uses nginx + git-http-backend + pre-receive hooks + Khatru (Go), `ngit-grasp` provides a unified Rust service that handles both Git and Nostr protocols natively.

## Status

**Production Ready** - Full GRASP-01 and GRASP-02 implementation with comprehensive test coverage.

## Key Features

- **Pure Rust Implementation**: Single binary, no external dependencies beyond Git itself
- **Integrated Authorization**: Push validation happens inline during the Git receive-pack operation
- **GRASP-01 Compliant**: Core service requirements for Git hosting with Nostr authorization
  - **Flexible Curation & Moderation**: Repository whitelists (GRASP-01 mode), repository blacklists (moderation), and event blacklists (author blocking)
- **GRASP-02 Proactive Sync**: Sophisticated relay-to-relay event and git data synchronization
  - **NIP-77 Negentropy**: Efficient set reconciliation with automatic fallback to REQ+EOSE
  - **Live & Historic Sync**: Real-time event streaming plus catch-up for past events
  - **Smart Throttling**: Respectful rate limiting (5 concurrent, 30/min per domain) with exponential backoff
  - **Multi-Maintainer First-Class**: Internal sync of pushed git data across all maintainer repositories
  - **Intelligent Purgatory**: Auto-fetches missing git data from clone URLs when events arrive first
  - **Discovery-Driven**: Dynamically connects to relays listed in repository announcements
- **Deletion Lifecycle**: NIP-09 deletion requests, NIP-62 request-to-vanish, blacklist/whitelist parity, and service de-listing share one cascade/holding/archive/recovery path for related events and git data
- **Developer-Friendly**: Built with modern Rust async patterns using tokio and actix-web

## Architecture Highlights

### Inline Authorization (GRASP-01)

The key architectural decision is **inline authorization** rather than Git hooks:

- Vendored and customised `git-http-backend` crate provides low-level access to the Git protocol
- We intercept the `git-receive-pack` operation before spawning the Git process
- Push validation happens by checking the Nostr relay for the latest state event
- Only matching pushes are forwarded to the actual Git repository

This approach provides:

- **Better error messages**: Direct HTTP responses vs. hook stderr
- **Simpler deployment**: No hook management or symlinks
- **Tighter integration**: Shared state between Git and Nostr components
- **Easier testing**: Pure Rust unit and integration tests

### Deletion Lifecycle

ngit-grasp owns NIP-09/NIP-62 deletion handling in relay policy code, with
backend auto-processing disabled. Removed repository data flows through holding
storage and git archives for a configurable recovery window, while GRASP-aware
cascade deletion removes repository-related events that lose their accepted
reference path and the git data needed to serve them. Tombstones gate
re-submission and request-to-vanish authors where applicable. The same lifecycle
is reused for operator moderation and curation reconciliation (repository
blacklist, repository whitelist, and service de-listing), while
`NGIT_DELETION_REQUEST_DISRESPECTOR=true` stores but does not act on user
deletion/vanish requests for archival relays.

See [Repository Lifecycle](docs/explanation/repository-lifecycle.md) for details.

### Sophisticated Sync System (GRASP-02)

The proactive sync implementation is production-grade with advanced features:

**NIP-77 Negentropy with Intelligent Fallback:**

- Attempts efficient set reconciliation via NIP-77 for full syncs
- Automatically falls back to REQ+EOSE with pagination when negentropy unavailable
- Combines live subscriptions (`limit:0`) with historic catch-up

**Multi-Layer Filter Strategy:**

- **Layer 1**: Repository announcements and maintainer lists (connection-level)
- **Layer 2**: Events tagging repositories (a/A/q tags, batched per 100 repos)
- **Layer 3**: Events tagging root events (e/E/q tags, batched per 100 IDs)

**Connection Health Management:**

- Exponential backoff for failed connections (5s → 1 hour)
- Rate limit detection with 65-second cooldown
- Dead relay handling (24h+ failures → minimal retry)
- Quick reconnect (<15min) vs fresh start (>15min or daily)

**Intelligent Purgatory with Active Git Data Hunting:**

- Events without git data held in-memory for 30 minutes
- **User events**: 3-minute delay (expect git push to follow)
- **Synced events**: 500ms delay (batch burst arrivals, then hunt immediately)
- Proactively fetches missing data from clone URLs every 2 minutes
- Respectful throttling: 5 concurrent, 30 requests/min per domain
- Round-robin fairness across repositories
- Auto-release when data arrives, auto-expire after 30 minutes

**First-Class Multi-Maintainer Support:**

- Git data pushed to one maintainer's repo automatically syncs to all other maintainers
- Shared object databases for storage efficiency (planned)
- Seamless collaboration without manual coordination

See [GRASP-02 Proactive Sync](docs/explanation/grasp-02-proactive-sync.md) for full architectural details.

## GRASP Compliance

### GRASP-01 (Core Service Requirements) ✅

- ✅ NIP-01 compliant Nostr relay at `/`
- ✅ Accepts NIP-34 repository announcements and state events
- ✅ Git Smart HTTP service at `/<npub>/<identifier>.git`
- ✅ Push validation against Nostr state events
- ✅ Multi-maintainer support via recursive maintainer sets
- ✅ Support for `refs/nostr/<event-id>` for PRs
- ✅ Git capabilities: `allow-tip-sha1-in-want`, `allow-reachable-sha1-in-want`, `uploadpack.allowFilter`
- ✅ CORS support for web-based Git clients
- ✅ NIP-11 relay information document
- ✅ **Purgatory**: Events without git data held for 30 minutes, auto-released when data arrives
- ✅ **Deletion Lifecycle**: NIP-09/NIP-62 support with GRASP-aware cascade deletion, related git-data archival/removal, holding/archive recovery, and archival-relay disrespector mode

### GRASP-02 (Proactive Sync) ✅

- ✅ **Relay Discovery**: Automatically connects to relays listed in repository announcements
- ✅ **Event Sync**: Proactive sync from discovered relays using NIP-77 negentropy with REQ+EOSE fallback
  - Live subscriptions (`limit:0`) for real-time event streaming
  - Historic sync with automatic pagination for large result sets
  - Daily full reconciliation to detect drift
  - Connection health tracking with exponential backoff
- ✅ **Git Data Sync**: Automatic fetching of missing git data from clone URLs
  - Smart timing: 3min delay for user events, 500ms for synced events
  - Respectful throttling: 5 concurrent requests, 30/min per domain
  - Round-robin fairness across repositories
  - Exponential backoff with fresh start on new events
- ✅ **Multi-Maintainer Support**: Pushed git data automatically synced to all maintainer repositories
- ✅ **Comprehensive Monitoring**: Prometheus metrics for sync health, bandwidth, and relay status

**See**: [GRASP-02 Proactive Sync](docs/explanation/grasp-02-proactive-sync.md) and [Purgatory Git Data Sync](docs/explanation/grasp-02-proactive-sync-purgatory-git-data.md)

### GRASP-05 (Archive) ✅

- ✅ Accept repositories not listing this instance via configurable whitelist
- ✅ Three whitelist formats: `<npub>`, `<npub>/<identifier>`, `<identifier>`
- ✅ Read-only mirroring with full GRASP-02 sync (git data + Nostr events) - **default behavior**
- ✅ Archive-all mode for complete ecosystem mirrors
- ✅ Fail-fast npub validation at startup

**Archive mode enables backup/mirror operation** - accept repository announcements that don't list your relay, useful for creating archives of critical projects or running comprehensive mirrors. Archived repositories are read-only by default (`NGIT_ARCHIVE_READ_ONLY=true`) with full event and git data sync.

**See**: [GRASP-05 Archive Mode](docs/explanation/grasp-05-archive.md)

### GRASP-06 (Contributor PR Submission) — opt-in

- ✅ Unauthenticated `git push` endpoint at `/prs/<npub>/<identifier>.git` for contributors
- ✅ Accepts PR (kind 1618) and PR Update (kind 1619) `refs/nostr/<event-id>` refs for any repository, even without an accepted announcement
- ✅ Validity established by the signed PR event (no HTTP auth required)
- ✅ Inline zero-ref cleanup — no separate periodic sweep
- ✅ Advertised in NIP-11 `supported_grasps` when enabled
- ✅ Mirrored into accepted-announcement repos on the same relay when event and push match

**Disabled by default** — enable with `NGIT_GRASP06_ENABLE=true`. `/prs/` repos are isolated from proactive sync and repo listings; they are a submission side-channel, not first-class hosted repos.

**See**: [Enable GRASP-06](docs/how-to/enable-grasp-06.md) and [GRASP-06 Design](docs/explanation/grasp-06-contributor-pr-submission.md)

## Curation & Moderation

ngit-grasp provides flexible tools for both curation (repository selection) and moderation (blocking spam/abuse):

### Repository Whitelists (Curation)

Control which repositories your relay accepts via two independent whitelist modes:

**Repository Whitelist (GRASP-01 Mode):**
- Only accept announcements that **both** list your service AND match the whitelist
- Three formats: `<npub>`, `<npub>/<identifier>`, `<identifier>`
- Environment: `NGIT_REPOSITORY_WHITELIST=npub1alice...,bitcoin-core`
- Use case: Curated relay accepting specific projects/developers

**Archive Whitelist (GRASP-05 Mode):**
- Accept announcements matching the whitelist **even if they don't list your service**
- Same three formats as repository whitelist
- Environment: `NGIT_ARCHIVE_WHITELIST=npub1satoshi...,linux`
- Use case: Backup/mirror relay for critical projects
- Default: Read-only mode (`NGIT_ARCHIVE_READ_ONLY=true`)

Both whitelists support flexible matching:
```bash
# Accept all repos from specific developer
NGIT_REPOSITORY_WHITELIST=npub1alice...

# Accept specific repository
NGIT_REPOSITORY_WHITELIST=npub1alice.../my-project

# Accept repos with specific identifier (any author)
NGIT_REPOSITORY_WHITELIST=bitcoin-core
```

### Blacklists (Moderation)

Block unwanted content without affecting your curation policy:

**Repository Blacklist:**
- Block specific repositories/developers/identifiers
- **Takes precedence over ALL whitelists** (checked first)
- Three formats: `<npub>`, `<npub>/<identifier>`, `<identifier>`
- Environment: `NGIT_REPOSITORY_BLACKLIST=npub1spam...,malware-repo`
- Use case: Block spam/malware repos while maintaining whitelist curation

**Event Blacklist:**
- Block **ALL events** from specific authors (npubs)
- **Takes precedence over ALL other validation** (checked first)
- Applies to all event types: announcements, state events, PRs, comments, etc.
- Events never reach relay storage or purgatory
- Environment: `NGIT_EVENT_BLACKLIST=npub1spammer...,npub1abuser...`
- Use case: Block abusive users completely

### Precedence & Interaction

Validation order (from first to last):

1. **Event Blacklist** → Reject if author is blacklisted (ALL event types)
2. **Repository Blacklist** → Reject if repository/npub/identifier is blacklisted (announcements only)
3. **Repository Whitelist** → Accept if announcement lists service AND matches whitelist
4. **Archive Whitelist** → Accept if announcement matches whitelist (even without listing service)
5. **Default GRASP-01** → Accept if announcement lists service (no whitelist configured)

Examples:
```bash
# Curated relay blocking spam
NGIT_REPOSITORY_WHITELIST=npub1alice...,npub1bob...
NGIT_REPOSITORY_BLACKLIST=npub1alice.../spam-repo
NGIT_EVENT_BLACKLIST=npub1spammer...
# Result: Accept Alice & Bob's repos EXCEPT Alice's spam-repo, block all events from spammer

# Archive relay with moderation
NGIT_ARCHIVE_WHITELIST=bitcoin-core,linux
NGIT_EVENT_BLACKLIST=npub1abuser...
# Result: Mirror bitcoin-core and linux projects, block all events from abuser

# Public relay with spam protection
NGIT_EVENT_BLACKLIST=npub1spam1...,npub1spam2...
# Result: Accept all GRASP-01 repos, block all events from spammers
```

**Privacy & Transparency:**
- Blacklists are **not advertised** in NIP-11 metadata (operational, not curation policy)
- Rejected events receive specific error messages for operator debugging
- No client-visible indication that blacklists are in use

**See**: [Configuration Reference](docs/reference/configuration.md) for complete details

## Defensive Measures & Rate Limiting

ngit-grasp implements multiple layers of defense against abuse, spam, and denial-of-service attacks:

**Per-Connection Rate Limits:**
- Max 500 concurrent subscriptions per connection
- Max 60 events published per minute per connection
- Built-in to rust-nostr relay-builder

**Per-IP Connection Monitoring:**
- Tracks connections per IP address (default threshold: 10)
- Flags potential abusers in logs and metrics
- **Does NOT enforce limits** (monitoring only)
- Privacy-preserving (IP addresses never exposed in Prometheus)

**Content Filtering (Blacklists/Whitelists):**
- **Event blacklist** - Block ALL events from specific authors (npubs)
- **Repository blacklist** - Block specific repositories/developers/identifiers
- **Repository whitelist** - Curate which repositories are accepted (GRASP-01 mode)
- **Archive whitelist** - Mirror specific repositories (GRASP-05 mode)
- See [Curation & Moderation](#curation--moderation) section above for details

**Relay Sync Protection (GRASP-02):**
- **Exponential backoff** - Failed connections: 5s → 10s → 20s → ... → 1 hour max
- **Naughty list** - Track relays with infrastructure issues separately (12h expiry)
- **Rate limit detection** - Auto 65s cooldown when remote relays rate limit us
- **Domain throttling** - Max 5 concurrent, 30/min per domain for git data fetching

**Event Validation:**
- Strict GRASP-01 protocol validation via WritePolicy plugin system
- Extensible for custom validation logic (has access to client IP address)

**Total Connection Limit:**
- Max 500 total connections (configurable via `NGIT_MAX_CONNECTIONS`)
- Prevents connection exhaustion DoS attacks

**Not Implemented:**
- Per-IP connection limits (only monitored, not enforced)
- Per-IP event rate limits (tracked per connection, not per IP)

**See**: [Defensive Measures](docs/explanation/defensive-measures.md) for complete details and future enhancements.

## Roadmap

### GRASP-02 Enhancements

**Proactive Sync Plus:**

- 🔄 Scan read/write relays of repo/PR/Patch/Issue authors for related comments
- 🔄 Stricter anti-spam mechanisms for author relay events
- 🔄 Periodic scanning of relays in User Grasp Lists for announcements listing our relay

### Data Efficiency

**Git Object Deduplication:**

- 🔄 Shared object database across repositories
- 🔄 Use `GIT_ALTERNATE_OBJECT_DIRECTORIES` or `.git/objects/info/alternates`
- 🔄 Significant storage savings for multi-maintainer repositories

### Monitoring & Observability

ngit-grasp exposes comprehensive Prometheus metrics at `/metrics` for:

**Git Operations:**

- Clone/fetch/push rates and bandwidth
- Authorization results (accepted/rejected)
- Top N repositories by bandwidth

**Nostr Events:**

- WebSocket connections (active, unique IPs, flagged abusers)
- Events received, stored, rejected by kind
- Purgatory status (events waiting for git data)

**Sync Health (GRASP-02):**

- Per-relay connection status and health states
- Event sync rates and bandwidth
- Git data fetch attempts and success rates
- Domain throttling metrics

**Configuration Options:**

| Option                     | CLI Flag                                      | Environment Variable                             | Default |
| -------------------------- | --------------------------------------------- | ------------------------------------------------ | ------- |
| Metrics enabled            | `--metrics-enabled`                           | `NGIT_METRICS_ENABLED`                           | `true`  |
| Connection abuse threshold | `--metrics-connection-per-ip-abuse-threshold` | `NGIT_METRICS_CONNECTION_PER_IP_ABUSE_THRESHOLD` | `10`    |
| Top N repos                | `--metrics-top-n-repos`                       | `NGIT_METRICS_TOP_N_REPOS`                       | `10`    |

**Privacy:** IP addresses are never exposed in metrics - only aggregate counts.

See [Monitoring Overview](docs/explanation/monitoring.md) and [Prometheus Setup Guide](docs/how-to/prometheus-setup.md) for deployment.

### Deletion Lifecycle Follow-ups

NIP-09/NIP-62 deletion handling, holding/archive retention, recovery, blacklist
and whitelist reconciliation, archival disrespector mode, and service de-listing
removal are implemented. Remaining work is operator-facing UX: richer holding
management, explicit restore commands, and optional delayed archival policies.

See [Repository Lifecycle](docs/explanation/repository-lifecycle.md).

### Mitigate DoS attack vector

Grasp servers can be DoS by pushing large amounts of git data to `refs/nostr/<event-id>` without having to first submit a signed nostr event. operators must temporarily disable pushes to `refs/nostr/*` without having recieved a signed event. This breaks the flow of sending PR / Update events in NIP-34 as the client doesnt know if the grasp server will accept git data / event so might include it as a server hint in `clone` without knowing whether the server will accept the data. Could an ephemeral event be sent to authorise or is that too complicated? Maybe require NIP-42 auth and authorise that IP address for the push based on WoT?

### Reject Commits with Secrets

This a useful feature of other git servers.

### Store all user grasp lists (for better grasp discovery)

✅ **Implemented**: Kind 10317 (User Grasp List) events are now accepted and synced from all relays for better GRASP repository discovery.

**Future enhancement**: We aspire to also accept and weekly sync kind 10002 (user relay lists) and kind 0 (user metadata) events, but only for authors of accepted events. This would require an additional state-driven layer 2 filter (see Roadmap in GRASP-02 Proactive Sync documentation).

**Future enhancement**: should we periodically scan relays in UserGraspLists to check for announcements that list our relay?

## Technology Stack

- **Rust**: Core language
- **actix-web**: HTTP server framework
- **git-http-backend**: Git protocol handling but vendored and customised for authorisation logic
- **nostr-relay-builder**: Nostr relay infrastructure from rust-nostr
- **nostr-sdk**: Nostr event handling and validation
- **tokio**: Async runtime

## Quick Start

```bash
# install ngit
curl -Ls https://ngit.dev/install.sh | bash

# Clone the repository
git clone nostr://danconwaydev.com/relay.ngit.dev/ngit-grasp
cd ngit-grasp

# Build (using Nix for reproducible environment)
nix develop -c cargo build --release

# Configure
cp .env.example .env
# Edit .env with your settings
# Required: NGIT_DOMAIN=your-domain.com
# Optional: NGIT_SYNC_BOOTSTRAP_RELAY_URL=wss://relay.example.com

# Run
nix develop -c cargo run --release

# Run tests
nix develop -c cargo test --lib
```

**What happens on startup:**

- Git HTTP server starts on configured bind address
- Nostr relay begins accepting WebSocket connections
- If bootstrap relay configured, sync system connects and discovers repositories
- Purgatory system activates, ready to hunt for missing git data
- Prometheus metrics exposed at `/metrics`

**Don't have Nix?** See [Getting Started Tutorial](docs/tutorials/getting-started.md) for alternative setup methods.

## Configuration

Configuration is loaded with the following priority (highest to lowest):

1. **CLI flags** (e.g., `--domain example.com`)
2. **Environment variables** (e.g., `NGIT_DOMAIN=example.com`)
3. **.env file** (loaded automatically if present)
4. **Built-in defaults**

This means CLI flags always take precedence over environment variables, which take precedence over `.env` file values.

### CLI Usage

```bash
# View all options with defaults
ngit-grasp --help

# Run with CLI flags (override everything else)
ngit-grasp --domain relay.example.com --relay-owner-nsec nsec1... --bind-address 0.0.0.0:7334

# Mix CLI flags with environment variables
NGIT_RELAY_OWNER_NSEC=nsec1... ngit-grasp --domain relay.example.com
```

### Configuration Options

#### Core Settings

| Option            | CLI Flag              | Environment Variable     | Default                                      |
| ----------------- | --------------------- | ------------------------ | -------------------------------------------- |
| Domain            | `--domain`            | `NGIT_DOMAIN`            | (required)                                   |
| Relay owner nsec  | `--relay-owner-nsec`  | `NGIT_RELAY_OWNER_NSEC`  | `.relay-owner.nsec` file (auto-generated)    |
| Relay name        | `--relay-name`        | `NGIT_RELAY_NAME`        | `${domain} grasp relay`                      |
| Relay description | `--relay-description` | `NGIT_RELAY_DESCRIPTION` | `Git Nostr Relay - a grasp implementation`   |
| Git data path     | `--git-data-path`     | `NGIT_GIT_DATA_PATH`     | `./data/git` (temp dir for memory backend)   |
| Relay data path   | `--relay-data-path`   | `NGIT_RELAY_DATA_PATH`   | `./data/relay` (temp dir for memory backend) |
| Bind address      | `--bind-address`      | `NGIT_BIND_ADDRESS`      | `127.0.0.1:7334` (NGIT on phone keypad)      |
| Database backend  | `--database-backend`  | `NGIT_DATABASE_BACKEND`  | `lmdb`                                       |

#### GRASP-02 Sync Settings

| Option                    | CLI Flag                                | Environment Variable                       | Default         |
| ------------------------- | --------------------------------------- | ------------------------------------------ | --------------- |
| Bootstrap relay           | `--sync-bootstrap-relay-url`            | `NGIT_SYNC_BOOTSTRAP_RELAY_URL`            | (optional)      |
| Base backoff              | `--sync-base-backoff-secs`              | `NGIT_SYNC_BASE_BACKOFF_SECS`              | `5` seconds     |
| Max backoff               | `--sync-max-backoff-secs`               | `NGIT_SYNC_MAX_BACKOFF_SECS`               | `3600` (1 hour) |
| Disconnect check interval | `--sync-disconnect-check-interval-secs` | `NGIT_SYNC_DISCONNECT_CHECK_INTERVAL_SECS` | `60` seconds    |
| Disable negentropy        | `--sync-disable-negentropy`             | `NGIT_SYNC_DISABLE_NEGENTROPY`             | `false`         |
| Batch window              | N/A                                     | `NGIT_SYNC_BATCH_WINDOW_MS`                | `5000` ms       |

#### Curation & Moderation Settings

| Option               | CLI Flag                    | Environment Variable           | Default   |
| -------------------- | --------------------------- | ------------------------------ | --------- |
| Repository whitelist | `--repository-whitelist`    | `NGIT_REPOSITORY_WHITELIST`    | (empty)   |
| Archive whitelist    | `--archive-whitelist`       | `NGIT_ARCHIVE_WHITELIST`       | (empty)   |
| Archive all          | `--archive-all`             | `NGIT_ARCHIVE_ALL`             | `false`   |
| Archive read-only    | `--archive-read-only`       | `NGIT_ARCHIVE_READ_ONLY`       | (auto)    |
| Repository blacklist | `--repository-blacklist`    | `NGIT_REPOSITORY_BLACKLIST`    | (empty)   |
| Event blacklist      | `--event-blacklist`         | `NGIT_EVENT_BLACKLIST`         | (empty)   |

#### Deletion Lifecycle Settings

| Option                        | CLI Flag                          | Environment Variable                 | Default             |
| ----------------------------- | --------------------------------- | ------------------------------------ | ------------------- |
| Disrespect user delete/vanish | `--deletion-request-disrespector` | `NGIT_DELETION_REQUEST_DISRESPECTOR` | `false`             |
| Holding retention             | `--holding-retention-secs`        | `NGIT_HOLDING_RETENTION_SECS`        | `7776000` (90 days) |
| Holding cleanup interval      | `--holding-cleanup-interval-secs` | `NGIT_HOLDING_CLEANUP_INTERVAL_SECS` | `86400` (1 day)     |
| Blacklist auto-restore        | `--blacklist-auto-restore`        | `NGIT_BLACKLIST_AUTO_RESTORE`        | `false`             |

**Sync Notes:**

- **Bootstrap relay**: Optional starting point for relay discovery. System automatically discovers additional relays from repository announcements. URL scheme is optional - if not provided, `wss://` is assumed (e.g., `git.shakespeare.diy` → `wss://git.shakespeare.diy`).
- **Backoff settings**: Controls exponential backoff for failed connections (`base * 2^(failures-1)`, capped at max).
- **Negentropy**: Can be disabled for testing REQ+EOSE fallback behavior.
- **Batch window**: Self-subscriber batches events for this duration before triggering sync filters.

### Database Backends

- `lmdb`: LMDB backend (default, persistent, general purpose)
- `memory`: In-memory database (fastest, no persistence - uses temp directories)

> **Note:** When using the `memory` backend, git data are automatically stored in temporary directories for ephemeral testing.

### Example: Production Deployment

```bash
# Using environment variables (recommended for production)
export NGIT_DOMAIN=gitnostr.com
export NGIT_RELAY_OWNER_NSEC=nsec1...  # Or let it auto-generate from .relay-owner.nsec
export NGIT_BIND_ADDRESS=0.0.0.0:7334
export NGIT_DATABASE_BACKEND=lmdb

# Optional: Enable proactive sync from a bootstrap relay
export NGIT_SYNC_BOOTSTRAP_RELAY_URL=wss://relay.damus.io

# Optional: Tune sync behavior
export NGIT_SYNC_BASE_BACKOFF_SECS=5      # Start backoff at 5 seconds
export NGIT_SYNC_MAX_BACKOFF_SECS=3600    # Cap backoff at 1 hour

ngit-grasp
```

**Production Tips:**

- Set `NGIT_SYNC_BOOTSTRAP_RELAY_URL` to a well-connected relay for initial repository discovery
- The system will automatically discover and connect to additional relays listed in repository announcements
- Monitor sync health via Prometheus metrics at `/metrics`
- Purgatory will automatically fetch missing git data from clone URLs

### Example: Development

```bash
# Using .env file
cp .env.example .env
# Edit .env with your settings
ngit-grasp

# Or override specific values with CLI flags
ngit-grasp --domain localhost:3000 --bind-address 127.0.0.1:3000
```

## Documentation

We use the **[Diátaxis](https://diataxis.fr/)** framework for documentation:

- **[Tutorials](docs/tutorials/)** - Learn by doing (Getting Started, First Audit)
- **[How-To Guides](docs/how-to/)** - Solve specific problems (Deploy, Configure)
- **[Reference](docs/reference/)** - Look up technical details (Config, Protocols)
- **[Explanation](docs/explanation/)** - Understand concepts (Architecture, Decisions)

**Start here:** [Documentation Index](docs/README.md)

## Development

See [Architecture Overview](docs/explanation/architecture.md) for system design and [Test Strategy](docs/reference/test-strategy.md) for testing approach.

### Running Tests

We have two test suites:

**1. Main Project Tests (ngit-grasp)**

```bash
# Run unit tests (no external dependencies)
nix develop -c cargo test --lib

# Run all integration tests (automatic relay management)
nix develop -c cargo test --test nip01_compliance --test nip34_announcements

# Run NIP-01 compliance tests
nix develop -c cargo test --test nip01_compliance

# Run NIP-34 announcement tests
nix develop -c cargo test --test nip34_announcements

# With detailed output
nix develop -c cargo test --test nip01_compliance -- --nocapture

# Run specific test
nix develop -c cargo test --test nip01_compliance test_nip01_smoke
```

**Integration tests automatically:**

- Start a fresh relay instance
- Run compliance tests using grasp-audit library
- Clean up when done
- No manual relay management needed!

**2. GRASP Audit Tool (grasp-audit)**

The audit tool tests GRASP compliance of any relay (including ours or external ones).
It is a member of the same workspace, so run it with `-p grasp-audit` from anywhere.

```bash
# Run unit tests
nix develop -c cargo test -p grasp-audit

# Test against any relay (including external ones)
nix develop -c cargo run -p grasp-audit -- --url wss://relay.example.com
```

### Development Commands

```bash
# Run with logging
RUST_LOG=debug nix develop -c cargo run

# Check code
nix develop -c cargo clippy
nix develop -c cargo fmt --check

# Generate test coverage (requires tarpaulin)
nix develop -c cargo tarpaulin --out Html
```

**Note:** Always use `nix develop` to ensure the correct build environment. See [docs/how-to/nix-flakes.md](docs/how-to/nix-flakes.md) for details.

## Project Structure

```
ngit-grasp/
├── src/
│   ├── main.rs              # Entry point, server setup
│   ├── lib.rs               # Library exports
│   ├── config.rs            # Configuration (core + sync settings)
│   ├── git/
│   │   ├── mod.rs           # Git module + repository operations
│   │   ├── handlers.rs      # Git HTTP handlers
│   │   ├── authorization.rs # Push validation logic (checks DB + purgatory)
│   │   ├── protocol.rs      # Git protocol encoding
│   │   └── subprocess.rs    # Git subprocess management
│   ├── nostr/
│   │   ├── mod.rs           # Nostr module
│   │   ├── builder.rs       # Relay builder + Nip34WritePolicy
│   │   ├── events.rs        # Event parsing and validation
│   │   └── policy/          # Sub-policies (split for maintainability)
│   │       ├── mod.rs       # Policy module exports
│   │       ├── announcement.rs  # Repository announcement validation
│   │       ├── state.rs     # State event validation + ref alignment
│   │       ├── pr_event.rs  # PR/PR Update validation
│   │       └── related.rs   # Forward/backward reference checking
│   ├── sync/                # GRASP-02 Proactive Sync (relay-to-relay)
│   │   ├── mod.rs           # SyncManager, main loop, data structures
│   │   ├── algorithms.rs    # derive_relay_targets(), compute_actions()
│   │   ├── filters.rs       # 3-layer filter building (announcements, repos, events)
│   │   ├── health.rs        # RelayHealthTracker (backoff, rate limits)
│   │   ├── relay_connection.rs # RelayConnection, event loop lifecycle
│   │   ├── self_subscriber.rs  # SelfSubscriber (batched event discovery)
│   │   └── metrics.rs       # SyncMetrics for Prometheus
│   ├── purgatory/           # In-memory holding area for events awaiting git data
│   │   ├── mod.rs           # Purgatory core (state/PR storage, 30min expiry)
│   │   ├── helpers.rs       # State event ref matching, PR lookup
│   │   ├── processing.rs    # Unified git data processing (push + sync paths)
│   │   └── sync/            # Proactive git data fetching
│   │       ├── mod.rs       # Public API (enqueue, main loop)
│   │       ├── loop.rs      # Sync loop (1s interval, debounced delays)
│   │       ├── functions.rs # Core sync logic (try URLs, handle results)
│   │       ├── queue.rs     # SyncQueue (backoff, fresh start on new events)
│   │       ├── throttle.rs  # DomainThrottle (5 concurrent, 30/min, round-robin)
│   │       └── context.rs   # SyncContext trait + mock for testing
│   ├── http/
│   │   ├── mod.rs           # HTTP module
│   │   ├── landing.rs       # Landing page handler
│   │   └── nip11.rs         # NIP-11 relay info document
│   └── metrics/
│       ├── mod.rs           # Prometheus metrics (Git, Nostr, Sync)
│       ├── bandwidth.rs     # Bandwidth tracking
│       └── connection.rs    # Connection tracking
├── docs/                    # Documentation (Diátaxis framework)
│   ├── explanation/         # Architecture, decisions, GRASP-02 deep-dives
│   ├── how-to/              # Deployment, configuration guides
│   ├── tutorials/           # Getting started, first steps
│   └── reference/           # API docs, test strategy
├── tests/                   # Integration tests (NIP-01, NIP-34, purgatory)
├── grasp-audit/             # Compliance audit crate (workspace member)
└── README.md
```

## Comparison with ngit-relay

| Feature             | ngit-relay (Go)                           | ngit-grasp (Rust)                                    |
| ------------------- | ----------------------------------------- | ---------------------------------------------------- |
| Language            | Go                                        | Rust                                                 |
| Components          | nginx + git-http-backend + hooks + Khatru | Single integrated binary                             |
| Authorization       | Pre-receive Git hook                      | Inline during receive-pack                           |
| GRASP-01            | ✅ Complete                               | ✅ Complete                                          |
| GRASP-02 Event Sync | ✅ Limited                                | ✅ Advanced (NIP-77 negentropy + fallback)           |
| GRASP-02 Git Sync   | ✅ Basic                                  | ✅ Automatic purgatory hunting                       |
| GRASP-06 PR Submit  | ❌                                        | ✅ Opt-in (`NGIT_GRASP06_ENABLE`)                   |
| Multi-Maintainer    | ✅ Supported                              | ✅ First-class (auto-sync across repos)              |
| Purgatory           | ✅ 24-hour expiry                         | ✅ 30-minute expiry + proactive git data fetching    |
| Health Tracking     | Basic                                     | Advanced (exponential backoff, rate limit detection) |
| Deployment          | Docker + supervisord                      | Single binary                                        |
| Testing             | Go tests + shell scripts                  | Rust unit + integration tests                        |
| Performance         | Good                                      | Excellent (zero-copy, async)                         |
| Monitoring          | Basic logs                                | Comprehensive Prometheus metrics                     |

## Contributing

Contributions welcome! Please:

1. Read [docs/explanation/architecture.md](docs/ARCHITECTURE.md)
2. Open an issue to discuss major changes
3. Follow Rust conventions and run `cargo fmt` + `cargo clippy`
4. Add tests for new functionality

## License

MIT License - see [LICENSE](LICENSE) for details

## Related Projects

- [GRASP Protocol](https://gitworkshop.dev/danconwaydev.com/grasp) - Protocol specification
- [ngit-relay](https://gitworkshop.dev/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-relay) - Reference implementation in Go
- [ngit](https://gitworkshop.dev/ngit) - Nostr Git plugin for git CLI
- [NIP-34](https://nips.nostr.com/34) - Git Stuff (Nostr protocol)

## Acknowledgments

- Reference implementation by [@DanConwayDev](https://gitworkshop.dev/danconwaydev.com)
- [rust-nostr](https://github.com/rust-nostr/nostr) team for excellent Nostr libraries
- Git community for the Smart HTTP protocol
