# ngit-grasp, with GRASP-P

A [GRASP](https://gitworkshop.dev/danconwaydev.com/grasp) (Git Relays Authorized via Signed-Nostr Proofs) implementation in Rust.

## SovTech fork: GRASP-P (experimental, work in progress)

> **Experimental, work in progress.** This repository is SovTech's fork of
> ngit-grasp carrying GRASP-P, an early prototype. GRASP-P has not been
> independently security-audited, its events, blob routes and configuration may
> change incompatibly without notice, and there is no stability or support
> guarantee. Do not rely on it for anything you cannot afford to lose or leak.

**What GRASP-P is:** private git repositories hosted on a public Nostr/GRASP
server whose operator is **not trusted**. The client encrypts everything before
upload; the server stores only ciphertext and opaque public keys, checks
signatures, enforces quotas and moves bytes. It is a different model from
GRASP-08, which gates access to a server that still reads plaintext.

| Part | Repo | Role |
|---|---|---|
| **GRASP-P** | this one (`src/grasp_p/`, `src/http/blossom.rs`) | Server extension to ngit-grasp |
| **CORD-git** | [cord-git](https://github.com/SovereignTechnology/cord-git) | Client: keys, encryption, membership, invites |

Start with [`docs/grasp-p/OVERVIEW.md`](docs/grasp-p/OVERVIEW.md) (one page), then the
server draft [`docs/grasp-p/grasp-xx-draft.md`](docs/grasp-p/grasp-xx-draft.md) and the full
convention [`docs/grasp-p/CORD-git-v0-spec.md`](docs/grasp-p/CORD-git-v0-spec.md).

**Upstream:** everything outside GRASP-P is [ngit-grasp](https://gitworkshop.dev/danconwaydev.com/grasp)
by DanConwayDev and contributors, MIT-licensed; this fork tracks its releases
(currently v3.0.7, see [`docs/grasp-p/SEAMS.md`](docs/grasp-p/SEAMS.md) for where the two meet).
The rest of this README is upstream's and describes upstream's features. It is not
an upstream project, and upstream is not responsible for GRASP-P.

**Where it lives:**

- Canonical repository, on Nostr (clone with [ngit](https://ngit.dev)):
  `nostr://npub1s0vtechh66tx7vrwdud8zfyheu9zca7swwfrzd4qu2a4f93mxs6qvn9adx/git.sovit.xyz/grasp-p`
- GitHub: [SovereignTechnology/grasp-p](https://github.com/SovereignTechnology/grasp-p), a read-only mirror.
  Send patches and pull requests over Nostr with ngit.

## Overview

`ngit-grasp` is a Rust-based implementation of the GRASP protocol, which enables decentralized Git repository hosting with Nostr-based authorization. This implementation combines:

- **Git Smart HTTP Backend**: Serves Git repositories over HTTP
- **Nostr Relay**: Stores and validates repository announcements and state events
- **Relay Owner Identity**: Root-mounted relays serve `_@domain` through NIP-05; every deployment seeds a minimal bot profile and single-relay NIP-65 list and trusts service events signed by the relay owner
- **Integrated Authorization**: Validates Git pushes against Nostr state events without requiring external hooks

## Status

**Upstream ngit-grasp: production ready** - Full GRASP-01 and GRASP-02 support,
default-on GRASP-03 Sync+, and opt-in GRASP-05, GRASP-06, and GRASP-08 profiles
with comprehensive test coverage.

**GRASP-P (this fork's addition): experimental, work in progress.** See
[the section above](#sovtech-fork-grasp-p-experimental-work-in-progress).

## Key Features

- **Pure Rust Implementation**: Single binary, no external dependencies beyond Git itself
- **Integrated Authorization**: Push validation happens inline during the Git receive-pack operation
- **GRASP-01 Compliant**: Core service requirements for Git hosting with Nostr authorization
  - **Flexible Curation & Moderation**: Repository whitelists (GRASP-01 mode), repository blacklists (moderation), and event blacklists (author blocking)
- **GRASP-02 & GRASP-03 Sync**: Proactive repository sync plus Nostr outbox mailbox discovery
  - **NIP-77 Negentropy**: Efficient set reconciliation with automatic fallback to REQ+EOSE
  - **Live & Historic Sync**: Real-time event streaming plus catch-up for past events
  - **Conversation Recovery**: Discovers accepted thread activity from participants' NIP-65 inboxes and outboxes
  - **Bounded Discovery**: Sanitizes peer relay URLs, limits per-author mailbox selection, and falls back to operator-selected relays when necessary
  - **Smart Throttling**: Respectful rate limiting (5 concurrent, 30/min per domain) with exponential backoff
  - **Multi-Maintainer First-Class**: Internal sync of pushed git data across all maintainer repositories
  - **Intelligent Purgatory**: Auto-fetches missing git data from clone URLs when events arrive first
  - **Discovery-Driven**: Dynamically connects to relays listed in repository announcements
- **GRASP-08 Private Services**: Optional service-wide NIP-42/NIP-98 authentication with private-to-private relay synchronization
- **Identifier-Family Git Storage**: Deduplicates objects across owner and contributor views while keeping their refs and authorization isolated
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

### Sophisticated Sync System (GRASP-02 & GRASP-03)

GRASP-02 provides proactive repository sync, while the default-on GRASP-03
Sync+ overlay recovers related conversations from participants' Nostr
mailboxes.

**NIP-77 Negentropy with Intelligent Fallback:**

- Attempts efficient set reconciliation via NIP-77 for full syncs
- Automatically falls back to REQ+EOSE with pagination when negentropy unavailable
- Combines live subscriptions (`limit:0`) with historic catch-up

**Multi-Layer Filter Strategy:**

- **Layer 1**: Repository announcements and maintainer lists (connection-level)
- **Layer 2**: Events tagging repositories (a/A/q tags, batched per 100 repos)
- **Layer 3**: Events tagging root events (e/E/q tags, batched per 100 IDs)

**NIP-65 Mailbox Discovery (GRASP-03):**

- Discovers eligible owners, maintainers, root authors, and conversation participants through user-index relays and retained NIP-65 lists
- Keeps accepted root-author inboxes in ordinary live/rotating coverage while probing broader participant mailboxes with thread-scoped historical queries
- Probes owners' and maintainers' bounded inboxes for repository-scoped history on public instances, recovering roots and replies published away from repository relays
- Uses operator-configured fallback relays when an eligible author has no accepted NIP-65 list
- Sanitizes and canonicalizes peer relay URLs, with at most four selected relays per author and purpose
- Reuses GRASP-02 connection pacing, subscription budgets, pagination, validation, and persistence

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
- Identifier-family object storage shares Git objects across related owner and GRASP-06 contributor views
- Thin repository views preserve independent refs, HEAD, and authorization while reusing family history
- Seamless collaboration without manual coordination

See [GRASP-02 Proactive Sync](docs/explanation/grasp-02-proactive-sync.md) and
[GRASP-03 Proactive Sync Plus](docs/explanation/grasp-03-proactive-sync-plus.md)
for sync architecture, and
[Identifier-Family Git Object Storage](docs/explanation/git-family-object-storage.md)
for the shared storage model.

## GRASP Compliance

### GRASP-01 (Core Service Requirements) ✅

- ✅ NIP-01 compliant Nostr relay at `/`
- ✅ Accepts NIP-34 repository announcements and state events
- ✅ Git Smart HTTP service at `/<npub>/<identifier>.git`
- ✅ Push validation against Nostr state events
- ✅ Multi-maintainer support via active lead resolution and reciprocal confirmation
- ✅ Support for `refs/nostr/<event-id>` for PRs
- ✅ Git capabilities: `allow-tip-sha1-in-want`, `allow-reachable-sha1-in-want`, `uploadpack.allowFilter`
- ✅ CORS support for web-based Git clients
- ✅ NIP-11 relay information document
- ✅ NIP-05 `_@domain` identity backed by the relay operator public key when the relay is mounted at `/`
- ✅ Relay-owner kind-0 bot profile and kind-10002 read/write list seeded locally when absent and published to user-index relays
- ✅ **Purgatory**: Events without git data held for 30 minutes, auto-released when data arrives
- ✅ **Deletion Lifecycle**: NIP-09/NIP-62 support with GRASP-aware cascade deletion, related git-data archival/removal, holding/archive recovery, and archival-relay disrespector mode

### GRASP-02 & GRASP-03 (Proactive Sync and Sync+) ✅

- ✅ **GRASP-02 Relay Discovery**: Automatically connects to relays listed in repository announcements
- ✅ **GRASP-02 Event Sync**: Proactive sync from discovered relays using NIP-77 negentropy with REQ+EOSE fallback
  - Live subscriptions (`limit:0`) for real-time event streaming
  - Historic sync with automatic pagination for large result sets
  - Daily full reconciliation to detect drift
  - Connection health tracking with exponential backoff
- ✅ **GRASP-02 Git Data Sync**: Automatic fetching of missing git data from clone URLs
  - Smart timing: 3min delay for user events, 500ms for synced events
  - Respectful throttling: 5 concurrent requests, 30/min per domain
  - Round-robin fairness across repositories
  - Exponential backoff with fresh start on new events
- ✅ **GRASP-02 Multi-Maintainer Support**: Pushed git data automatically synced to all maintainer repositories
- ✅ **GRASP-03 Mailbox Discovery**: Finds accepted conversation activity through eligible authors' NIP-65 read/write relays
  - Default-on with an explicit opt-out and conditional NIP-11 advertisement
  - Thread-scoped historic probes for accepted participants
  - Repository-scoped historic probes for owners and maintainers on public instances
  - Bounded recursive descendant discovery and per-author relay selection
  - User-index discovery with operator-configured mailbox fallbacks
- ✅ **Comprehensive Monitoring**: Prometheus metrics for sync health, bandwidth, and relay status

**See**: [GRASP-02 Proactive Sync](docs/explanation/grasp-02-proactive-sync.md),
[GRASP-03 Proactive Sync Plus](docs/explanation/grasp-03-proactive-sync-plus.md),
and [Purgatory Git Data Sync](docs/explanation/grasp-02-proactive-sync-purgatory-git-data.md)

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

### GRASP-08 (Private Service) — opt-in

- ✅ Requires NIP-42 authentication before a WebSocket session can read or publish events
- ✅ Requires repository-scoped NIP-98 credentials for Git Smart HTTP requests
- ✅ Uses a service-wide member set combining configured npubs with eligible accepted-relay owners
- ✅ Preserves GRASP-01 maintainer authorization for repository writes
- ✅ Supports authenticated private-to-private event and git-data sync while public instances avoid private peers
- ✅ Keeps NIP-11, the root NIP-05 identity, the landing page, and the service icon public for discovery

**Disabled by default** — enable with `NGIT_PRIVATE_MODE=true` and configure at
least one `NGIT_PRIVATE_MEMBERS` entry. Private mode cannot be combined with
GRASP-06 because the contributor endpoint is intentionally unauthenticated.

**See**: [GRASP-08 Private Service Authentication](docs/explanation/grasp-08-private-service.md)

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

**Relay Sync Protection (GRASP-02 & GRASP-03):**
- **Exponential backoff** - Failed connections: 5s → 10s → 20s → ... → 1 hour max
- **Naughty list** - Suppress relays with infrastructure issues until expiry (12h default)
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

## Monitoring & Observability

ngit-grasp exposes comprehensive Prometheus metrics at `/metrics` for:

**Git Operations:**

- Clone/fetch/push rates and bandwidth
- Authorization results (accepted/rejected)
- Top N repositories by bandwidth

**Nostr Events:**

- WebSocket connections (active, unique IPs, flagged abusers)
- Events received, stored, rejected by kind
- Purgatory status (events waiting for git data)

**Sync Health (GRASP-02 & GRASP-03):**

- Per-relay connection status and health states
- Event sync rates and bandwidth
- Git data fetch attempts and success rates
- Domain throttling metrics
- Fixed-cardinality Sync+ author, mailbox, cursor, and worker state

**Configuration Options:**

| Option                     | CLI Flag                                      | Environment Variable                             | Default |
| -------------------------- | --------------------------------------------- | ------------------------------------------------ | ------- |
| Metrics enabled            | `--metrics-enabled`                           | `NGIT_METRICS_ENABLED`                           | `true`  |
| Connection abuse threshold | `--metrics-connection-per-ip-abuse-threshold` | `NGIT_METRICS_CONNECTION_PER_IP_ABUSE_THRESHOLD` | `10`    |
| Top N repos                | `--metrics-top-n-repos`                       | `NGIT_METRICS_TOP_N_REPOS`                       | `10`    |

**Privacy:** IP addresses are never exposed in metrics - only aggregate counts.

See [Monitoring Overview](docs/explanation/monitoring.md) and [Prometheus Setup Guide](docs/how-to/prometheus-setup.md) for deployment.

## Roadmap

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

## Technology Stack

- **Rust**: Core language
- **actix-web**: HTTP server framework
- **git-http-backend**: Git protocol handling but vendored and customised for authorisation logic
- **nostr-relay-builder**: Nostr relay infrastructure from rust-nostr
- **nostr-sdk**: Nostr event handling and validation
- **tokio**: Async runtime

## Quick Start

For production, start with the [deployment chooser](docs/how-to/deploy.md).
The repository ships Docker and Compose configurations, a NixOS module, a
hardened systemd unit, and templates for selected managed hosts. All supported
paths preserve the same
[deployment contract](docs/reference/deployment-contract.md).

The shortest fresh-VPS path uses Docker Compose and Caddy:

```bash
cp deploy.env.example .env
# Set NGIT_DOMAIN in .env and point DNS at this server.
export NGIT_IMAGE="ncontainer.io/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp:latest"
docker compose -f compose.yaml -f compose.caddy.yaml pull ngit-grasp
docker compose -f compose.yaml -f compose.caddy.yaml up --no-build -d
scripts/verify-deployment.sh https://ngit.example.com
```

Pin an explicit release version instead of `latest` for reproducible
production deployments. The Docker guide also covers source builds.

For development from source:

```bash
# install ngit
curl -Ls https://ngit.dev/install.sh | bash

# Clone the repository
git clone nostr://danconwaydev.com/ngit-grasp
cd ngit-grasp

# Build (using Nix for reproducible environment)
nix develop -c cargo build --release

# Configure
cp .env.example .env
# Edit .env with your settings
# Required: NGIT_DOMAIN=your-domain.com
# Optional: NGIT_BASE_PATH=/grasp  # Share a domain at wss://your-domain.com/grasp
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
- Prometheus metrics exposed at `<base-path>/metrics`

**Don't have Nix?** Use the container path above or see the
[Getting Started Tutorial](docs/tutorials/getting-started.md) for development
alternatives.

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

# Run with CLI flags and let ngit-grasp create .relay-owner.nsec
ngit-grasp --domain relay.example.com --bind-address 0.0.0.0:7334

# Supply an existing owner key through the environment
NGIT_RELAY_OWNER_NSEC=nsec1... ngit-grasp --domain relay.example.com
```

The relay-owner nsec is deliberately not accepted as a command-line argument,
because process arguments are visible through tools such as `ps` and
`/proc/<pid>/cmdline`. NixOS deployments should use `relayOwnerNsecFile`, which
passes the key through a protected systemd credential.

### Configuration Options

#### Core Settings

| Option              | CLI Flag                 | Environment Variable        | Default                                      |
| ------------------- | ------------------------ | --------------------------- | -------------------------------------------- |
| Domain              | `--domain`               | `NGIT_DOMAIN`               | (required)                                   |
| Base path           | `--base-path`            | `NGIT_BASE_PATH`            | `/`                                          |
| Relay owner nsec    | —                        | `NGIT_RELAY_OWNER_NSEC`     | systemd credential, then `.relay-owner.nsec` |
| Relay name          | `--relay-name`           | `NGIT_RELAY_NAME`           | `${domain} grasp relay`                      |
| Relay description   | `--relay-description`    | `NGIT_RELAY_DESCRIPTION`    | `Git Nostr Relay - a grasp implementation`   |
| Git data path       | `--git-data-path`        | `NGIT_GIT_DATA_PATH`        | `./data/git` (temp dir for memory backend)   |
| Relay data path     | `--relay-data-path`      | `NGIT_RELAY_DATA_PATH`      | `./data/relay` (temp dir for memory backend) |
| Bind address        | `--bind-address`         | `NGIT_BIND_ADDRESS`         | `127.0.0.1:7334` (NGIT on phone keypad)      |
| Trusted proxy CIDRs | `--trusted-proxy-cidrs`  | `NGIT_TRUSTED_PROXY_CIDRS`  | (empty; forwarded headers ignored)           |
| Database backend    | `--database-backend`     | `NGIT_DATABASE_BACKEND`     | `lmdb`                                       |

#### GRASP-02 & GRASP-03 Sync Settings

| Option                     | CLI Flag                                | Environment Variable                       | Default               |
| -------------------------- | --------------------------------------- | ------------------------------------------ | --------------------- |
| Bootstrap relay            | `--sync-bootstrap-relay-url`            | `NGIT_SYNC_BOOTSTRAP_RELAY_URL`            | (optional)            |
| Sync+ mailbox discovery    | `--sync-plus-enabled`                   | `NGIT_SYNC_PLUS_ENABLED`                   | `true`                |
| User-index relays          | `--user-index-relays`                   | `NGIT_USER_INDEX_RELAYS`                   | 3 public indexes      |
| Sync+ fallback relays      | `--sync-plus-fallback-relays`           | `NGIT_SYNC_PLUS_FALLBACK_RELAYS`           | 4 public relays       |
| Recursive descendant limit | `--sync-recursive-descendant-limit`     | `NGIT_SYNC_RECURSIVE_DESCENDANT_LIMIT`     | `500`                 |
| Allow non-global targets   | `--sync-allow-non-global-targets`       | `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS`       | `false`               |
| Base backoff               | `--sync-base-backoff-secs`              | `NGIT_SYNC_BASE_BACKOFF_SECS`              | `5` seconds           |
| Max backoff                | `--sync-max-backoff-secs`               | `NGIT_SYNC_MAX_BACKOFF_SECS`               | `3600` (1 hour)       |
| Disconnect check interval  | `--sync-disconnect-check-interval-secs` | `NGIT_SYNC_DISCONNECT_CHECK_INTERVAL_SECS` | `60` seconds          |
| Disable negentropy         | `--sync-disable-negentropy`             | `NGIT_SYNC_DISABLE_NEGENTROPY`             | `false`               |

**GRASP-02/03 Sync Notes:**

- **Sync+**: Enabled by default. It discovers eligible authors' accepted NIP-65 relay lists and adds bounded mailbox coverage on top of GRASP-02. Disable it to retain ordinary proactive sync without advertising GRASP-03.
- **User-index relays**: Default to `wss://purplepag.es`, `wss://index.hzrd149.com`, and `wss://indexer.coracle.social` for relay-owner identity publication and eligible-author NIP-65 discovery.
- **Fallback relays**: Default to `wss://relay.ditto.pub`, `wss://relay.damus.io`, `wss://nos.lol`, and `wss://relay.primal.net` when a successful user-index lookup finds no accepted NIP-65 list.
- **Recursive descendant limit**: Bounds the query frontier below each event that directly tags a repository root; direct root-tagging events do not consume the allowance.
- **Outbound target safety**: Event-provided relay and clone targets must be globally reachable by default. Only enable non-global targets for tests or closed development networks.
- **Bootstrap relay**: Optional starting point for relay discovery. The system automatically discovers additional relays from repository announcements; a missing URL scheme defaults to `wss://`.
- **Backoff settings**: Control exponential reconnection backoff (`base * 2^(failures-1)`, capped at max).
- **Negentropy**: Can be disabled to exercise the REQ+EOSE fallback path.

#### GRASP-08 Private Service Settings

| Option                | CLI Flag                 | Environment Variable        | Default                        |
| --------------------- | ------------------------ | --------------------------- | ------------------------------ |
| Private mode          | `--private-mode`         | `NGIT_PRIVATE_MODE`         | `false`                        |
| Permanent members     | `--private-members`      | `NGIT_PRIVATE_MEMBERS`      | (required in private mode)     |
| Canonical Git origin  | `--private-public-origin` | `NGIT_PRIVATE_PUBLIC_ORIGIN` | inferred from `NGIT_DOMAIN`    |

Private mode is a service-wide read boundary: every WebSocket session uses
NIP-42 and every Git Smart HTTP request uses the GRASP-08 repository-scoped
NIP-98 profile. Membership grants read access, while GRASP-01 still determines
who may push. See the
[configuration reference](docs/reference/configuration.md#grasp-08-private-service)
for deployment constraints and reverse-proxy guidance.

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

### Database Backends

- `lmdb`: LMDB backend (default, persistent, general purpose)
- `memory`: In-memory database (fastest, no persistence - uses temp directories)

> **Note:** When using the `memory` backend, git data are automatically stored in temporary directories for ephemeral testing.

### Example: Production Deployment

```bash
# Using environment variables (for containers and other non-systemd deployments)
export NGIT_DOMAIN=gitnostr.com
export NGIT_RELAY_OWNER_NSEC=nsec1...  # Or let it auto-generate from .relay-owner.nsec
export NGIT_BIND_ADDRESS=0.0.0.0:7334
export NGIT_DATABASE_BACKEND=lmdb

# When a private backend is reached only through a reverse proxy:
# export NGIT_BIND_ADDRESS=127.0.0.1:7334
# export NGIT_TRUSTED_PROXY_CIDRS=127.0.0.1/32

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
│   ├── sync/                # GRASP-02/03 proactive sync and mailbox discovery
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
│   │   ├── nip05.rs         # NIP-05 root identity document
│   │   └── nip11.rs         # NIP-11 relay info document
│   └── metrics/
│       ├── mod.rs           # Prometheus metrics (Git, Nostr, Sync)
│       ├── bandwidth.rs     # Bandwidth tracking
│       └── connection.rs    # Connection tracking
├── docs/                    # Documentation (Diátaxis framework)
│   ├── explanation/         # Architecture, decisions, and GRASP deep-dives
│   ├── how-to/              # Deployment, configuration guides
│   ├── tutorials/           # Getting started, first steps
│   └── reference/           # API docs, test strategy
├── tests/                   # Integration tests (NIP-01, NIP-34, purgatory)
├── grasp-audit/             # Compliance audit crate (workspace member)
└── README.md
```

## Contributing

Contributions welcome! Please:

1. Read [the architecture overview](docs/explanation/architecture.md)
2. Open an issue to discuss major changes
3. Follow Rust conventions and run `cargo fmt` + `cargo clippy`
4. Add tests for new functionality

## License

MIT License - see [LICENSE](LICENSE) for details

## Sister Projects

- [ngit](https://ngit.dev) - CLI and Git remote helper for collaborating on repositories over Nostr
- [ngit-ci](https://gitworkshop.dev/danconwaydev.com/ngit-ci) - Self-hosted CI that watches Nostr Git repositories and publishes signed results

## Related Specifications

- [GRASP Protocol](https://gitworkshop.dev/danconwaydev.com/grasp) - Protocol specification
- [NIP-34](https://nips.nostr.com/34) - Git Stuff (Nostr protocol)

## Acknowledgments

- [rust-nostr](https://github.com/rust-nostr/nostr) team for excellent Nostr libraries
- Git community for the Smart HTTP protocol
