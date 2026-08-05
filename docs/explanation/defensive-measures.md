# Defensive Measures & Rate Limiting

This document describes the defensive measures implemented in ngit-grasp to protect against abuse, spam, and denial-of-service attacks.

**Note:** A point-in-time analysis of defensive measures in other Nostr relays (strfry, nostr-rs-relay, khatru) was conducted to inform these design decisions. The analysis examined connection limits, rate limiting approaches, and per-IP enforcement strategies across the ecosystem.

## Overview

ngit-grasp employs multiple layers of defense:

1. **Connection & Subscription Limits** - Per-connection limits on subscriptions and event publishing
2. **Content Filtering** - Blacklist/whitelist system for repositories and event authors
3. **Event Validation** - Strict GRASP-01 protocol validation
4. **Relay Health Management** - Intelligent handling of problematic remote relays

## What's Implemented

### Per-Connection Rate Limits

**Source:** Built-in to rust-nostr relay-builder

- **Subscription limit:** Max 500 concurrent subscriptions per connection
- **Event publishing limit:** Max 60 events per minute per connection
- **Subscription ID length:** Max 250 characters
- **Filter limit:** Max 500 results per query (default)

These limits prevent individual connections from overwhelming the relay.

### Per-IP Connection Monitoring

**Source:** Custom ngit-grasp implementation  
**Location:** `src/metrics/connection.rs`

- **Status:** Monitoring only (does NOT enforce limits)
- Tracks connections per IP address internally
- Flags IPs exceeding threshold (default: 10 connections)
- **Privacy:** IP addresses never exposed in Prometheus metrics, only aggregate counts
- Logs warnings when threshold exceeded

**Note on enforcement:** Per-IP connection limits are not built into rust-nostr relay-builder (tracks per WebSocket connection, not per IP). If abuse is detected via metrics, enforcement should be implemented as a PR to rust-nostr/relay-builder to benefit the entire Nostr ecosystem, rather than custom code in ngit-grasp.

### Content Filtering (Blacklists/Whitelists)

**Source:** Custom ngit-grasp implementation  
**Location:** `src/config.rs`, `src/nostr/builder.rs`

**Event Blacklist:**
- Block ALL events from specific authors (npubs)
- Takes precedence over all other validation
- Events never reach storage or purgatory

**Repository Blacklist:**
- Block specific repositories, developers, or identifiers
- Takes precedence over whitelists
- Three formats: `npub`, `npub/identifier`, `identifier`

**Repository Whitelist:**
- Curate which repositories are accepted (GRASP-01 mode)
- Only accept announcements that both list your service AND match whitelist
- Same three formats as blacklist

**Archive Whitelist (GRASP-05):**
- Mirror specific repositories even if they don't list your service
- Same three formats as blacklist
- Default: read-only mode when enabled

**Privacy:** Blacklists not advertised in NIP-11 metadata.

### Event Validation Plugin System

**Source:** Built-in to rust-nostr relay-builder  
**Implementation:** Custom GRASP-01 validation in `src/nostr/builder.rs`

- **WritePolicy trait:** Controls which events are accepted
- **QueryPolicy trait:** Controls which queries are allowed (not currently used)
- Access to client IP address for future per-IP rate limiting
- Modular sub-policies for different event types (announcements, state events, PRs)

### Relay Health Management (GRASP-02 Sync)

**Source:** Custom ngit-grasp implementation  
**Location:** `src/sync/health.rs`

**Exponential Backoff:**
- Failed connections trigger increasing delays: 5s → 10s → 20s → ... → 1 hour max
- Prevents hammering dead or slow relays

**Naughty List:**
- Tracks relays with persistent infrastructure issues (DNS, TLS, protocol errors)
- Separate from normal connection failures
- 12-hour expiration (configurable)
- Reduces retry frequency for broken relays

**Rate Limit Detection:**
- Detects when remote relay rate limits us
- Automatic 65-second cooldown
- Prevents hammering relays that tell us to slow down

**Domain Throttling (Git Data Fetching):**
- Max 5 concurrent requests per domain
- Max 30 requests per minute per domain
- Respectful rate limiting when fetching missing git data

### Outbound Target Policy (SSRF Protection)

**Source:** Custom ngit-grasp implementation  
**Location:** `src/outbound.rs`

Repository announcements, state events, and PR events are untrusted input,
but their `relays` and `clone` tags direct proactive sync's outbound
WebSocket connections and purgatory git fetches. Production logs showed
event-directed sync dialling `ws://localhost:3334`, `ws://127.0.0.1:7334`,
and `ws://100.125.184.46:7334` (CGNAT); a crafted event could use this to
probe or attack the relay host's local network.

One fail-closed policy is applied immediately before every event-directed
outbound sink:

- **Relay connections** (`RelayConnection::connect`): re-checked before every
  dial, including reconnects, plus a registration-time gate so forbidden
  targets never enter the reconnect lifecycle.
- **Git fetches** (`RealSyncContext::fetch_oids`): checked immediately before
  spawning the pass's git subprocesses (`git ls-remote` and `git fetch`),
  with the vetted DNS answers pinned onto each of them.

The policy enforces:

- **Scheme allowlist per sink** - `ws`/`wss` for relays, `http`/`https` for
  git; no `file:`, `ssh:`, `git:`, or other protocol escapes.
- **No credentials** in URLs.
- **No local hostnames** - `localhost`, single-label names, and IANA
  special-use suffixes (`.local`, `.internal`, `.home.arpa`, `.onion`,
  `.test`, `.invalid`, `.localdomain`).
- **Globally reachable addresses only** - loopback, private (RFC 1918),
  CGNAT (RFC 6598), link-local, unspecified, multicast, broadcast,
  documentation, benchmarking, reserved, and unique-local ranges are all
  rejected, for IP literals and for every DNS answer (resolution failure
  fails closed).
- **Exact service matching** - GRASP-01 admission (`lists_service`) and the
  don't-fetch-from-ourselves filter compare parsed host and port, so
  `gitnostr.com.attacker.example` or `https://evil.example/gitnostr.com/`
  cannot satisfy a check for `gitnostr.com`.

The **operator-configured bootstrap relay** (`NGIT_SYNC_BOOTSTRAP_RELAY_URL`)
is trusted and exempt, so a local bootstrap relay keeps working. Trust is
carried by the source of the URL, never by URL comparison: an event-provided
URL that merely resembles the bootstrap relay is still rejected.

Git subprocesses are additionally confined so an authorized URL cannot escape
the decision: `GIT_ALLOW_PROTOCOL=http:https`, `http.followRedirects=false`,
proxies disabled (config and environment), `credential.helper=` cleared, and
the vetted DNS answers pinned via `http.curloptResolve`.

**Known limitation (DNS rebinding, relay connections only):** the vetted DNS
answers cannot be pinned onto nostr-sdk's connector because its connect API
accepts a URL, not a pre-resolved socket address. Relay DNS is therefore
re-validated immediately before every connection attempt but re-resolved by
the SDK during the dial, leaving a narrow time-of-check/time-of-use window.
Closing it needs upstream connector support for pre-resolved addresses
(rust-nostr). Git fetches do not share this window because their DNS answers
are pinned.

The escape hatch `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS=true` disables the
reachability checks (scheme and credential checks remain) for integration
tests and closed development networks. Production relays must leave it unset.

## What's NOT Implemented

### Per-IP Rate Limiting

- **Per-IP connection limits:** Not enforced (only monitored)
- **Per-IP subscription limits:** Not supported
- **Per-IP event publishing limits:** Not supported

**Why:** rust-nostr relay-builder tracks limits per WebSocket connection, not per IP address.

**To implement:** Would require custom middleware/WritePolicy to aggregate across connections from the same IP.

### Query Filtering

**Status:** QueryPolicy trait available but not currently used.

**Potential uses:** Rate limit queries per IP, block expensive queries, restrict access to certain event kinds.

## Future Enhancements

### Per-IP Rate Limiting

Per-IP connection and event rate limiting were considered but deferred until abuse is detected in production. The current protections (per-connection limits, total connection limit, content filtering) are sufficient for the git relay use case.

**Decision rationale:** The primary DoS vector is connection exhaustion, which is addressed by the total connection limit (`NGIT_MAX_CONNECTIONS`). Per-IP enforcement would require custom middleware in rust-nostr relay-builder (which currently tracks limits per WebSocket connection, not per IP). If abuse is detected via the per-IP monitoring metrics, enforcement should be implemented as a PR to rust-nostr/relay-builder to benefit the entire Nostr ecosystem.

**Related:** Git endpoint throttling (issue ff38) is a separate concern with different requirements.

## Summary Table

| Feature | Status | Enforced? | Configurable? |
|---------|--------|-----------|---------------|
| **Per-Connection Limits** |
| Max subscriptions (500) | ✅ Active | Yes | No (relay-builder default) |
| Event rate limit (60/min) | ✅ Active | Yes | No (relay-builder default) |
| **Total Connection Limit** |
| Max connections (500) | ✅ Active | Yes | Yes (`NGIT_MAX_CONNECTIONS`) |
| **Per-IP Monitoring** |
| Connection tracking | ✅ Active | No (monitor only) | Threshold only |
| **Content Filtering** |
| Event blacklist | ✅ Active | Yes | Yes |
| Repository blacklist | ✅ Active | Yes | Yes |
| Repository whitelist | ✅ Active | Yes (if set) | Yes |
| Archive whitelist | ✅ Active | Yes (if set) | Yes |
| **Event Validation** |
| GRASP-01 validation | ✅ Active | Yes | Via WritePolicy |
| **Relay Sync Protection** |
| Exponential backoff | ✅ Active | Yes | Yes |
| Naughty list | ✅ Active | Yes | Yes (12h default) |
| Rate limit detection | ✅ Active | Yes | Automatic |
| Domain throttling | ✅ Active | Yes | Hardcoded (5/30) |
| Outbound target policy (SSRF) | ✅ Active | Yes | Yes (`NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS`) |
| **Not Implemented** |
| Per-IP connection limit | ⚠️ Deferred | No | - |
| Per-IP rate limiting | ⚠️ Deferred | No | - |
| Query filtering | ⚠️ Available | No | Not implemented |

## Related Documentation

- [Configuration Reference](../reference/configuration.md) - All config options for defensive features
- [Monitoring Overview](monitoring.md) - Prometheus metrics for tracking abuse
- [GRASP-05 Archive](grasp-05-archive.md) - Archive whitelist details
- [Architecture](architecture.md) - Overall system design
