# Peer-controlled state ownership

This document records the memory-lifecycle audit prompted by the 2026-08-09
`auth-required` incident. It covers state whose cardinality or lifetime can be
influenced by an inbound client, an outbound relay, or an advertised Git
source. Ordinary growth of admitted events and repositories is intentionally
out of scope: that is retained application data, not transient peer state.

The classifications used below are:

- **Static**: a local constant, configured ceiling, or semaphore bounds the
  number of entries.
- **Time**: every entry has an expiry or a finite retry budget.
- **External**: entries are deduplicated against admitted repository/event
  state and therefore cannot outgrow that retained state.
- **Session**: entries are bounded by a connection ledger and cleared when the
  connection generation ends.

No transient peer-controlled collection is intentionally unbounded. An
external bound is acceptable only where admission policy already owns the
larger retained set; it is not an excuse to copy arbitrary wire input.

## Inventory

| State | Producer and cleanup owner | Bound and terminal behaviour | Observation |
|---|---|---|---|
| Inbound WebSocket connections | rust-nostr accepts sockets; disconnect owns cleanup | External to the process by the configured/OS connection ceiling. Per-IP accounting uses only a trusted proxy chain. Repeated disconnect is idempotent. | `ngit_connections_active`, unique-IP and abuser gauges |
| Inbound subscriptions | rust-nostr REQ/CLOSE handling | Static per connection: configured subscription count, cumulative subscription-state bytes, request/filter sizes, and event rate. Disconnect clears the connection registry. | NIP-11 limits, connection logs |
| Git HTTP request/response streams | HTTP handlers and child-process pumps | Static queues of `STREAM_CHANNEL_DEPTH = 8`; body and WebSocket message limits bound buffered input. Receiver loss terminates pumps. | request status and process-resource metrics |
| Per-relay EVENT data lane | `RelayConnection::run_event_loop`; processor task owns drain | Static 1,000 entries per connected relay. Disconnect drops the receiver. Delayed or missing terminals cannot enlarge it. | pipeline queue-depth/delay log |
| EOSE/CLOSED actor lanes | per-relay event processors; sync actor owns drain | Static 1,000 entries globally per lane. Repeated terminals backpressure the data lane; permit release is independently handled by the terminal-control listener. | retained-state and delayed-EOSE logs |
| Transient and live subscription permits | subscription ledger; EOSE/CLOSED/CLOSE/disconnect own release | Session bound by NIP-11 `max_subscriptions` or the fallback budget. The watchdog sends CLOSE before releasing a missing-terminal slot. Repeated terminals are idempotent. | subscription-ledger and watchdog logs |
| Authentication retry markers | first `auth-required` CLOSED; second refusal/disconnect owns cleanup | Session bound: an ID is admitted only while it owns a live or transient ledger permit. Forged and stale peer IDs are ignored. | `ngit_sync_retained_state_current{class="auth_retries"}` |
| Connection attempts/workers/results | one token per canonical derived relay; actor owns result | External queue: at most one queued/running task per relay in admitted coverage. Static execution: eight semaphore holders and an eight-entry result channel. Stale/reordered results cannot consume a newer token. | connection-attempt counters and `queued_connection_attempts` gauge |
| Self-subscriber actions and disconnect notices | subscriber/connection tasks; actor owns drain | Static 100-entry channels. Producers await capacity; duplicate dirty-relay actions are re-derived from indexes. | actor and connection logs |
| Pending sync batches, pagination, and requested/received IDs | historic/negentropy admission; terminal handler owns completion | Session/external: open subscriptions require ledger permits; pagination state is nested in a pending batch. EOSE/CLOSED, watchdog CLOSE, disconnect, or daily reset removes it. | retained pending-batch/subscription gauges |
| Missing-event recovery | incomplete negentropy hydration; recovery task owns progress/expiry | Time and static per attempt: 300 IDs per pass, 16 source batches retained, 12 zero-progress attempts. Duplicate IDs merge. | recovery outcome logs |
| Rejected-event hot/cold indexes | write policy; invalidation and cleanup tasks | Time: full events expire after two minutes and metadata after seven days; duplicate IDs replace/merge. Startup restores remaining lifetime rather than resetting it. | hot/cold current and expiry metrics |
| Purgatory event maps and sync queue | write policy; promotion/cleanup owns removal | Time/external: entries are keyed by admitted event/repository identity, normally expire at 30 minutes, and soft-expired announcements at 24 hours. Queue entries deduplicate by identifier and disappear on completion or event expiry. | purgatory counts, queue and Git-process metrics |
| Per-domain Git throttle queues | incomplete purgatory fetch; throttle manager owns drain | External: one entry per purgatory identifier/domain, merged on repeat. Completion, URL exhaustion, or purgatory expiry removes useful work. Request history is time-windowed. | domain/fetch logs and Git-process metrics |
| Dependency retry attempts and temporary relays | rejected/purgatory dependency discovery; maintenance owns expiry | Time/external: event IDs are pruned against current purgatory input; temporary relays have explicit deadlines. Repeats overwrite timestamps. | retained dependency gauges |
| NIP-65 discovery and mailbox probes | accepted root and descendant authors; ordinary root-inbox coverage plus discovery/probe scheduler own completion | External/session work: root-author read inboxes remain ordinary derived sync targets, while participant maps derive from accepted root threads. Identity discovery is globally single-flight. Mailbox history has at most one ordinary `fetch_events` worker per accepted relay and 32 process-wide; each page consumes that relay's pacing and ledger capacity and has a 30-second timeout. New relay workers are admitted one per maintenance pass, then each successful worker drains its own filter cursor until the cycle completes. Exclusive connections retire when idle. Numeric filter cursors and due times are in memory and bounded by desired mailbox relays. | discovery/probe logs and relay gauges |
| Deferred consolidation | capacity refusal; final batch/reset/disconnect owns removal | External and deduplicated by relay. Final batch completion processes the set directly; no self-addressed notification queue remains. | retained deferred-consolidation gauge |
| Descendant rotations and auxiliary live coverage | accepted root coverage; EOSE/CLOSED/disconnect/daily reset own transition | Session/external: one state object per derived relay and at most one rotating request in flight per relay. Coverage IDs consume ledger slots. | retained rotation gauge and terminal logs |
| Health and naughty-list entries | connection failures; health checker owns recovery/expiry | External/time: one entry per canonical target, ordinary failures back off, persistent entries expire after 12 hours. Metrics expose only three fixed categories. | health gauges and aggregate naughty metrics |
| Outbound connection and desired-coverage indexes | admitted announcements/root events; disconnect/removal owns session state | External: canonical relay URLs and desired items derive from admitted or purgatory data. Reconnect replaces session-only state rather than duplicating it. | tracked/connected relay gauges |
| Spawned tasks | listeners, bounded workers, timers, and Git subprocesses | Static concurrency or one task per owned connection/request. Shutdown receivers terminate service tasks; subprocess watchdogs and receiver loss terminate request tasks. No task is spawned merely to retain an item that failed a full queue. | process task/resource metrics and lifecycle logs |

## Invariants for future changes

1. Wire-provided identifiers may index state only after they resolve to an
   application-owned connection, subscription permit, admitted event, or
   purgatory entry.
2. Backpressure must bound retained memory, not merely concurrent execution.
   A semaphore in front of an unbounded waiting queue is not a memory bound.
3. Terminal handling is idempotent. Missing terminals require a finite
   close-before-release path; repeated or reordered terminals must not create
   replacement state.
4. Reconnect resets every session-class collection. A previous generation may
   never release, retire, or restore a current generation's subscription.
5. Prometheus labels use fixed vocabularies for peer failures and retained
   state. Peer URLs, event IDs, subscription IDs, and error text do not create
   new diagnostic series unless their cardinality is already explicitly
   bounded and retired.

The aggregate `ngit_sync_retained_state_current` gauge is the first alerting
surface for unexpected transient growth. Process RSS and cgroup pressure remain
the final defence: a flat work-concurrency graph with a rising retained-state
class indicates a lifecycle bug rather than legitimate throughput.
