# Explanation: Sync Scaling Constraints and Budgets

**Purpose:** Explains the relay-imposed constraints that bound proactive sync,
and justifies how we spend the three budgets they create — filter payload,
subscriptions, and concurrency — as the watched item set grows.
**Audience:** Contributors changing sync filter construction, subscription
management, or negentropy scheduling; operators reasoning about scale limits.

---

## The Problem

Proactive sync ([GRASP-02](grasp-02-proactive-sync.md)) watches a growing set
of items per relay: repository identifiers, repo references, and root event
IDs. Every item must appear in filters twice — once in live subscriptions and
once in historic sync (negentropy or REQ+EOSE). As the watched set grows, sync
pressure on each relay grows along three axes:

1. **Filter payload** — how many items fit in one filter / one message.
2. **Subscription count** — how many concurrent subscriptions we hold.
3. **Request concurrency** — how many sync operations run at once.

These axes are not independent: relays bound them with shared, mostly
undiscoverable limits. This document records the limits we verified, the
budget model derived from them, and the levers we use — in order — to scale.

Production motivation (2026-08-04, gitnostr.com): the bootstrap relay received
146 filters in one startup action (869 repos + 3632 root events, chunked at
100 items). Historic sync opened one negentropy round per filter with no
bound, drawing 34 "too many concurrent NEG requests" rejections from nos.lol
and 61 per-filter timeouts in two minutes.

---

## Constraint Inventory

Verified 2026-08-04 against implementation sources and live NIP-11 documents.
Re-verify before relying on exact numbers; defaults change.

### strfry (most common large public relay implementation)

| Limit | Default | Source |
| --- | --- | --- |
| Tag values per filter (count) | none — byte-capped | `src/filters.h:41` |
| Tag value bytes per filter set | 65535 | `src/filters.h:41` |
| Tag fields per filter | 3 (`maxTagsPerFilter`) | `golpe.yaml` |
| Filters per REQ | 200 (`maxReqFilterSize`); 3 if optional `filterValidation` enabled | `golpe.yaml` |
| Subscriptions per connection | 200 (`maxSubsPerConnection`) | `golpe.yaml` |
| Concurrent negentropy | **shares `maxSubsPerConnection`** — no separate knob | `src/apps/relay/RelayNegentropy.cpp` |
| WebSocket message size | 131072 (`maxWebsocketPayloadSize`) | `golpe.yaml` |

The key strfry finding: **negentropy views and ordinary subscriptions draw
from the same per-connection budget.** "ERROR: too many concurrent NEG
requests" is emitted when NEG views exceed `maxSubsPerConnection`.

### Live NIP-11 documents (operators tighten defaults)

| Relay | `max_limit` | `max_subscriptions` | `max_message_length` |
| --- | --- | --- | --- |
| [nos.lol](https://nos.lol/) (strfry 1.1.0) | 500 | **20** | 131072 |
| [relay.primal.net](https://relay.primal.net/) (strfry 1.0.3-1-g60d35a6) | 500 | **20** | 1000000 |
| [nostr.wine](https://nostr.wine/) (operator software 0.3.3) | 1000 | 50 | 524288 |
| [relay.damus.io](https://relay.damus.io/) (strfry 1.1.0-1-g691a533f11eb) | 500 | 200 | 1000000 |
| [relay.ditto.pub](https://relay.ditto.pub/) (Ditto Relay 0.1.0) | 1000 | 20 | 4000000 |
| [relay.nostr.band](https://relay.nostr.band/) | unavailable — HTTPS timed out twice | unavailable | unavailable |

Live documents fetched 2026-08-06 with `Accept: application/nostr+json`.
The five reachable relays advertise their result cap as
`limitation.max_limit`.

### Discoverability gap (NIP-11)

NIP-11 `limitation` has **no field for tag values per filter or filter count
per subscription**. It does define `max_limit` (clamp applied to a
filter's explicit `limit`), and `default_limit` (maximum returned events when
`limit` is omitted — the field pagination actually needs), in addition to
`max_subscriptions` and `max_message_length`, but implementations and
operators advertise these unevenly: `default_limit` in particular is rarely
present (neither nos.lol nor relay.ditto.pub advertises it, checked live
2026-08-06). `max_limit` also cannot express whether the allowance is per
filter or aggregate across a multi-filter REQ. Consequently neither filter
sizing nor the pagination model can be negotiated reliably; both need
conservative defaults, observation, and reactive fallback.

The reactive filter-count fallback is session-local. An explicit
filter-count refusal for a multi-filter REQ geometrically lowers that
connection's grouping ceiling (`10 → 5 → 2 → 1`, or from the actual rejected
group size) and re-derives the rejected historic batch or complete live
coverage without parsing arbitrary response numbers. This matters because
strfry reports the submitted count (`invalid number of filters: 8`), whereas
rust-nostr reports its configured ceiling. The learned ceiling never rises in
the session and resets on reconnect. A one-filter refusal is not recoverable
by regrouping and uses the ordinary long `filter_incompatible` policy pause.
Explicit invalid-filter, oversized-filter-item, and positive-limit-only
refusals use that same policy pause for core coverage, even when the rejected
REQ contains multiple filters. Splitting a group cannot repair an invalid
individual filter. This avoids repeating an unchanged filter after each
short rate-limit cooldown. Refused auxiliary descendant live coverage retains
its existing historical fallback.

### Our own embedded relay (nostr-sdk `LocalRelay`, 0.45.3)

- `max_reqs` = 500, enforced for REQ only (`src/nostr/builder.rs`).
- Negentropy: ngit-grasp configures at most 10 retained sessions and 50,000
  retained items per connection, with a 60,000-byte protocol frame limit.
  Continuations have a separate allowance from query starts. LMDB scans run
  on blocking workers, so a scan does not occupy an async runtime worker.
- 20 filters per REQ by default; no limit on tag values per filter.
- Query result limits (verified against the published `nostr-sdk-0.45.3`
  crate source, `src/local_relay/local/inner.rs`):
  enforced **per filter, not per REQ**. A filter without a `limit` is given
  `default_filter_limit` (500); the effective limit is then clamped to
  `min(limit, max_filter_limit, max_query_results)` (defaults: no
  `max_filter_limit`, `max_query_results` = 500). Each filter is queried
  independently and the merged, deduplicated results are sent **without
  aggregate truncation** — a source comment suggests the merged set is also
  capped, but the implementation does not do this.
- Behaviour change from 0.45.0-alpha.8 and earlier: a filter without an
  explicit `limit` previously returned *every* match; stable 0.45.0 returns
  at most the newest 500 per filter, so large backlogs arrive via
  pagination instead of one unbounded response.

khatru (used by the ngit-relay reference implementation) and nostr-rs-relay
similarly enforce no filter-size limits by default.

### Per-query result limits and the pagination model

NIP-01 defines `limit` per filter, for the initial query only, and lets
relays return fewer events than requested. It neither guarantees that each
filter in a multi-filter REQ receives an independent result allowance nor
forbids an aggregate cap across the whole REQ. Which model a relay
implements is an empirical question, and it decides whether grouped
REQ+EOSE pagination (per-filter `until` cursors inside one grouped
subscription) is safe.

### Audit result: per-filter everywhere; no aggregate caps

Source audit, 2026-08-06, of nine implementations at release tags —
nostr-sdk `LocalRelay` 0.45.0, strfry 1.1.1, nostr-rs-relay 0.10.0,
khatru v0.19.1, relayer v2.2.14, nostream v3.0.0, rnostr v0.4.9,
chorus v2.0.2, haven v1.2.2. The full per-implementation table with
file:line citations is preserved in this file's history (commit
`e889ea5`).

- Every implementation applies result limits **per filter**, and none caps
  the merged results of a multi-filter REQ, so grouped pagination's
  per-filter cursor model is sound. `until` never changes the cap.
- Defaults for a filter sent without `limit`: 500 (nostr-sdk, strfry,
  nostream), 375/250 (haven LMDB/Badger), 300 (rnostr), 1000 or unbounded
  (nostr-rs-relay by backend), unbounded at the framework layer (khatru,
  relayer, chorus — stores decide). "Unbounded" means the semantic query
  limit; timeouts, rate limits, and finite databases still shorten
  responses, as NIP-01 permits.
- strfry and rnostr technically accept arbitrarily low operator caps,
  making any fixed `PAGINATION_THRESHOLD` formally unsafe at that
  configuration boundary, but no live deployment anywhere near the
  threshold was found; live strfry relays advertise `max_limit` 500,
  nostr.wine 1000.
- NIP-11 advertisement of the cap is uneven: strfry, nostream, and rnostr
  publish `max_limit`; nostr-rs-relay, khatru-family, and chorus do not.

#### Implementation limit matrix

These are implementation defaults, not claims about every deployment. `★`
means that implementation emits the value in the corresponding standard
NIP-11 `limitation` field; operators can still override or omit advertised
values. `—` means no native limit was found at that layer, not that a reverse
proxy, host, storage backend, or embedding application cannot impose one.

| Implementation | Results / filter | Filters / subscription | Subscriptions / connection | Connections / IP | Evidence |
| --- | ---: | ---: | ---: | ---: | --- |
| nostr-sdk `LocalRelay` 0.45.0 | 500 | 20 | 500 | — (128 global) | published crate `local_relay/builder.rs:19-29,41-46,338-359` |
| strfry 1.1.1 | 500 ★ | 200 | 200 ★ | — | [`strfry.conf:95-117`](https://github.com/hoytech/strfry/blob/1.1.1/strfry.conf#L95-L117), [`RelayWebsocket.cpp:89-97`](https://github.com/hoytech/strfry/blob/1.1.1/src/apps/relay/RelayWebsocket.cpp#L89-L97) |
| nostr-rs-relay 0.10.0 | SQLite: unbounded; PostgreSQL: 1000 | — | — | — | [`sqlite.rs:1149-1155`](https://github.com/scsibug/nostr-rs-relay/blob/0.10.0/src/repo/sqlite.rs#L1149-L1155), [`postgres.rs:891-900`](https://github.com/scsibug/nostr-rs-relay/blob/0.10.0/src/repo/postgres.rs#L891-L900) |
| khatru v0.19.1 | store-defined | — | — | — | per-filter dispatch in [`handlers.go:289-324`](https://github.com/fiatjaf/khatru/blob/v0.19.1/handlers.go#L289-L324) |
| relayer v2.2.14 | store-defined / framework unbounded | — | — | — | [`handlers.go:182-255`](https://github.com/fiatjaf/relayer/blob/v2.2.14/handlers.go#L182-L255) |
| nostream v3.0.0 | 500 default; requested maximum 5000 ★ | 10 ★ | 10 ★ | — | [`base.ts:87`](https://github.com/Cameri/nostream/blob/v3.0.0/src/constants/base.ts#L87), [`default-settings.yaml:215-222`](https://github.com/Cameri/nostream/blob/v3.0.0/resources/default-settings.yaml#L215-L222), [`root-request-handler.ts:87-104`](https://github.com/Cameri/nostream/blob/v3.0.0/src/handlers/request-handlers/root-request-handler.ts#L87-L104) |
| rnostr v0.4.9 | 300 ★ | 10 ★ | 20 ★ | — | [`setting.rs:123-156,340-352`](https://github.com/rnostr/rnostr/blob/v0.4.9/relay/src/setting.rs#L123-L156) |
| chorus v2.0.2 | unbounded | — | 128 ★ | 5 | [`config.rs:30-47,52-93`](https://github.com/mikedilger/chorus/blob/v2.0.2/src/config.rs#L30-L93), [`nip11.rs:143-153`](https://github.com/mikedilger/chorus/blob/v2.0.2/src/web/nip11.rs#L143-L153) |
| haven v1.2.2 | LMDB: 375; Badger: 250 | — | — | — | backend construction in [`init.go:61-78`](https://github.com/bitvora/haven/blob/v1.2.2/init.go#L61-L78); eventstore v0.17.5 [`lmdb/query.go:26-43`](https://github.com/fiatjaf/eventstore/blob/v0.17.5/lmdb/query.go#L26-L43) |
| Ditto Relay 0.1.0 (`cf34437`, no release tag) | 100 default; requested maximum 1000 ★ | 100 ★ | 20 ★ | — | [`relay.ts:188-206,1256-1307`](https://gitlab.com/soapbox-pub/ditto-relay/-/blob/cf3443718cb251801dd1842de1a847af50b155ad/src/relay.ts#L188-206), live [relay.ditto.pub](https://relay.ditto.pub/) NIP-11 |

The result column distinguishes a filter's implicit default from the largest
explicit request where they differ. This matters for pagination: nostream and
Ditto normally return 500 and 100 respectively when `limit` is omitted even
though they advertise the larger accepted `max_limit`.

#### Admission and rate limits (condensed)

Native rate limiting varies wildly and is invisible to clients. Our own
embedded relay enforces per-connection per-minute quotas (1,200 queries, 6,000
WebSocket messages, 60 event writes); nostream ships per-IP connection-attempt
and kind-specific event quotas with EWMA decay; khatru and haven offer
discrete leaky counters that drain over minutes; nostr-rs-relay, relayer,
and rnostr have token-bucket limiters that are disabled by default; chorus
budgets raw bytes per connection (16 MiB burst, 1 MiB/s refill), caps
five simultaneous connections per IP, and bans immediate reconnects;
strfry and Ditto have no native limiter at all, deferring to deployment
infrastructure. The full survey with citations is preserved in this
file's history (commit `9723ff4`).

rust-nostr 0.45.3 supplies the 1,200-query-start allowance that ngit-grasp
previously selected with a compatibility override. NIP-77 continuations use
an independent 1,200/minute allowance, while all frames still share the
6,000/minute message cap. A finite per-connection limit remains one DoS layer;
per-IP admission and global resource bounds address clients multiplying
connections. Outbound pacing remains necessary for peers with older SDKs or
stricter operator-selected limits.

NIP-11 describes hard relay limitations, not rate-limit algorithms. The
standard fields relevant here are `max_limit` and
`max_subscriptions`; it has no standard fields for simultaneous connections
per IP, connection-attempt rate, message/event/query rate, burst size, window,
decay model, or retry-after time. Even an advertised `max_limit` does not say
whether it applies independently to each filter or to the merged REQ, which is
why the source audit above remains necessary. Relay-specific extensions can
add fields, but clients cannot assume common names or semantics.

Two gates cover the distinct concerns. A proactive background gate spaces
historic, dependency, pagination, hydration, retry, and NIP-77 round starts at
one per second from session startup; persistent live subscriptions bypass it.
A reactive compatibility gate remains inactive until an explicit
`too many queries` response, then spaces every application-visible start and
selects REQ fallback because the application cannot pace individual
`NEG-MSG` frames.

The client encodes this model in per-connection `RelayPaginationSession`
state (`src/sync/mod.rs`). After EOSE it learns the largest raw page seen
from that relay and computes `max(90, floor(0.9 × estimated_cap))`, where
`estimated_cap` also includes an advertised NIP-11 `default_limit` while
that hint remains trusted. A filter meeting the adaptive threshold is
fetched again with `until` set to its oldest raw `created_at`.
Consequences:

- Every raw delivery matching a tracked filter counts before deduplication
  or write-policy processing. Purgatory-routed, rejected, and repeated
  events therefore consume both the relay's allowance and our page count,
  and the `until` cursor is derived from that same raw stream.
- Ditto's 100-event omitted-limit default is now above the adaptive floor
  and is learned from its first page even though it advertises only
  `max_limit: 1000`. `max_limit` never raises the threshold because it
  describes explicit limits, not the omitted-limit filters sent here.
- A relay capping a filter below 90 can still silently truncate history.
  No such deployment was found in the audit. No audited implementation
  enforces an aggregate cap across filters in one REQ.
- Larger learned pages raise the threshold and avoid redundant requests.
  The 0.9 slack can still produce one final verification-shaped page when
  a result count falls near the learned cap; this is the deliberate cost
  of tolerating relay-side page shrinkage.
- Implemented design (accepted 2026-08-06): keep omitting
  `limit` — an explicit limit would cap the relays that serve unbounded
  pages — count raw deliveries, and adapt the threshold per relay:
  1. **Count raw delivered events (implemented).** Every delivered event
     that matches a tracked filter is counted before deduplication and write
     policy, and the cursor uses the same stream. Purgatory-routed, rejected,
     and repeated events can no longer consume relay allowance invisibly.
  2. **Adaptive per-relay threshold (implemented):**
     `estimated_cap = max(largest observed page, advertised
     default_limit if present)`;
     `threshold = max(90, floor(0.9 × estimated_cap))`. Observed pages
     are ground truth (always ≤ the true cap, so never unsafe, and
     converging upward to eliminate redundant pages); the 0.9 slack
     absorbs relay-side shrinkage such as expired-event skipping; the
     floor of 90 stays below Ditto's 100, the smallest default found.
     Learned state is per connection session and NIP-11 is refetched on
     reconnect, so an operator lowering their cap cannot strand a stale
     threshold.
  3. **NIP-11 fields (implemented):** `default_limit` ("maximum returned events if
     you send a filter without a limit") is the standard field for
     exactly this and is used as a hint when advertised — though
     rarely: neither nos.lol nor relay.ditto.pub advertises it (checked
     live 2026-08-06). Being self-reported, a wrong-high value is
     unsafe, so the first page that the hint would declare exhausted
     triggers one verification page; if it yields new events the hint
     is discarded in favour of learned-only. `max_limit` must never
     raise the threshold while requests omit `limit`: it bounds
     accepted explicit requests, not the omitted-limit page size
     (Ditto: 1000 advertised vs 100 served; nostream: 5000 vs 500).

### Working floors

Derived from the tightest commonly observed values; all sizing below assumes:

- **Subscription budget B = 20** per connection (nos.lol, relay.primal.net,
  Ditto Relay default), shared between live REQs, NEG rounds, and fallback
  REQs. Caveat found by the 2026-08-06 limit matrix: nostream defaults to
  **10** subscriptions per connection and 10 filters per REQ (the former is
  standard NIP-11; nostream emits the latter as a relay-specific field), below
  this floor — the fixed 4 NEG + 5 REQ + 2
  margin pattern alone would overdraw a default nostream before any live
  subscriptions. Honouring advertised `max_subscriptions`
  is therefore required ledger work, not just an optimisation.
- **Message budget M = 128 KB** (nos.lol); we target ≤ 96 KB of filter payload
  per message, a 1.3× margin for the envelope.
- **Per-filter value budget 32 KB** (half of strfry's 65535-byte set cap;
  a full-chunk NEG-OPEN is ~33 KB, ~1.8× under the 60 KB negentropy frame
  limit our own embedded relay enforces), chosen so three full chunks fit one
  96 KB REQ message — see lever 2.
- A serialized 64-char hex ID costs ~67 bytes (`"…",`), so:
  ~489 hex IDs per filter, ~1460 hex IDs per message. Variable-length values
  (`#d` identifiers, repo references) must be budgeted by bytes, not count.

---

## Our Approach: A Per-Connection Budget Ledger

Each relay connection owns one implemented budget ledger of B subscription
slots. Four consumers share it, in priority order:

1. **Essential live subscriptions** (persistent, `limit: 0`) — announcements,
   repository states, canonical repository `a` references and canonical root
   `e` references are never demoted.
2. **Reserved margin** (2 slots) — control-plane safety capacity kept beyond
   the live set (which includes Layer-1) for ad-hoc operations and recovery.
3. **Historic sync and dependency recovery** (transient) — at least one usable
   slot remains after live admission; negentropy rounds,
   REQ+EOSE pages/fallbacks/retries, and exact-ID purgatory polls draw from
   the remainder. NEG retains its four-round class cap and transient REQ its
   five-request class cap, but neither can exceed the shared residual.
4. **Priority-tiered reference coverage** — remaining filters are considered
   in this order: root `E`; core compatibility `q`/`A`; descendant canonical
   `e`/`a`; descendant `q`. A complete tier remains persistent only when it
   fits after essential coverage while preserving the margin and a transient
   slot. Lower tiers advance one relay-compatible, cursor-overlapped REQ+EOSE
   filter group per five-second tick through the same transient queue. Descendant uppercase
   `E`/`A` references are historic-only. Direct thread members contribute
   event IDs and replaceable/addressable coordinates, covering one descendant
   generation without recursively expanding the frontier.

NIP-11 `max_subscriptions` sets B for each new connection session; when it is
absent B falls back to 20. Advertised values below that floor are honoured
(notably nostream's default 10). Two slots remain reserved. Essential live
filter groups are packed first and admitted atomically against the advertised
subscription-count budget. Incremental five-second batches preserve full
essential REQs and separately owned tiered reference REQs. Tier filters are
packed across boundaries, while admission stops at a complete-tier boundary.
The planner uses the same
filter-count and serialized-byte grouping rules as wire submission. It repacks
the complete mutable core tail with the new filters when that releases at least
one slot; otherwise it retires only the smallest useful subset which reduces
the incremental slot cost. Thus byte-bound groups are not rebuilt merely
because they contain fewer than the maximum filter count. Repository and
identifier inputs are sorted before byte chunking so equivalent coverage has
stable group identity. Before extending the tail, exact duplicates are removed
against currently held core filters and within the incoming action. Historic
retries therefore reuse successful live coverage instead of consuming more
slots. Auxiliary subscriptions do not count toward this check because their
owner can retire them independently. Historical bounds remain part of filter
identity, and closed core filters become eligible for admission again.
Historic repository batches union root and direct-descendant values into one
`e`/`E`/`q` family, and repository and addressable-descendant coordinates into
one `a`/`A`/`q` family, before ordinary count/byte grouping. This lets one REQ
deduplicate events matching both core and descendant references without
creating a subscription per repository.
If the changed tail cannot fit the count or learned byte budget, no extension
is opened and historic recovery remains available. Capacity pressure is the
backstop which may schedule a complete regroup after outstanding historic
batches drain; an ordinary tail update never rebuilds stable full groups.

Reconnect and exceptional full restoration rebuild essential coverage first;
the five-second reconciler then admits the largest complete prefix of reference
tiers which fits the refreshed session budget. Both full replacement and tail
replacement remember the exact previous grouping:
a failure while opening a replacement closes every newly opened group and
restores the retired groups. A partial CLOSE failure likewise reopens any tail
groups which were already closed before reporting the failure. Multi-connection
sharding remains the later lever.

A transient slot is released only after EOSE has caused CLOSE to be enqueued,
after relay CLOSED, or after connection teardown. Because NIP-01 provides no
CLOSE acknowledgement, the 120-second recovery path sends CLOSE for only the
timed-out subscription and releases only that subscription's generation-scoped
slot after the SDK accepts the message; valid production startup pages exceeded
30 seconds, while two minutes remains a bounded escape from a stuck
subscription. If CLOSE cannot be enqueued, the slot remains held until ordinary
connection teardown so local accounting cannot run ahead of the relay. The SDK
auto-close deadline also removes transient registry entries: SDK unsubscribe
alone only removes persistent subscriptions. A generation-checked timeout
notification retires the pending batch, cancels its remaining admission work,
and closes its other requests without confirming coverage. Unexpected transient
CLOSED follows the same failure path; queued EOSE is processed first so a
successful response followed by CLOSED still confirms normally. Exact-ID
purgatory polling uses the same transient class bound and shared ledger as
historic pagination. Transient subscription IDs and their permits are
registered locally before the REQ is sent; this ordering is required because
an empty or cached response can deliver EOSE/CLOSED before the SDK subscribe
call returns. Negentropy hydration also registers the complete paced chunk set
and its requested-event accounting in the pending batch before sending the
first REQ, so early deliveries cannot become an artificial missing residual.
Subscribe failure rolls both forms of pre-registration back. Unexpected
CLOSED for a persistent live subscription is
reported to the manager, which recomputes and transactionally reopens complete
live coverage. Each reconnect closes the retired ledger and creates a new
generation; queued or late borrowers therefore fail before sending on the new
SDK session and cannot inflate or bypass its capacity.

Descendant live subscriptions are kept outside the core rollback set. Core
consolidation or restoration first closes them, and aborts if CLOSE cannot be
sent, so auxiliary coverage cannot silently consume capacity needed by newly
required core filters. An auxiliary CLOSED retires its remaining group and
falls back to EOSE-closing history without rebuilding healthy core coverage.

Some relays additionally cap the cumulative serialized REQ state retained by
one connection. NIP-11 has no field for this limit, so it cannot be negotiated
before the first refusal. A CLOSED reason of the rust-nostr form `active
subscriptions exceed max size N bytes` is treated as a durable capacity signal,
not as a temporary query-rate episode. The connection remembers N across
reconnects and rebuilds its persistent filter groups within that byte budget,
reserving one maximum-sized transient REQ. Byte-limited sessions serialize
transient REQs so actual relay occupancy cannot overdraw that reserve.

Persistent groups beyond the learned cap are not silently abandoned. One
byte-limited relay is given a paced incremental historic catch-up every five
minutes, with a one-minute overlap, through the same slot ledger and background
query pacer as ordinary history. This preserves eventual completeness without
recreating an impossible live set. The first capacity response remains
unavoidable because the limit is not advertised; multi-connection sharding is
still out of scope and would improve latency rather than correctness.

The per-relay event processor retains its 1,000-message bounded data queue.
Permit release does not depend on that queue draining: a separate listener on
rust-nostr's broadcast relay notifications consumes only EOSE/CLOSED terminals
and closes/releases transient ownership. The processor-facing listener still
delivers ordered EVENT and lifecycle work to the sync actor. EOSE and CLOSED
use bounded actor inboxes; permit retirement is independent of actor progress.
History reconciliation, paced group admission, pagination and hydration retries
run in background jobs (eight globally, one per relay), without holding the
manager or pending-index lock during network or pacing waits. Live startup for
other relays can proceed immediately. Each batch pre-registers wire IDs and a
local admission barrier, preventing fast EOSE from confirming partial coverage.
Admission failure retires the incomplete set and leaves its coverage retryable;
reset/disconnect cancels workers before the next session starts. Connection
attempts retain their eight-worker cap and start at least 250 ms apart, measured
from actual starts so a delayed executor does not emit a catch-up burst.


The levers, in the order we reach for them:

### Lever 1: Maximise items per filter (byte-budgeted chunking)

Replace the fixed 100-items-per-chunk rule with byte budgets: a filter chunk
is full when it reaches 32 KB of serialized tag values (~489 hex IDs), and a
message is full at ~96 KB. The 100-item chunk was a guess made when we
believed relays capped item counts; the verified constraints are byte caps
(strfry 65535 per filter set, message size per NIP-11), so counting items
wastes ~4.9× capacity for hex IDs while being *unsafe* for unbounded-length
`#d` identifiers.

Chunk and REQ budgets are maximised *together* because they bound different
costs: for a total serialized payload T, persistent subscription count
scales with how full each REQ is packed (T / 96 KB), while negentropy round
count scales with chunk size (T / 32 KB — one round per filter). Bigger
chunks do not inflate subscription counts as long as full chunks still pack
three to a REQ, so 32 KB chunks in 96 KB REQs minimise both at once — and
three full chunks per REQ matches strfry's strict `filterValidation` limit
of three filters per REQ. What eventually bounds filter size is none of the
byte caps but per-query result limits (e.g. damus "blocked: too many query
results" against filters that match too much at once); accounting for those
belongs to the budget-ledger work.

Because the limits are not discoverable (NIP-11 gap), the budget is static
and conservative rather than probed; the existing transient-failure cooldown
and REQ+EOSE fallback absorb the rare relay with tighter limits.

What this lever cannot do: collapse the three tag-variant filters. NIP-01
ANDs distinct tag conditions within one filter, so `a`/`A`/`q` (and
`e`/`E`/`q`) coverage requires three filters per chunk regardless of size.
strfry's `maxTagsPerFilter = 3` counts tag *fields* per filter; our filters
use one tag field each, so this is not a binding constraint.

### Lever 2: Pack filters per REQ — coupled to lever 1 by message size

Live subscriptions send all their filters in one REQ message, so the message
budget M caps **items per subscription** (~1460 hex IDs at the 96 KB payload
budget) no matter how items are split into filters. Packing more filters
into fewer REQs is what actually shrinks the persistent subscription count,
so the rule is a byte budget per REQ message, with filter count as a
secondary bound (strfry accepts 200 filters per REQ, but its optional
strict `filterValidation` mode accepts only 3 — matched by three full 32 KB
chunks per 96 KB REQ). Smaller filters may initially pack up to 10; the
session-local fallback above adapts them for strict relays while avoiding the
persistent-subscription cost everywhere else.

### Lever 3: Bound and schedule concurrency (coordination with live sync)

Negentropy reconciles one filter per round, and each in-flight round consumes
a subscription slot **from the same budget as live subscriptions** (strfry).
So concurrency is not a free scaling axis; it is the residual of the ledger:

- Per-connection NEG concurrency is at most
  `min(4, B − L − margin − other transients)`; when no residual remains,
  historic work waits rather than overdrawing.
- Rounds queue behind a per-connection semaphore; each completion releases
  the next. No timed batches or sleeps — throughput degrades smoothly instead
  of bursting into rejections.
- The ledger bounds simultaneous resource use, not query starts over time.
  Non-urgent historic REQs, pagination and hydration/retry pages, exact-ID
  dependency fetches, and NIP-77 round starts proactively share a one-second
  start interval from the beginning of each connection session. Persistent
  live subscriptions bypass that background gate and retain priority. This
  bounds application-visible starts, but cannot pace SDK-managed NIP-77
  `NEG-MSG` continuations. If a relay returns
  `rate-limited: too many queries`, the current connection
  first rejects locally queued starts for a 65-second initial cooldown so
  their incomplete work can be re-derived in priority order, then learns a
  shared query-start interval: 600 ms initially (100 starts/minute, below the
  older rust-nostr 120/minute limit), doubling on a later rate-limit episode up to
  10 seconds. Live, transient REQ, exact-ID fetch and NIP-77 round starts all
  pass through that reactive pacer in addition to background work retaining
  its proactive spacing. Relays that never report a query rate limit still
  receive proactively paced background work, while live starts remain
  immediate; reconnecting resets both per-session gates.
  After any query-budget refusal, NIP-77 is skipped for the rest of the session:
  rust-nostr owns the internal `NEG-MSG` exchange, so the application cannot
  guarantee that each charged frame passes through its pacing gate. Historic
  recovery then uses the paced REQ path.
- Failed rate-limit recovery probes double their pause from 65 seconds to
  at most one hour. Repeated notices during a pause do not extend it. Five
  unpaused minutes without another refusal reset the next delay; time spent
  paused or a successful WebSocket handshake does not count as recovery.
  Incomplete requests use an independent backoff with the same bounds,
  including watchdog expiry and unexpected transient CLOSED before EOSE.
  The watchdog records the pause before releasing its slot, preventing queued
  work from immediately replacing a failed request. Existing live coverage
  stays open, and history workers release global capacity while waiting.
  Overlapping rate, policy and request pauses must all expire before recovery;
  required live repair is remembered across overlapping pauses. Timeout-only
  recovery does not rebuild successful live subscriptions.
  If the transport disconnects, dialing also waits for every active policy,
  rate, or request pause before applying the ordinary transport backoff. A
  policy-limited health label must not override an outstanding dial deadline.
- Transient REQ+EOSE subscriptions — historic sync groups, fallback
  filters, exact-ID fetches, retries, and pagination pages — retain a
  five-request class cap inside the shared ledger: a slot is acquired when
  the auto-close REQ is sent and released when its EOSE or CLOSED arrives
  (with a 120 s watchdog that sends CLOSE for only the unresponsive
  subscription before releasing its slot). Each held permit retains one of a
  fixed set of request classes (historic page, pagination page, hint
  verification, negentropy hydration, retry, or semantic fallback); watchdog
  logs and metrics expose that class without using relay URLs or subscription
  IDs as metric labels. Live subscriptions are ledgered first, so NEG,
  transient REQ,
  and purgatory exact-ID polling share only the remaining capacity.
- The scheduler and outbound connection share the relay's rate-limit and
  policy-refusal state. Definitive blocked/restricted CLOSED responses pause
  admission on the control stream too, including participant mailbox fetches.
  NOTICE and rate-limited CLOSED messages update that state on the independent
  control stream, even when event delivery to the processor is blocked. New
  work checks it before pacing, then checks again after pacing and capacity
  waits immediately before handing a REQ, direct fetch, or new NIP-77 round
  to the SDK. Queued work rejected during the cooldown releases its permits
  and returns an error for the existing incomplete-work recovery paths.
  Filter-count and retained-subscription-byte refusals keep their specialized
  recovery paths rather than activating this generic cooldown. Requests
  already handed to the SDK and SDK-owned protocol continuations are not
  cancelled by this check; existing live subscriptions remain open.
  Historic group admission stops at the first failure and retires any groups
  already started. A partial set never becomes a confirmable batch: the whole
  set remains eligible for ordinary recovery after the pause. Expected local
  deferrals are debug messages, rather than one error per remaining group.
  Negentropy's separate transient-failure cooldown still directs later rounds
  to the budget-accounted REQ+EOSE fallback.
- The reactive machinery (escalating cooldown, rate-limit detection in both
  NOTICE and subscription-specific CLOSED messages, and per-batch fallback)
  remains the backstop for relays whose limits are below our floors. A
  rate-limited CLOSED removes its incomplete historic batch from pending and
  defers both that retry and live-coverage restoration until the cooldown;
  rejected work is therefore neither falsely confirmed nor immediately
  replayed into the limiter. Prevention remains first, reaction second.

### Lever 4: Multiple connections per relay (last resort)

strfry-family limits are **per connection**, so a second connection doubles
both the subscription budget and the NEG budget at that relay. This is the
escalation path when a relay's watched set can no longer fit:
`needed_live_slots + margin + 1 > B` even after levers 1–2.

Costs and risks, which is why it is last:

- Per-IP connection caps exist but are not advertised anywhere; exceeding
  them looks like abuse and risks bans. The tightest native cap found by
  the 2026-08-06 limit matrix is chorus at five simultaneous connections
  per IP (with a reconnect ban of at least one second), so the ≤ 4 bound
  now has source evidence rather than being pure caution. Bound
  connections per relay (≤ 4) and scale in with hysteresis.
- Each connection re-authenticates (NIP-42) and carries its own health state,
  file descriptor, and TLS/session overhead.
- Filter-to-connection assignment must be deterministic (stable sharding of
  the watched set) so reconnects and consolidation do not reshuffle
  subscriptions across the pool.

### Where the pressure actually lands

Budget pressure is worst where the watched set is largest — today that is our
own bootstrap relay (869 repos / 3632 roots ≈ 1 MB of serialized tag values,
i.e. ~11 messages minimum even optimally packed). Public relays typically
carry small per-relay target sets but tight budgets (B = 20). Two
consequences:

- For infrastructure we control (bootstrap, self-relay), raise and advertise
  server-side limits rather than spending client-side levers.
- For public relays, levers 1–3 keep us comfortably inside B = 20 at current
  scale; lever 4 exists for the point where a single public relay's target
  set outgrows ~`(B − margin) × 1460` hex-ID-equivalents (~26 k items).

---

## Serving-Side Obligations

We are also a relay, and peer GRASP instances run this same sync against us.
The rust-nostr 0.45 embedded relay now enforces 10 active negentropy sessions,
20 filters per REQ, and the other bounds recorded in the relay-limits
reference. ngit-grasp explicitly selects those defaults and advertises the
standard, discoverable subset. The remaining serving-side gap is a bound on
tag-value/filter payload size, for which NIP-11 has no standard field. At scale
we must:

1. Retain the existing NEG, REQ, subscription-memory, message, event, and rate
   bounds, and design a filter-payload bound if production evidence requires it.
2. Keep NIP-11 `limitation` aligned with every enforced standard field so
   well-behaved peers can budget against us.

---

## Trade-offs

**Gained:** deterministic behaviour against unadvertised limits; startup
bursts bounded by design rather than absorbed by cooldowns; a single model
(the ledger) that live sync, historic sync, and fallback all account against;
a defined escalation path to multi-connection scale.

**Given up:** peak theoretical throughput on permissive relays (a damus-class
relay with 200 subscription slots is used as if it had 20 when `limitation`
is absent — we only relax budgets when NIP-11 advertises headroom); some
implementation complexity (byte-budgeted chunking, permit-gated scheduling,
eventual sharding).

---

## Alternatives Considered

### Adaptive probing (start big, shrink on rejection)

**Pros:** discovers each relay's true limits; no static guesswork.
**Cons:** rejection signals are non-standard free-text NOTICEs; every
startup pays a rejection burst per relay; failure attribution is ambiguous
(payload size vs. subscription count vs. rate limit), so the probe can learn
the wrong lesson.
**Why not:** we tried the reactive-only posture implicitly and it produced
the 2026-08-04 incident; static floors with reactive backstop are
deterministic and testable.

### NIP-11-driven budgets

**Pros:** honest relays advertise `max_subscriptions` and
`max_message_length`; budgets could be exact.
**Why partial:** `max_subscriptions` and `default_limit` are consumed when
present, but message-size negotiation is not yet implemented, filter count has
no current standard NIP-11 field, and many relays omit `limitation` entirely —
so floors remain necessary. Proposing a NIP-11 extension for filter-size limits
is worthwhile upstream work.

### Timed batching with pause-on-rate-limit

**Pros:** simple to picture.
**Cons:** reactive by construction (eats one rejection burst per relay per
startup), needs heuristic NOTICE parsing as its *primary* control loop, and
fixed pauses waste time on fast relays while still bursting slow ones.
**Why not:** fixed global batching would penalise every relay and cannot adapt
to their different windows. The semaphore ledger continuously contains active
resources; the implemented per-session pacer is activated only by an explicit
query-rate refusal and then drains work smoothly at a learned rate.

---

## Rollout Mapping

| Lever | Status |
| --- | --- |
| 3 — bounded NEG concurrency | Stabilisation cycle 3 (in flight) |
| 3 — bounded transient REQ+EOSE concurrency | Landed with cycle 3 (same PR) |
| 1 + 2 — byte-budgeted chunking and REQ packing | Landed with cycle 3 (same PR) |
| Ledger unification (live + historic + fallback + purgatory polling against one NIP-11-aware subscription budget) | Implemented 2026-08-06; message-budget negotiation remains follow-up |
| 4 — multi-connection sharding | Deferred until a relay's target set approaches the single-connection ceiling |
| Serving-side limits + NIP-11 advertisement | Implemented 2026-08-07 for rust-nostr's enforceable limits and the standard discoverable subset; filter-payload bounding remains follow-up |

---

## Related Documentation

- [GRASP-02 Proactive Sync](grasp-02-proactive-sync.md) — the sync
  architecture these budgets apply to (filter layers, live vs historic,
  negentropy fallback).
- [Defensive Measures & Rate Limiting](defensive-measures.md) — the
  serving-side counterpart.
- [Monitoring Overview](monitoring.md) — metrics for observing sync health.

### Failed participant mailbox probes

Mailbox fetch failures, including rejected authentication, retry after five
minutes and double on each failed probe up to one hour. Only a successful fetch
resets this delay; reconnects and inventory growth preserve it. The cursor still
advances so one failed filter cannot monopolize the mailbox. Backoff is scoped
to that relay's mailbox work and does not close working live subscriptions.
Mailbox-only reconnects wait for the next probe deadline; independent discovery
or repository work can still connect. Removing a relay from the mailbox
inventory retires its backoff state.
