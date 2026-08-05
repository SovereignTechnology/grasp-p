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

| Relay | `max_subscriptions` | `max_message_length` |
| --- | --- | --- |
| nos.lol (strfry) | **20** | 131072 |
| relay.primal.net | **20** | 1000000 |
| nostr.wine | 50 | 524288 |
| relay.damus.io | 200 | 1000000 |
| relay.nostr.band, relay.ngit.dev | not advertised | not advertised |

### Discoverability gap (NIP-11)

NIP-11 `limitation` has **no field for tag values per filter and no field for
filters per REQ**. Only `max_subscriptions` and `max_message_length` are
advertised, and many relays omit `limitation` entirely. Consequence: filter
sizing cannot be negotiated per relay — it must be statically conservative,
with reactive fallback as the backstop.

### Our own embedded relay (nostr-sdk `LocalRelay`, 0.45.0-alpha.8)

- `max_reqs` = 500, enforced for REQ only (`src/nostr/builder.rs`).
- Negentropy: **no concurrency limit at all** (upstream `TODO`), 60000-byte
  frame limit per NEG message.
- No limits on filters per REQ or tag values per filter.

khatru (used by the ngit-relay reference implementation) and nostr-rs-relay
similarly enforce no filter-size limits by default.

### Working floors

Derived from the tightest commonly observed values; all sizing below assumes:

- **Subscription budget B = 20** per connection (nos.lol, relay.primal.net),
  shared between live REQs, NEG rounds, and fallback REQs.
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

Each relay connection owns one budget of B subscription slots. Three
consumers share it, in priority order:

1. **Live subscriptions** (persistent, `limit: 0`) — the product; sized first.
2. **Reserved margin** (2 slots) — the Layer-1 announcement subscription plus
   one spare for ad-hoc operations.
3. **Historic sync** (transient) — negentropy rounds and REQ+EOSE fallback
   subscriptions get the remainder: `N = clamp(B − L − margin, 1, 4)`.

Historic work is transient, so even `N = 1` makes progress; live coverage is
what must never be sacrificed. When even live subscriptions cannot fit
(lever 4 below), the budget multiplies across connections rather than being
overdrawn.

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
chunks per 96 KB REQ).

### Lever 3: Bound and schedule concurrency (coordination with live sync)

Negentropy reconciles one filter per round, and each in-flight round consumes
a subscription slot **from the same budget as live subscriptions** (strfry).
So concurrency is not a free scaling axis; it is the residual of the ledger:

- Per-connection NEG concurrency `N = clamp(B − L − margin, 1, 4)` — with the
  B = 20 floor and typical live loads, effectively ≤ 4.
- Rounds queue behind a per-connection semaphore; each completion releases
  the next. No timed batches or sleeps — throughput degrades smoothly instead
  of bursting into rejections.
- Transient REQ+EOSE subscriptions — historic sync groups, fallback
  filters, exact-ID fetches, retries, and pagination pages — queue behind
  their own per-connection semaphore (5 permits): a permit is acquired when
  the auto-close REQ is sent and released when its EOSE or CLOSED arrives
  (with a 30 s watchdog against relays that never answer). Live
  subscriptions are not gated. 4 NEG + 5 REQ + 2 margin leaves at least
  nine slots of the B = 20 floor for live subscriptions.
- Permit acquisition checks relay health first: while a rate-limit or
  transient-failure cooldown is active, queued rounds take the REQ+EOSE
  fallback path (which is itself budget-accounted) instead of firing into a
  relay that just complained.
- The reactive machinery (escalating cooldown, NOTICE-based rate-limit pause,
  per-batch fallback) remains the backstop for relays whose limits are below
  our floors — prevention first, reaction second.

### Lever 4: Multiple connections per relay (last resort)

strfry-family limits are **per connection**, so a second connection doubles
both the subscription budget and the NEG budget at that relay. This is the
escalation path when a relay's watched set can no longer fit:
`needed_live_slots + margin + 1 > B` even after levers 1–2.

Costs and risks, which is why it is last:

- Per-IP connection caps exist but are not advertised anywhere; exceeding
  them looks like abuse and risks bans. Bound connections per relay (≤ 4) and
  scale in with hysteresis.
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
The embedded relay currently enforces **no negentropy concurrency limit**
(upstream nostr-sdk `TODO`) and no filter-size limits — the mirror image of
the client-side incident that motivated this document. At scale we must:

1. Enforce server-side bounds (NEG concurrency, filters per REQ, filter
   payload) so one peer cannot exhaust us.
2. Advertise our limits in NIP-11 `limitation` (`max_subscriptions`,
   `max_message_length`) so well-behaved peers can budget against us —
   partially compensating for the discoverability gap we suffer as a client.

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
**Why partial:** the two advertised fields *are* consumed when present
(relaxing B and M above the floors), but per-filter and filters-per-REQ
limits simply have no NIP-11 field, and many relays omit `limitation`
entirely — so floors remain necessary. Proposing a NIP-11 extension for
filter-size limits is worthwhile upstream work.

### Timed batching with pause-on-rate-limit

**Pros:** simple to picture.
**Cons:** reactive by construction (eats one rejection burst per relay per
startup), needs heuristic NOTICE parsing as its *primary* control loop, and
fixed pauses waste time on fast relays while still bursting slow ones.
**Why not:** the semaphore ledger achieves the same containment continuously,
with the heuristics demoted to backstop.

---

## Rollout Mapping

| Lever | Status |
| --- | --- |
| 3 — bounded NEG concurrency | Stabilisation cycle 3 (in flight) |
| 3 — bounded transient REQ+EOSE concurrency | Landed with cycle 3 (same PR) |
| 1 + 2 — byte-budgeted chunking and REQ packing | Landed with cycle 3 (same PR) |
| Ledger unification (live + historic + fallback against one budget, NIP-11-aware B/M) | Design accepted here; implement after cycles 3–4 |
| 4 — multi-connection sharding | Deferred until a relay's target set approaches the single-connection ceiling |
| Serving-side limits + NIP-11 advertisement | Follow-up work item |

---

## Related Documentation

- [GRASP-02 Proactive Sync](grasp-02-proactive-sync.md) — the sync
  architecture these budgets apply to (filter layers, live vs historic,
  negentropy fallback).
- [Defensive Measures & Rate Limiting](defensive-measures.md) — the
  serving-side counterpart.
- [Monitoring Overview](monitoring.md) — metrics for observing sync health.
