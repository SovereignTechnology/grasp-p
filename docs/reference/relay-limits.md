# Embedded relay limits

ngit-grasp embeds rust-nostr `LocalRelay` 0.45.0. The application selects every
effective limit explicitly so future dependency defaults cannot silently alter
production admission policy.

## Effective limits

| Limit | ngit-grasp default | Operator configuration | NIP-11 |
| --- | ---: | --- | --- |
| Total inbound connections | Unbounded | `NGIT_MAX_CONNECTIONS` | No standard field |
| Active REQs per connection | 500 | `NGIT_RELAY_MAX_SUBSCRIPTIONS` | `max_subscriptions` |
| Results per filter | 500 | `NGIT_RELAY_FILTER_LIMIT` | `max_limit`, `default_limit` |
| Serialized event size | 192 KiB | `NGIT_RELAY_MAX_EVENT_SIZE_BYTES` | No equivalent field |
| Event writes per minute | 60 | Fixed | No standard field |
| Queries per minute | 1,200 | Fixed temporary override | No standard field |
| Authentication events per minute | 30 | Fixed | No standard field |
| WebSocket messages per minute | 6,000 | Fixed | No standard field |
| WebSocket message size | 5 MiB | Fixed | `max_message_length` |
| Handshake deadline | 10 seconds | Fixed | No standard field |
| Subscription-ID length | 250 bytes | Fixed | `max_subid_length` |
| Filters per REQ | 20 | Fixed | No standard field |
| Subscription state per connection | 5 MiB | Fixed | No standard field |
| Active negentropy sessions per connection | 10 | Fixed | No standard field |
| Negentropy items per connection | 50,000 | Fixed | No standard field |
| Negentropy frame | 60,000 bytes | Fixed upstream | No standard field |

The filter setting is applied consistently to rust-nostr's explicit filter
cap, per-query result cap, and omitted-limit default. Limits are per filter;
results from multiple filters in one REQ are merged without an aggregate
truncation.

The 192 KiB event default is three times rust-nostr's new 64 KiB default.
Production history contains a valid NIP-34 patch event of about 149 KiB, so
64 KiB is incompatible with ngit-grasp's purpose. The raised limit remains
bounded and below the 5 MiB WebSocket message ceiling.

The 5 MiB subscription-state allowance raises rust-nostr's 1 MiB default.
Repository sync keeps multiple byte-budgeted filters live: production's
34-filter coverage reached roughly 1.2 MiB and the smaller bound silently left
part of that coverage closed. The new allowance remains finite per connection,
matches the maximum admitted WebSocket message, and provides about four times
the observed working-set headroom. NIP-11 has no field for this cumulative
byte limit, so clients cannot negotiate it.

The 1,200-query allowance temporarily overrides rust-nostr 0.45's newly
introduced 120/minute default. A finite per-connection bound remains one useful
DoS layer, but the upstream default is unusually restrictive for sync clients
and currently counts every SDK-managed NIP-77 `NEG-MSG` continuation as another
query. Review this 10× override after upstream changes that accounting; a small
per-connection quota is not a substitute for per-IP admission or global
resource bounds because clients can multiply connections.

## Client adaptation

ngit-grasp refetches NIP-11 per connection session. Its outbound sync ledger
uses `max_subscriptions`, falling back conservatively when absent. Adaptive
historic pagination uses `default_limit` with a verification page and learns
from raw delivered page sizes. `max_limit` describes explicit filter limits;
historic sync currently omits `limit`, so it does not treat `max_limit` as an
omitted-filter page-size promise.

NIP-11 has no standard `max_filters` field in the current schema. Filter-count
and serialized-message budgets therefore remain conservative client-side
constants rather than falsely negotiated capabilities.
