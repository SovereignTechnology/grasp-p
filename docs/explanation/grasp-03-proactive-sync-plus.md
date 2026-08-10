# GRASP-03 proactive sync plus

GRASP-03 extends repository-declared GRASP-02 coverage to the Nostr outbox
model. An accepted issue, patch or pull request may have replies in the root
author's inbox even when those events are absent from repository relays.

## Minimal approach

The implementation adds a narrow discovery control-plane, not a second sync
engine: derive accepted root IDs and authors locally; ask a small existing
index set for each author's latest NIP-65 kind `10002`; treat `read` and
unmarked relays as inboxes; and merge inbox-to-root mappings into ordinary
per-relay sync targets.

GRASP-02 then owns all transport. Its current root tiers, historic and
live/rotating coverage, grouping, subscription ledger, rate-limit recovery,
pagination and per-relay connection lifecycle apply unchanged.

The index set is the configured bootstrap relay plus relays already declared
for accepted repositories. Discovery is best effort: completeness assumes the
current relay-list event is available from at least one existing source. This
avoids a new configuration surface and unbounded global discovery.

The local accepted-root inventory refreshes once per minute. Remote discovery
queries contain at most 100 authors, start at most one batch on each two-second
maintenance tick, and refresh successful author/source pairs after 24 hours.
Failures retry after five minutes. A query starts only when an existing relay
session has immediate transient capacity, and its SDK-owned REQ draws from the
same pacer and subscription ledger as historic work.

## Deliberately excluded

- the old recursive `SyncScope` graph and response-author fan-out;
- maintainer mailbox expansion unrelated to an accepted root;
- profile, broad identity, or general kind-`10002` storage;
- fallback lists and per-user configuration knobs; and
- a separate GRASP-03 subscription scheduler.

Kind `0` and general kind `10002` storage can follow if their value justifies
the admission and lifecycle policy they require.
