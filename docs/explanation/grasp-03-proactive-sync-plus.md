# GRASP-03 proactive sync plus

GRASP-03 extends repository-declared GRASP-02 coverage to the Nostr outbox
model. An accepted issue, patch or pull request may have replies in the root
author's inbox even when those events are absent from repository relays.

## Minimal approach

The implementation adds a narrow discovery control-plane, not a second sync
engine: derive accepted root IDs and authors locally; ask a small existing
index set for each author's latest profile kind `0` and NIP-65 kind `10002`;
retain those replaceable events locally; treat `read` and unmarked relays as
inboxes; and merge inbox-to-root mappings into ordinary per-relay sync targets.

GRASP-02 then owns all transport. Its current root tiers, historic and
live/rotating coverage, grouping, subscription ledger, rate-limit recovery,
pagination and per-relay connection lifecycle apply unchanged.

Authors without an accepted stored relay list are queried through the configured
user-index set plus the bootstrap relay. Once a list is retained, discovery
follows its `write` and unmarked outboxes instead, allowing newer replacements
to converge without making arbitrary repository relays identity sources.
Discovery remains best effort and bounded to this operator-visible source graph.

The self-subscriber builds a compact root-candidate inventory during its
existing startup load and maintains it incrementally as roots arrive. StateOnly
candidates remain inert; promotion of their repository to Full makes them
eligible without rescanning retained events. A once-per-minute reconciliation
derives sources from this index. Remote queries contain at most 100 authors and
only one discovery batch may be in flight globally. Admission samples immediate
transient capacity; if historic work wins the small race before the permit is
acquired, that single batch may wait but discovery can never build a waiter
queue. Its SDK-owned REQ draws from the same pacer and subscription ledger as
historic work. Authors returned by a successful query refresh after 24 hours;
missing authors and failed queries retry after five minutes. Identity events
pass through the ordinary write policy, persistence and broadcast path. Only a
stored, accepted kind `10002` can change inbox ownership. On startup, retained
relay lists for accepted root authors rebuild inbox ownership from the local
database before any network refresh, so serving established coverage does not
depend on an external index remaining available. Remote discovery then refreshes
that retained state on the normal cadence.

Inbox replacement/removal changes desired ownership immediately. Additions are
derived promptly. Removals prevent future rotating and historic work, but do
not eagerly CLOSE live descendants or abort shared in-flight batches: existing
coverage drains on its natural EOSE/CLOSED/disconnect or an ordinary later
consolidation rebuild. This avoids interrupting unrelated roots and subscription
churn merely because one author replaced a relay list. Root deletion follows
the existing GRASP-02 root-index lifecycle and is reconstructed from retained
accepted events on restart; this change does not add a second deletion graph.

## Deliberately excluded

- the old recursive `SyncScope` graph and response-author fan-out;
- maintainer mailbox expansion unrelated to an accepted root;
- identity storage for authors other than accepted roots;
- fallback lists and per-user configuration knobs; and
- a separate GRASP-03 subscription scheduler.
