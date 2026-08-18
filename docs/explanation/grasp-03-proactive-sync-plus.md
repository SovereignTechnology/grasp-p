# GRASP-03 proactive sync plus

GRASP-03 extends repository-declared GRASP-02 coverage to the Nostr outbox
model. An accepted issue, patch or pull request may have replies, reactions or
zaps in a conversation participant's inbox or outbox even when those events
are absent from repository relays.

The overlay is enabled by default and can be disabled with
`NGIT_SYNC_PLUS_ENABLED=false`. Because it extends the proactive GRASP-02
manager, it is effective only while that manager is running. NIP-11 advertises
`GRASP-03` only when the overlay is enabled.

## Minimal approach

The implementation adds a narrow discovery control-plane, not a second sync
engine: derive accepted root IDs and participant authors locally; ask a small
existing index set for each author's latest profile kind `0` and NIP-65 kind
`10002`; retain those replaceable events locally; keep accepted root authors'
`read` and unmarked inboxes in ordinary GRASP-02 coverage; and probe accepted
participants' `read`, `write` and unmarked conversation mailboxes with
repository and thread-reference filters. On public instances, the same
history-only probe associates accepted repository owners and declared
maintainers with those repositories and queries their mailboxes by repository
coordinate. This can discover a root which is not yet present locally.

Mailbox work reuses GRASP-02's connection safety, filter byte packing,
pagination, subscription ledger, request pacing, event pipeline and write
policy. The participant expansion is history-only: a non-root participant
relay never becomes a permanent live source merely because an accepted author
advertised it. Root-author inboxes retain the pre-existing live/rotating Sync+
behavior.

Authors without an accepted stored relay list are queried through the configured
user-index set plus the bootstrap relay. Once a list is retained, discovery
follows its `write` and unmarked outboxes instead, allowing newer replacements
to converge without making arbitrary repository relays identity sources.
Discovery remains best effort and bounded to this operator-visible source graph.

If a successful user-index query returns no accepted kind `10002`, accepted
roots associated with that author temporarily use the operator-configured
Sync+ fallback relay set as mailboxes. Root-author fallback roots continue
through ordinary GRASP-02 historic, live and rotating coverage; non-root
participant roots use the paced history probe. An accepted relay list removes
the author from fallback coverage and schedules its declared relays instead.

The self-subscriber builds a compact root-candidate inventory during its
existing startup load and maintains it incrementally as roots arrive. StateOnly
candidates remain inert; promotion of their repository to Full makes them
eligible without rescanning retained root events. A bounded recursive scan of
locally accepted root threads adds the authors of replies, reactions, zaps and
other descendants. Root provenance is carried through event-ID and address
references, so each participant is associated only with accepted threads in
which their events occur, including indirect descendants that expose only an
immediate parent. Eligible identity authors are
the owners and declared maintainers of accepted Full announcements plus
accepted root and descendant authors—not every author retained by the relay. A
once-per-minute reconciliation derives sources from this index. Remote queries
contain at most 100 authors and only one discovery batch may be in flight
globally. Admission samples immediate
transient capacity; if historic work wins the small race before the permit is
acquired, that single batch may wait but discovery can never build a waiter
queue. Its SDK-owned REQ draws from the same pacer and subscription ledger as
historic work. Discovery sources use the managed connection safety and
reconnection machinery, but are a distinct control-plane role: connecting to a
user index or outbox does not start ordinary announcement, repository, or
descendant sync against it. At most one new discovery source is dialled per
maintenance pass, and an exclusively discovery connection retires after its
currently due identity or mailbox work drains. A relay that independently becomes a
repository source is promoted to the ordinary lifecycle without opening a
duplicate connection. Authors returned by a successful query refresh after 24 hours;
missing authors and failed queries retry after five minutes. Configured user
index relays discover authors with no accepted local relay list, requesting the
profile alongside it. Accepted NIP-65
write/unmarked outboxes are then followed additively for newer replacements;
new outboxes discovered by a replacement join the same bounded round until no
unvisited source remains. Identity events
pass through the ordinary write policy, persistence and broadcast path. Only a
stored, accepted kind `10002` can change mailbox ownership. On startup, retained
relay lists for eligible authors rebuild mailbox ownership from the local
database before any network refresh, so serving established coverage does not
depend on an external index remaining available. Remote discovery then refreshes
that retained state on the normal cadence.

Root-author read/unmarked inboxes still use ordinary GRASP-02 coverage. Wider
participant mailboxes use history-only workers. A maintenance pass starts at
most one due relay, while each relay may have at most one worker in flight.
Relays do not share a mailbox lane or terminal state: a slow or unavailable
relay cannot prevent another relay from progressing on a later pass.

Each worker selects one stable-sorted, byte-bounded filter and delegates its
REQ lifecycle to the existing `RelayConnection::fetch_events` path. That path
owns per-relay request pacing, background priority, subscription-ledger
capacity, EOSE/CLOSED handling and a 30-second timeout. The worker reuses the
ordinary pagination state to continue through full historic pages until the
filter is exhausted or a page makes no new progress. It then passes events
through the normal write policy and persistence pipeline. No mailbox-specific
pending-batch kind, EOSE hook, close API, watchdog or cross-relay coordinator
is added.

The probe covers accepted repository coordinates, root IDs, bounded recursive
descendant IDs, and descendant address coordinates using `a`/`A`/`q` and
`e`/`E`/`q`. A repository-scoped owner or maintainer mailbox also receives
event-reference filters for every currently known root in that repository.
This permits a status or other descendant stored only on that mailbox to be
found even when the root author's current relay list does not name it. A
participant-only mailbox remains constrained to its derived roots. A numeric
in-memory cursor gives each byte-bounded filter group a turn. A successful
complete rotation refreshes after 24 hours; a failed group advances the cursor
after a five-minute delay and is retried on a later rotation. This is
deliberately best effort rather than a durable exactly-once schedule. A relay
already needed for ordinary repository sync shares its connection; an
exclusively control-plane connection retires when its identity and mailbox
work is idle.

Owner/maintainer expansion can increase a relay's history rotation in
proportion to the byte-packed repository coordinates and known roots assigned
to it. Shared relays and duplicate repository scopes are unioned before filter
construction. The expansion does not increase instantaneous worker
concurrency on any one relay: the manager still starts at most one due relay
per maintenance pass, each relay remains single-flight, and each worker fetches
one filter group through the existing background request pacer before
yielding. More distinct maintainer relays can nevertheless produce more active
per-relay workers across successive passes; the fixed-cardinality relay,
cursor, and active-worker metrics expose that growth for a production soak.

On restart, accepted roots and retained kind `10002` events rebuild participant
and mailbox ownership from LMDB. The in-memory group cursor is intentionally
not restored, so historic mailbox probing starts again from the first current
filter and remains safe to repeat. Inventory changes keep the cursor modulo the
new stable-sorted filter set; they do not coordinate with a worker on another
relay.

The fixed-cardinality retained-state metric reports eligible authors, desired
history-probe relays, allocated filter cursors, and active per-relay workers.
This makes a stuck worker or unexpected inventory expansion visible without
putting peer URLs or public keys into metric labels.

Mailbox replacement/removal changes desired ownership immediately. Root-author
inbox additions use ordinary coverage, while removal-only changes let existing
shared live subscriptions drain naturally. History-probe additions become due
promptly; removals prevent future groups while an already in-flight
`fetch_events` worker may finish naturally. Root deletion follows the existing
GRASP-02 root-index lifecycle and is reconstructed from retained accepted
events on restart; this change does not add a second deletion graph.

## Deliberately excluded

- mailbox expansion for authors who have not produced locally accepted
  repository-thread events and are not an accepted repository owner or
  maintainer;
- repository mailbox expansion beyond an owner's or declared maintainer's
  exact accepted Full repositories;
- repository-coordinate mailbox expansion in private mode;
- identity storage for authors outside accepted repositories and their
  locally accepted threads;
- per-user fallback configuration knobs; and
- permanent non-root participant-mailbox live subscriptions.
