# GRASP-P operator runbook

> **Provenance (Phase-4b):** written against `ngit-grasp` branch
> `grasp-p-phase-4b` (Phase-4b feature-complete: per-write-key rate limiting,
> 30640 replacement cadence, exact-host URL checks, hourly full re-issue,
> mirror retry backoff, denylist purge/reload, kind-1984 intake, shipped
> default `whitelist`, split-view watchdog, nginx zones + Prometheus alerts).
> Every knob name, default, metric, and message string below was verified
> against the code at that revision; `file:line` citations are included so
> reviewers can re-verify. If code and this runbook ever disagree, the code
> wins — file a doc bug.
>
> **Since the port onto ngit-grasp v3.0.7 (2026-10-05):** the `file:line`
> citations below still point at the v1.2 line and no longer match; search
> for the symbol instead. No GRASP-P deployment exists at present: the host
> names below show the shape of one and are not GRASP-P nodes. A tagless
> kind-1059 wrap from a client is now refused by the relay before the
> GRASP-P policy sees it. The host needs
> git 2.42 or newer on `PATH` (Debian 13, or a newer git on Debian 12): see
> [../SEAMS.md](../SEAMS.md).

Audience: the operator of a public two-node GRASP-P deployment
(`git.sovit.xyz` / `git.buildinelsalvador.com` shape): YunoHost boxes, nginx
terminating TLS in front of `ngit-grasp` on `127.0.0.1:7334`, systemd units,
Prometheus scraping the node's loopback metrics endpoint (§3, "Where the
scrape comes from"; examples below use `127.0.0.1:9464`).

Sibling ops docs (read those first for install detail; this runbook does not
duplicate them):

- [watchdog.md](watchdog.md) — split-view watchdog build, flags, systemd units
- [prometheus-alerts.yaml](prometheus-alerts.yaml) — the alert rules this runbook plays
- [nginx-upload-zones.conf](nginx-upload-zones.conf) — per-IP outer rate layer
- [../../reference/configuration.md](../../reference/configuration.md) — full knob reference (WP-E admission section, Phase-4b sections)
- [../../how-to/prometheus-setup.md](../../how-to/prometheus-setup.md) — scrape setup

---

## 1. Deployment posture

**The shipped default is `whitelist`.** `NGIT_GRASP_P_REGISTRATION_MODE`
defaults to `whitelist` (src/config.rs:619) and
`NGIT_GRASP_P_TENANT_WHITELIST` defaults to empty (src/config.rs:627). An
empty whitelist is the accept-nothing posture: every NEW alias registration
is rejected with `tenant is not on the registration whitelist`
(src/grasp_p/registration.rs:463), and boot emits a loud warn
(src/config.rs:1025–1030):

```
NGIT_GRASP_P_REGISTRATION_MODE=whitelist with an empty NGIT_GRASP_P_TENANT_WHITELIST: all new private-repo registrations will be rejected (existing registrations are unaffected)
```

If you expected `open`, that line is your misconfiguration alarm.

### Admit a tenant

```bash
# on BOTH nodes: append the tenant npub (bech32, comma-separated) to the unit env
NGIT_GRASP_P_TENANT_WHITELIST=npub1aaa…,npub1bbb…
systemctl restart ngit-grasp
```

**A config change requires a restart — there is no reload path.** The
process handles only SIGINT/SIGTERM for shutdown (src/main.rs:87–111); no
SIGHUP handler exists. The single exception is the denylist file, which
reloads on its own timer (§4). Everything else — including the whitelist —
takes effect only at boot.

The whitelist feeds the `policy_fingerprint` preimage (§2), so both nodes
MUST run identical lists: update both env files, restart both, then verify
fingerprint parity before admitting traffic.

### When to use `open` / `pow`

- **`open`** — staging/self-use only. Every fresh key receives the full
  per-tenant quota, so ~50 pseudonymous tenants can lawfully exhaust the
  whole-subsystem storage budget (server issue !7; the WP-E note in
  configuration.md §`NGIT_GRASP_P_REGISTRATION_MODE`).
- **`pow`** — permissionless-but-costly admission:
  `NGIT_GRASP_P_POW_BITS` NIP-13 leading-zero bits on the 30640 (default 20,
  valid 1–40 — src/config.rs:1032).
- **`paid`** — not built. `Config::validate()` hard-fails boot
  (src/config.rs:1014–1017). Never select it.

### Escalation path: `open` → `whitelist` → `pow`

The mode gate applies to NEW aliases only, and `boot_reconcile` is
**non-destructive** (src/grasp_p/mod.rs:488–506; pinned by the exit12
integration test): a same-tenant replay of an event this node already
admitted skips the admission gates, and a replay that no longer passes is
warn-logged only — no meta mutation, no eviction, no relay-DB prune.

What existing tenants experience when you tighten the mode: **nothing.**
Across reboots they keep serving — 30640 REQ, blob GET, new 30641 editions,
rotations (configuration.md §`NGIT_GRASP_P_REGISTRATION_MODE`, "Boot-time
re-enforcement").

Exception: after a **meta-store wipe**, replays ARE fresh admissions, so a
stricter mode blocks the rebuild. Remedy (same configuration.md section):
temporarily set `open` (or list the affected npubs), restart to rebuild the
index, then flip back.

Any mode change moves the `policy_fingerprint` — coordinate both nodes (§2).

### What a registration is checked for, and in what order

A kind-30640 registration from a client or from the peer is checked from the
cheapest test to the most costly, and the first failure is the answer:

1. its date, then its size;
2. its shape, with no signature verified: the `d` tag, at least one `w`
   key, the number of keys against `NGIT_GRASP_P_MAX_WRITE_KEYS_PER_ALIAS`,
   the form of each key, no key twice, a proof on every key that is not the
   author's, and `relays` and `server` tags that name this node;
3. admission: an account that already holds the alias passes; anyone else is
   subject to the mode (`whitelist`, `pow`, `open`);
4. the proofs of possession, one signature check per key;
5. the write: admission once more, then conflicts, the alias limit, the
   quota and the replacement cadence.

What this means in operation:

- **A sender the mode refuses costs the node almost nothing.** It gets
  `tenant is not on the registration whitelist` (or the proof-of-work
  message) before any proof is verified and before any conflict is looked
  at. It raises no `NgitPrivateRegistrationConflict`, and nothing is pruned
  on its account. It still counts in
  `ngit_private_events_rejected_total{kind="30640"}`
  ([Admission rejection spike](#admission-rejection-spike)).
- **An account you take off the whitelist keeps its repositories.** It can
  still replace the registrations it holds (rotate keys, remove a member).
  It cannot register a new alias. To stop an account altogether, use the
  event blacklist, which freezes it and leaves its data readable (§2, "The
  event blacklist"; §4 step 8).
- **A registration with several faults reports the earliest one in the list
  above.** A client that used to see a proof message may now see the key
  limit, the whitelist or a `must list this node` message for the same
  event. The texts themselves are unchanged (§5).
- **At start-up** the node re-applies the registrations in its own relay
  database that its meta store lacks. There the conflict checks still come
  before the mode, so a leftover loser of an old conflict is removed even
  when its author is no longer admitted. A conflict met there against a
  seat the meta store already held is judged as it would be live, by the
  order and by the seat's age (a refusal by age deletes nothing); against
  a seat the replay itself created (a rebuild of a wiped meta store) by the
  order alone ([Registration conflict](#registration-conflict)). A restart
  or a rebuild can still differ from what the node decided when the events
  first arrived in the cases listed in §10 ("A rebuild meets leftovers",
  "Three or more parties"). Never start on a meta store older than the
  relay database (§9, "Restores").

### Under a base path

A node served under `NGIT_BASE_PATH` (say `/grasp`) is named by its host and
that path together. Nothing in this section applies to a node at the root of
its domain.

- **Registrations must name the mounted URL.** The `relays` tag has to carry
  `wss://<domain>/grasp` and the `server` tag `https://<domain>/grasp`. A
  registration naming `wss://<domain>` alone is refused with
  `registration relays tag must list this node`: a client told the bare host
  would talk to whatever else is served there. A registration for a pair
  names both nodes; each node looks for itself.
- **Peer lists must spell each node with its path.** In
  `NGIT_GRASP_P_SYNC_PEER_URLS`, `wss://<domain>/grasp` is this node and is
  left out; `wss://<domain>` or `wss://<domain>/other` is taken for another
  service and dialled as a peer. The same holds for the entries of
  `NGIT_GRASP_P_MIRROR_PEER_URLS`: `https://<domain>/grasp` is this node,
  `https://<domain>` another service the mirror asks for blobs. The
  `policy_fingerprint` covers this node's full address and every entry of
  `NGIT_GRASP_P_SYNC_PEER_URLS` (§2), so an entry that misses a path shows
  there as a mismatch, whichever node it names. The aliases in the scrape
  tell which: a node that numbers itself as a peer has an entry that misses
  its own path.
- **The watchdog** given `--relay-a wss://<domain>/grasp` takes that node's
  blob base from the `server` values with the same path. Pass
  `--blob-base-a` / `--blob-base-b` when no registration names it.
- **Moving a node under a path, or to another path, orphans its
  registrations for clients**: they name the old URL. The node keeps
  serving them from its meta store, but a rebuild of a wiped meta store
  refuses every registration that does not name the new URL. Have the
  accounts publish new editions first.

### Who a node replicates with

A node replicates private repositories with the relays in
`NGIT_GRASP_P_SYNC_PEER_URLS` and with no other. Write the other node of
the pair there, on both nodes; one list for both is fine, since an entry
that names the node itself is left out.

- **List each peer over `wss://`, by its public name**: the other node's
  `NGIT_DOMAIN`, as in `wss://b.example` (a bare `b.example` is read the
  same way). A peer is sent every alias and write key the node holds. Use
  `ws://` only on a private link, by the address that is the peer's
  `NGIT_DOMAIN` there, with `NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS=true`
  ([A pair on a private network](#a-pair-on-a-private-network)). Without
  that setting (or `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS=true`, for tests and
  closed networks) a `ws://` entry, or an `http://` one (read as `ws://`),
  stops the node at startup:
  `NGIT_GRASP_P_SYNC_PEER_URLS lists ws://..., a plaintext ws:// peer, and
  a peer is sent every alias and key this node holds`. The same holds for a
  peer that is also the bootstrap relay: the node dials that one as
  written, with no other check on its scheme.
- **Only a listed peer is sent the private sync filters.** They name every
  alias and write key the node holds. Every other relay the node syncs with
  for its public repositories (the user index, the Sync+ fallbacks, relays
  that announcements name) gets upstream's filters and nothing more.
- **Only a listed peer may bring GRASP-P events.** A registration, state
  root or stream wrap that relay sync brings from any other relay is
  refused before admission, held nowhere and remembered nowhere, so the
  same event from the peer, or from a client, is taken as ever. The node
  logs `Refusing GRASP-P events from a relay that is not a configured sync
  peer` once per relay (up to 1024 relays), and counts each such event in
  `ngit_private_sync_foreign_source_total`. Such a relay was never asked
  for them; a rising count means a relay sends what nobody asked for, or
  the peer is reached under a second name that the list does not spell
  (another host name, a path, `ws://` for `wss://`).
- **The bootstrap relay is a peer only when the list names it.**
  `NGIT_SYNC_BOOTSTRAP_RELAY_URL` alone no longer wires a pair: such a
  relay carries public sync only, is retired and redialled as upstream
  decides, and gets no alias in the scrape. A node whose peer is named only
  there replicates nothing, and its `NgitSyncPeerDisconnected` fires with
  value 1. The `policy_fingerprint` takes its domain set from the list, not
  from the bootstrap relay (§2), so such a pair shows unequal fingerprints,
  and each node warns at startup: `NGIT_GRASP_P_SYNC_PEER_URLS names no peer
  of this node`.
- **Unset list, no replication.** A node with GRASP-P on and no peer serves
  its clients and pulls no private repository from any relay. With its blob
  mirror on, or a bootstrap relay set, it says so once at startup
  (`NGIT_GRASP_P_SYNC_PEER_URLS names no peer of this node`). Sync is
  pull-only and reads are not gated, so any client, and any node that lists
  this one as its peer, can still fetch its GRASP-P events by REQ and its
  blobs by GET.
- **Blobs come from `NGIT_GRASP_P_MIRROR_PEER_URLS` alone.** Write the other
  node's blob base there, on both nodes: the host, port and path of its
  relay, over `https` (`https://<peer-domain>`, or
  `https://<peer-domain>/grasp` under a base path). One list for both
  nodes is fine here too. A node with the mirror on and no peer in the list
  fetches no blob from anywhere and says so once at startup:
  `NGIT_GRASP_P_MIRROR_ENABLE is true and NGIT_GRASP_P_MIRROR_PEER_URLS
  names no peer of this node`; its missing blobs fail as `no_peer`
  ([Mirror failures](#mirror-failures)).

Relay and server tags in a registration are advisory: they tell clients
where to go, and never make the node open a relay connection or fetch a
blob from a host they name. The two lists are separate settings and the
node does not compare them: set both.

### A pair on a private network

The two nodes of a pair can reach each other over a private link (a tunnel,
a private subnet) while the node's guard against internal addresses stays
on for every relay that customers' events name.

- **Set `NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS=true` on both nodes, and
  leave `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS` unset.** The first says the
  pair's link is private. It lets the blob mirror fetch from a private
  address, and it exempts the relay connection to a configured peer, and
  to no other relay, from the outbound target policy. The second lifts
  that policy for every relay an event names; a pair no longer needs it.
- **A configured peer** is an entry of `NGIT_GRASP_P_SYNC_PEER_URLS`, and
  the relay in `NGIT_SYNC_BOOTSTRAP_RELAY_URL` only when the list names it
  too. Name the other node there by the address it has on the private
  link, for example `ws://10.20.0.2:8080`. The policy_fingerprint
  compares this entry with the other node's own address (§2): an entry by
  IP, or on a port other than the one in the peer's `NGIT_DOMAIN`, makes
  the two fingerprints differ for good. The exemption goes with exactly
  that URL: a customer's event that names another internal address is
  refused as before, with `Rejecting event-directed sync relay target` in
  the log.
- **Set `NGIT_GRASP_P_MIRROR_PEER_URLS` as well**, to the other node's blob
  address on the link, for example `http://10.20.0.2:8080`. It is the
  mirror's only source of peers: a registration's `server` tags cannot
  point the mirror at an internal host. With the setting on, the mirror
  checks no address a listed name resolves to, so list the peer by its
  address on the link, as here, or by a name whose DNS you control.
- **`ws://` and `http://` inside the link, or certificates from a public
  authority.** The relay client trusts the public web roots only, so a
  `wss://` peer with a certificate from a private authority is refused
  (`added to naughty list`, category `TlsCertificateInvalid`).
- **The setting is not in the `policy_fingerprint`** (§2): it decides what
  a node dials, not what it accepts. If one node has it and the other does
  not, the second does not start while it lists its peer over `ws://`
  (unless it has `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS=true`).
  Listed over `wss://` on an internal address, the second does not fetch
  blobs from the first over the link (its mirror backlog grows), and it
  refuses a peer that only `NGIT_GRASP_P_SYNC_PEER_URLS` names: `Skipping
  private-repo peer relay` in its log, events flow one way only, and
  `NgitSyncPeerDisconnected` with value 1 on that node
  ([Sync peer disconnected](#sync-peer-disconnected)). A listed peer that
  `NGIT_SYNC_BOOTSTRAP_RELAY_URL` names as well is still dialled there, so
  events arrive in both directions and only the blobs do not.
- **With the setting `false`**, the default, every peer must be `wss://`,
  and a peer that only `NGIT_GRASP_P_SYNC_PEER_URLS` names must be on a
  public address as well, like any relay. A `ws://` peer stops the node at
  startup, the bootstrap relay included when the list names it, unless
  `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS=true` (tests and closed networks).
  The relay in `NGIT_SYNC_BOOTSTRAP_RELAY_URL` alone is the operator's own
  target: the node dials it as written whatever this setting says, as
  upstream does, and never checks its address; a `ws://` one draws a
  warning at startup ([Which relays a node dials](#which-relays-a-node-dials)).
  The blob mirror still refuses an internal address without the setting.

On a node with GRASP-P enabled, a relay that an event or the peer list names
and that resolves to a NAT64 (`64:ff9b::/96`) or 6to4 (`2002::/16`) address
wrapping an internal IPv4 address, or to any address in the local-use NAT64
prefix (`64:ff9b:1::/48`), is refused before the dial: such an address
passes the ordinary check and can lead to an internal host. So is an IPv6
address outside `2000::/3` or inside `2001::/23` (Teredo, SIIT, SRv6), space
public relays are not numbered from. The blob mirror refuses the same
addresses. The log says `Rejecting event-directed relay target` with the
address. Not checked: the relay in
`NGIT_SYNC_BOOTSTRAP_RELAY_URL`, and a connection that the first point
exempts. The check is made on the addresses the name resolves to just
before the dial; the dial itself resolves the name again and is not held
to them (the NIP-11 probe is), so this stops a fixed record, not a name
whose answers change between the two lookups.

### Which relays a node dials

A node with GRASP-P enabled serves public repositories too, and syncs them
as upstream does: it dials the relays that public announcements name,
purgatory's dependency relays, and the relays in participants' NIP-65
lists. None of them is sent anything private, but it dials them over
`wss://` only, so that nobody on the path reads or alters what it pulls,
and so that a name whose answer changes just before the dial can hand an
internal host a TLS ClientHello at most, never an HTTP request of a
stranger's making.

| Dial | Chosen by | Scheme on a GRASP-P node | Carries |
|---|---|---|---|
| `NGIT_SYNC_BOOTSTRAP_RELAY_URL` | the operator | as written; `ws://` draws a warning, and when the peer list names it too, needs `NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS=true` or `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS=true` | public sync, and everything private when the peer list names it too |
| Relays that events name: announcements, purgatory's dependency relays, NIP-65 discovery and mailbox relays | anyone who publishes (the NIP-65 lane also uses `NGIT_USER_INDEX_RELAYS` and `NGIT_SYNC_PLUS_FALLBACK_RELAYS`) | `wss://` only; a `ws://` one is refused | public sync |
| `NGIT_GRASP_P_SYNC_PEER_URLS` | the operator | `wss://`, or `ws://` only with `NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS=true`; otherwise the node does not start, unless `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS=true` | every alias and key, and the GRASP-P events |
| Publishing the relay's identity, to `NGIT_USER_INDEX_RELAYS` | the operator | as written | the relay owner's kind 0 and 10002 |
| `NGIT_GRASP_P_MIRROR_PEER_URLS` | the operator | `https://`, or `http://` only with `NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS=true` | which blobs this node wants |
| Git fetches of public repositories | anyone who publishes | upstream's (`http://` or `https://`) | nothing |

A refused relay is never dialled or probed, and is logged once, as
`Rejecting event-directed sync relay target` with the relay and the reason
`a node that hosts private repositories dials event-directed relays over
wss:// only (relays that events name, and the entries of
NGIT_USER_INDEX_RELAYS and NGIT_SYNC_PLUS_FALLBACK_RELAYS)`. NIP-65
discovery then passes over it and dials the next source. A public
repository whose relays are all `ws://` therefore gets no relay sync on
this node; its events still arrive from clients that publish here, and
from the `wss://` relays this node already syncs it with, such as the
bootstrap relay and participants' inbox relays. A `ws://` entry in
`NGIT_USER_INDEX_RELAYS` still receives the identity events.

At startup, after the other GRASP-P checks:

- **Error:** `NGIT_GRASP_P_SYNC_PEER_URLS lists ws://..., a plaintext ws://
  peer`: list the peer over `wss://`, or declare the link private
  (above). `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS=true` also lets the node
  start, and is not meant for production.
- **Warning:** `NGIT_SYNC_BOOTSTRAP_RELAY_URL is ws://..., a plaintext ws://
  relay`: the operator's choice is kept. Use `wss://` unless the link is
  private.
- **Warning:** `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS=true on a node that hosts
  private repositories`: every outbound address check is lifted for what
  anyone's events name, and so is the `wss://` rule. Expected on test
  nodes; on a production node, unset it, and declare a private pair link
  with `NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS=true` instead.

---

## 2. `policy_fingerprint` parity

**What it is.** The first 16 hex chars of the SHA-256 over the
`grasp-p-policy-v4` preimage (`policy_preimage` in src/grasp_p/mod.rs):

```
grasp-p-policy-v4|mode=…|pow_bits=…|whitelist=…|max_event_bytes=…|max_blob_bytes=…|quota_tenant=…|quota_repo=…|global_budget=…|max_aliases=…|max_keys=…|replace_capacity=…|replace_refill_per_hour=…|accept_legacy_wrap_kind=…|blacklist=…|deletion_request_disrespector=…|domains=…
```

`domains` is this node's address (its domain, and its mount path under
`NGIT_BASE_PATH`) and the peers in `NGIT_GRASP_P_SYNC_PEER_URLS`, sorted,
each with the host in lower case, no default port (neither `:80` nor
`:443`, whatever the scheme), no trailing slash and no scheme. Write each
node in the other's list, on both nodes, and the two hash the same set; one
list for both nodes works too, since an entry that names the node itself is
left out. A list that leaves the other node out, names a third node, or
misses a mount path shows as a mismatch. Each entry has to be the other
node's own address: its `NGIT_DOMAIN`, with the port as written there, and
its mount path. A pair that lists each other by private-link addresses
(`ws://10.20.0.2:8080` for a node whose `NGIT_DOMAIN` is `b.example`)
replicates, but its fingerprints never match. Such a pair matches only when
each lists the other by its service name, resolved to the link address by
DNS or a hosts entry you control, on the same port. The
bootstrap relay is not in it (it was until v3): a pair may bootstrap its
public sync from any relay. The raw whitelist and the blacklist feed the
hash but are never exposed; still, someone who can guess every other input
can test a guess of either list against the published digest.

`blacklist` is the keys on `NGIT_EVENT_BLACKLIST` as sorted hex: on a
GRASP-P node a listed account is frozen (below), and a node that lists it
refuses what its peer took. An entry counts only when it is exactly an npub,
as upstream compares it, so order, repeats and entries that refuse nothing
do not move the digest.

`deletion_request_disrespector` is upstream's archival switch
(`NGIT_DELETION_REQUEST_DISRESPECTOR`). With it on, a deletion request for a
registration frees neither its alias nor its keys, and the deleted
registration sent again is taken, so with it on one node only a later
registration that reuses them is accepted there and refused on the other.

`accept_legacy_wrap_kind` (`NGIT_GRASP_P_ACCEPT_LEGACY_WRAP_KIND`, default
`true`) is in the preimage because it decides which stream-wrap KINDS the
node admits: a peer with it off rejects a legacy kind-1059 stream wrap this
node accepted and stored — a split view of the same repo. The label bumped
`v2` → `v3` when the knob was introduced.

The label bumped `v3` → `v4` when the domains moved to the peer list and the
blacklist and upstream's archival switch joined. It also marks two rules that changed what a node accepts
without a setting: a seat older than an hour is never displaced (§3
[Registration conflict](#registration-conflict)), and only the account key
deletes, a whole repository at a time (§5). **Every node's fingerprint
changes on each of these upgrades**; that is expected, and a mismatch of
labels during a rolling upgrade is exactly the signal to finish the roll.

Deliberately ABSENT from the preimage (node-local knobs):

- write-rate bucket (`NGIT_GRASP_P_WRITE_RATE_*`) — node-local DoS
  protection; synced/loopback traffic bypasses it
- denylist (`NGIT_GRASP_P_DENYLIST_*`) — per-jurisdiction legal config;
  paired nodes may legitimately differ
- re-issue interval, mirror retry knobs and the mirror's attempt budget
  (`NGIT_GRASP_P_MIRROR_MAX_ATTEMPTS_PER_MIN`) — node-local recovery
- the mirror's peer list and `NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS` — where
  a node fetches from and what it dials, never what it accepts

**Where to see it.**

- NIP-11: `private_repos.policy_fingerprint`, with the preimage label
  alongside it in `private_repos.policy_version` and the accepted set in
  `private_repos.kinds`
- boot log: the `GRASP-P private repositories enabled` line carries the
  `mode`, `policy_fingerprint`, `policy_version`, `sync_peers` (the peer set
  the domains come from) and `event_blacklist_keys` (how many keys the list
  refuses) fields

**Upgrade note.** Every label bump (v1→v2: the cadence knobs; v2→v3: the
wrap kinds; v3→v4: the peer list and the blacklist) and the WP-E mode
default flip (`open` → `whitelist`) change the fingerprint. An operator who never set the mode explicitly sees
their fingerprint change on upgrade (configuration.md WP-E notes). **Peers
must move together** — upgrade both nodes in the same window, or set the
mode explicitly on both beforehand.

**Check parity.**

```bash
for d in git.sovit.xyz git.buildinelsalvador.com; do
  printf '%s  ' "$d"
  curl -sH 'Accept: application/nostr+json' "https://$d/" \
    | jq -r '.private_repos | "\(.policy_fingerprint)  \(.policy_version)  \(.kinds|join(","))"'
done
```

The two lines must be identical (the watchdog's check 1,
`fingerprint-parity`, and check 1b, `kinds-parity`, do the same comparison —
§7). A mismatch means either that registrations can be accepted on one node
and silently rejected on the other (per-repo desync), or that the peer lists
do not name each other (no replication). Fix the config divergence, restart,
re-verify. Compare the two nodes' `sync_peers` and `event_blacklist_keys`
in the boot line first: a peer list that does not name the other node, or a
blacklist set on one node only, are the divergences the digest alone cannot
point at.

Read the digest WITH the version label:

- **different `policy_version`** (e.g. `…-v2` vs `…-v3`) — a rolling upgrade
  that has not finished. A label bump moves EVERY node's digest, so the pair
  necessarily mismatches for the whole window. Finish the roll.
- **same `policy_version`, different digest** — a real knob split: the two
  nodes disagree about what they accept. Diff the preimage knobs above.

The watchdog prints both labels on the `fingerprint-parity` line
(`policy-a=` / `policy-b=`) and says which case it is — including the third
one: a node that advertises NO label (`policy-a=unadvertised`) predates the
`policy_version` field entirely, which is the same rolling-upgrade window
seen from one side, so the watchdog calls it a version skew until both nodes
are upgraded (src/bin/ngit-private-watchdog.rs:484–519).

### The event blacklist

`NGIT_EVENT_BLACKLIST` (comma-separated npubs) is upstream's relay-wide
block. On a GRASP-P node it also freezes the private repositories of a
listed account (the key that signs their registrations):

- **What it refuses.** New registrations, deletion requests and vanishes by
  the account (upstream's check, since the account key signs them); and
  every write made under a registration the account holds, whichever key
  signs it: state roots, stream wraps, the upload preflight (`HEAD
  /upload`), `PUT /upload` and `DELETE /<sha256>`. A registration signed
  by one of the keys its registrations list is refused too, and no
  registration displaces one of its seats, however young (the challenger
  gets `alias already registered` or `write key already registered`). A
  listed key's own blob writes are refused too, under any registration.
  From clients and from the peer alike.
- **What the customer sees.** A refused event gets `blocked: Account <npub>
  is blacklisted` (or upstream's `blocked: Event author <npub> is
  blacklisted` for an event the listed key signed itself); a refused blob
  write gets `403` with the same text in `X-Reason`. Neither contains
  `unregistered`, so the client does not try to widen its registration;
  the push fails with that message.
- **What stays.** On each node, what it held when it was restarted: the
  account's registrations, state roots and wraps are still served to any
  `REQ`, its blobs to `GET`/`HEAD /<sha256>`, and its
  own `GET /list` answers, so the customer can clone, fetch and download
  everything and leave. Its stored bytes stay on the ledger. Taking content
  down is the denylist's job (§4); the blacklist removes nothing.
- **Both nodes, one restart each.** The list is read at start only, and it
  is in the fingerprint: put the same list on both nodes and restart both
  in one window. Until both run it, the node with the list refuses what its
  peer still takes, and the watchdog's `fingerprint-parity` fails as a
  same-version knob split. Lifting a block is the same: remove the npub on
  both nodes and restart both. A node that refused what its peer took asks
  the peer for everything again when it reconnects after its restart, so
  those events arrive then. List an account only once the pair is in step
  (the watchdog's `registration-parity` and `manifest-parity` checks pass).
  A write one node took before its restart that the other had not yet
  received is refused there for good, from sync as from a client: the two
  nodes then serve different data, and an offboard request that reached
  one node only leaves the other holding the registration and its key
  claims, so a later registration that reuses them is accepted on one node
  and refused on the other while the fingerprints still match.
- **Not exempt: the node's own key.** Upstream lets events signed by the
  node's own key pass its list; the GRASP-P writes have no such exception.
  Do not list a node's own key: upstream still takes the registrations and
  deletion requests it signs on that node while a peer with another key
  refuses them, which the fingerprint cannot show. The node warns at start
  (`NGIT_EVENT_BLACKLIST names this node's own key`).

### Wire-kind migration (`NGIT_GRASP_P_ACCEPT_LEGACY_WRAP_KIND`)

Stream wraps moved from kind 1059/21059 to 3359/23359. Rules:

- **Flip the knob on BOTH nodes in ONE maintenance window.** While the pair
  is split, wraps of a kind only one node admits are rejected on the other
  and never replicate. Sync is pull-only, so a wrap authored during the
  split never reaches the strict node — not late, *never*. There is no
  backfill for it.
- **Treat a `v2` → `v3` (or any label) upgrade the same way**: both sides in
  one window, because every node's fingerprint moves on the bump.
- **Stream-wrap divergence is NOT covered by the watchdog's data-parity
  checks.** `fingerprint-parity`, `registration-parity`, `manifest-parity`,
  and `blob-existence` compare registrations, 30641 editions
  and blobs — never wrap sets. `kinds-parity` tells you the nodes *disagree
  about which wrap kinds they admit*; nothing tells you which wraps actually
  diverged. Wrap-set reconciliation is not implemented.
- **Clients MUST emit exactly one wrap kind per logical wrap.** Server
  dual-accept exists so a client can SWITCH kinds, never so it can emit both.
  The quota charge is keyed on `event.id` and the kind is in the id preimage,
  so the same plaintext published as 1059 and 3359 is two ids: charged twice,
  stored twice — and wrap event bytes have no credit path (they are released
  only when the registration dies), so a dual-emitting client permanently
  doubles its `event_bytes` consumption.

---

## 3. Alert response playbook

One subsection per rule in [prometheus-alerts.yaml](prometheus-alerts.yaml);
anchors match the `runbook:` links in that file. Metrics are defined in
src/metrics/mod.rs (`ngit_private_*`) and src/sync/metrics.rs (`ngit_sync_*`).

### Where the scrape comes from

A node with GRASP-P enabled does **not** serve `/metrics` on its public
listener (`127.0.0.1:7334` above). That path is answered there like any
unknown path: the 404 page, or for an `OPTIONS` request the 204 every path
gets. The scrape counts private repositories, stored bytes, takedowns and
reports, and upstream's route answers anyone, with a wildcard CORS header.
The public repositories of the node are served by the same process, so their
`/metrics` is closed with it.

The scrape is served by a listener of its own, and only when
`NGIT_GRASP_P_METRICS_BIND` names a loopback address. Its path is `/metrics`
whatever `NGIT_BASE_PATH` is:

```bash
# unit env; an IP address on loopback, never a host name
NGIT_GRASP_P_METRICS_BIND=127.0.0.1:9464
systemctl restart ngit-grasp
journalctl -u ngit-grasp --since -1m | grep 'Private metrics endpoint listening on'
curl -s 127.0.0.1:9464/metrics | grep -c '^ngit_private_'
```

- **Unset is the default, and then nothing serves the scrape.** Metrics are
  still collected in memory, and the startup log says
  `Private metrics are collected and served nowhere`. Every rule in
  [prometheus-alerts.yaml](prometheus-alerts.yaml) reads this scrape, so
  without the endpoint none of them has a series to read. The one thing that
  then fires is the half of `NgitSyncPeerDisconnected` that reports a peer
  with no series. The watchdog (below) covers divergence between the two
  nodes and nothing else.
- **One startup line is upstream's and reads wrong here.** `Metrics enabled on
  /metrics endpoint` is still logged on a GRASP-P node. It means only that
  metrics are collected; where they are served is in the two lines named
  above.
- **Write the scrape target as the address, or as `localhost:<port>`.** The
  endpoint answers the scrape only when the request's `Host` header is a
  loopback address or `localhost`; under any other name for the host it
  answers 404. This keeps a web page that points its own name at 127.0.0.1
  from reading the scrape through a browser on the host. A connection that
  sends no request for 30 seconds is closed, so a collector reconnects
  between scrapes that are further apart.
- **A bad value stops the node at startup**, with an error that names the
  setting: an address that is not loopback, a host name, the setting
  together with `NGIT_METRICS_ENABLED=false`, or an address that is already
  in use. A port taken by another service is therefore a new way for a
  restart to fail; check `journalctl -u ngit-grasp` first when one does.
- **Loopback is not authentication.** Any process on the host can read the
  scrape. Run the Prometheus collector on the host, or in the node's own
  network namespace, and ship from there over a channel you control. Do not
  put a reverse proxy in front of the endpoint; the nginx example
  ([nginx-upload-zones.conf](nginx-upload-zones.conf)) answers `/metrics`
  with 404.
- **No relay is named by its URL.** The `relay` label holds `peer-1`,
  `peer-2`, … for the peers you configured and nothing for any other relay;
  see [Relays in the scrape](#relays-in-the-scrape).
- **`scripts/verify-deployment.sh`** (upstream's) requests `/metrics` on the
  public listener and fails against a GRASP-P node. Run it with
  `VERIFY_METRICS=false`, and check the endpoint with the `curl` above.

With GRASP-P disabled none of this applies: the setting is ignored and
`/metrics` is upstream's public route.

### Relays in the scrape

The scrape of a GRASP-P node names no relay by its URL. Upstream labels six
families of sync series with the URL of the relay each one is about
(`ngit_sync_relay_connected`, `ngit_sync_connection_attempts_total`,
`ngit_sync_relay_status`, `ngit_sync_relay_failures`, which the server never
sets, `ngit_sync_policy_refusals_total`, `ngit_sync_hydration_events_total`),
and does so for every relay the node dials. Most of those relays are named by
customers' repositories, and a scrape is shipped off the host into a
monitoring system. So the `relay` label is rewritten before a scrape is sent:

- **Your configured peers appear under an alias**: `peer-1`, `peer-2`, … The
  peers are the entries of `NGIT_GRASP_P_SYNC_PEER_URLS`, numbered in the
  order you wrote them
  ([Who a node replicates with](#who-a-node-replicates-with)).
  In the list, different spellings of one relay (`relay.example/`,
  `https://relay.example`, `wss://relay.example`) are one peer, and an
  entry that names the node itself takes no number. The relay in
  `NGIT_SYNC_BOOTSTRAP_RELAY_URL` has an alias only when the list names
  it, and then the number of its entry.
- **On a pair the alias is `peer-1` on both nodes.** `peer-1` on node A is
  node B, and `peer-1` on node B is node A. Prometheus's `instance` label
  says which node a series came from, and with that which node its
  `peer-1` is. Each node is scraped on a loopback address, so where both
  use the same port the default `instance` is the same on both: give each
  node its own `instance` (or another label) in its scrape configuration.
- **Every other relay has no series of its own in the scrape**: the relays
  that customers' repositories name, the user-index relays, the Sync+
  fallbacks, and a bootstrap relay the list does not name. The node serves
  its public repositories from the same process, so the relays those bring
  in are left out as well. All of them are still counted in three
  aggregates, which carry no relay label:
  `ngit_sync_relays_tracked_total`, `ngit_sync_relays_connected_total` and
  `ngit_sync_naughty_relays_total`. `ngit_sync_relays_dead_total` is in the
  scrape as well, but the server never updates it and it reads 0.
- **What you can no longer read from the metrics**, for every relay that is
  not a configured peer: whether it is connected, how its dials went, its
  health state, which subscriptions it refused and how many events it
  delivered. The sums over those relays go with them, because their samples
  are left out whole: `ngit_sync_connection_attempts_total`,
  `ngit_sync_policy_refusals_total` and `ngit_sync_hydration_events_total`
  count the peers only, and so does any count of `ngit_sync_relay_status` or
  `ngit_sync_relay_connected` by value. How many relays are degraded, dead,
  rate limited or policy limited is therefore no longer in the scrape. Two
  panels of upstream's Grafana dashboard
  (`docs/grafana/ngit-grasp-dashboard.json`), "Relay Health Distribution" and
  "Connection Attempts (5m)", are built on these series, and so are the
  queries and example alerts in `docs/explanation/monitoring.md` that count
  or sum them (the counts by `ngit_sync_relay_status`, the connection
  success rate, `SyncManyDegraded`): on a GRASP-P node they show the peers
  only. The node's log names every relay by its URL:
  `journalctl -u ngit-grasp | grep -i relay`.
- **Changing the list renumbers.** Insert, remove or reorder entries and the
  aliases move with them, so the history of `peer-1` then belongs to another
  relay. Add a new peer at the end of the list.

```bash
curl -s 127.0.0.1:9464/metrics | grep 'relay="'   # peer-N only, never a URL
```

The peer alert selects the alias (`relay=~"peer-.+"`); see
[Sync peer disconnected](#sync-peer-disconnected). With GRASP-P disabled the
scrape is upstream's, relay URLs included.

### Mirror lag

**Alert:** `NgitPrivateMirrorLag` — `ngit_private_mirror_lag_blobs > 0` for 15m.

What it means: blobs referenced by synced 30641 manifests are not yet in the
local blob store. The gauge is set by the repair scan and by nothing else, so
it is up to one scan interval (60 s) old. A brief non-zero value is normal
(fetches in flight or queued). A blob waiting out its retry backoff stays
counted: the backoff stops it being queued, not being counted.

Every failed fetch backs off (table under [Mirror failures](#mirror-failures)),
so a blob that keeps failing is tried rarely, about once per
`NGIT_GRASP_P_MIRROR_RETRY_MAX_SECS` in the end. This alert, not the failure
rate, is what shows such a blob.

Remediate:

```bash
curl -s 127.0.0.1:9464/metrics | grep '^ngit_private_mirror_failed_total'   # reason mix
journalctl -u ngit-grasp --since -1h | grep 'private mirror'                # full reason strings
curl -sI https://<peer-host>/<sha256>                                       # peer serves the blob?
```

Likely causes: no peer (`no_peer` — `NGIT_GRASP_P_MIRROR_PEER_URLS` unset,
or naming only this node; the node warned at startup); peer unreachable; SSRF
guard blocking the peer (`blocked` — non-https, or a name that resolves to an
internal address, at the check before the request or at the connection; keep
`NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS=false` in production; a name that
does not resolve at all counts as `network`); local
quota/budget refusal (`quota` — see [Ledger budget](#ledger-budget)); late
upload (`http_status: 404` on all peers — retried at the max interval). Peer
set: the entries of `NGIT_GRASP_P_MIRROR_PEER_URLS` minus the ones that name
this node (host, port, and mount path if it has one; `peer_servers_for` in
src/grasp_p/mirror.rs), the same for every account; a registration's
`server` tags are not consulted. There is no give-up.

**After the fix.** A blob is fetched again when its backoff ends, then the
repair scan (60 s tick) queues it: expect up to
`NGIT_GRASP_P_MIRROR_RETRY_MAX_SECS` plus 20% (about 73 min at the default)
for `404`, `blocked`,
`verify` and `too_large`, and for any blob that had failed many times.
Restarting the node clears every backoff, and the scan at boot queues every
missing blob at once: do that when the wait matters.

**One account far behind, the others fine.** That is the queue working.
Missing blobs wait in one queue per account (the tenant key), the accounts
are served in turn, and one account holds at most half of
`NGIT_GRASP_P_MIRROR_MAX_CONCURRENCY` (rounded down, at least one) fetches,
so one account whose blobs come slowly, or never, cannot take every fetch.
Two such accounts can hold all of them at the default of four; other
accounts then wait for fetches of theirs to end (one fetch lasts at most the
fetch timeout plus the blob's length at 256 KiB/s, per peer) and are served
in their turn. The warn lines name the alias; the registration names the
account. A blob that several accounts claim is fetched for the one with the
fewest missing blobs; if this node's own state refuses it for that account
(`quota`, a dead registration), the same attempt goes on for the next
claimant, up to four accounts. A node with
one busy account mirrors at half the configured concurrency: raise
`NGIT_GRASP_P_MIRROR_MAX_CONCURRENCY` if a healthy pair is too slow.

**Lag that drains slowly on a healthy pair.** Fetches started per minute
over all accounts are bounded by `NGIT_GRASP_P_MIRROR_MAX_ATTEMPTS_PER_MIN`
(default 600: a burst of 600, then 10 a second; `0` = unlimited). A push of
many thousands of small blobs is held to that rate. Nothing is dropped; raise
the setting if the replica must catch up faster. One account is also held
to 1024 blobs per repair scan (one scan a minute): its backlog holds 1024
and the next scan refills it, so no setting takes one account past about 17
blobs a second. There is no metric for
fetches held back by the budget: compare the rate of
`ngit_private_mirror_fetched_total` with the setting.

### Mirror failures

**Alert:** `NgitPrivateMirrorFailures` — per-`reason` rate > 0 for 10m.

The metric label is the failure-reason string up to the first colon
(`reason_label` in src/grasp_p/mirror.rs). One count is one blob that no peer
delivered in one attempt. Every class backs off; none is retried by every
scan. Classes (`classify_failure` and the table in the module documentation
of src/grasp_p/mirror.rs):

| `reason` label | retry | ends the attempt on the first peer | operator action |
| --- | --- | --- | --- |
| `no_peer` | backoff `base·2^(n-1)`, capped, ±20% jitter | (no peer to try) | the node has no blob peer: `NGIT_GRASP_P_MIRROR_PEER_URLS` is unset or names only this node (startup warning `the blob mirror has no peers`) — list the other node |
| `network` | same backoff | no | transport failure, no answer within `NGIT_GRASP_P_MIRROR_FETCH_TIMEOUT_SECS`, a body that stalled or outran its deadline, or a peer name that did not resolve or resolved to no address — DNS/TLS, peer down, egress firewall, a very slow link. The mirror uses no proxy from the environment: a peer reachable only through `HTTPS_PROXY` fails here |
| `http_status` | same backoff; `404` from every peer always waits `NGIT_GRASP_P_MIRROR_RETRY_MAX_SECS` | no | 5xx: peer erroring; 404 on all peers: late upload, benign, self-heals; other codes: proxy/edge oddity |
| `quota` | same backoff | yes | local ledger/budget full — [Ledger budget](#ledger-budget). Refused before any request is sent when the ledgers already show it |
| `store` / `reserve` / `sink` / `write` | same backoff | yes | this node's own state (registration gone, the repository no longer references the blob, denylisted mid-fetch, meta store or disk error) — read the full reason in the warn line |
| `blocked` | always the max interval | no | SSRF guard: peer is non-https, carries credentials, uses a local name, or resolves to a non-global address, either at the check before the request or at the connection (`blocked: <host> resolved to <address>, ...` in the warn line: the answer held an address the mirror may not reach, and the whole answer was refused) — fix the entry or the peer's DNS, or, for a pair on a private link, set `NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS=true` |
| `too_large` | always the max interval | no | the peer announced more than `NGIT_GRASP_P_MAX_BLOB_BYTES`, or sent more bytes than the fetch expected (the announced length, or the declared size when none was announced), or the state root declared more than the maximum — check that both nodes run the same maximum; a body longer than expected means the peer serves other bytes: investigate it |
| `verify` | always the max interval | no | peer served wrong bytes: they do not hash to the blob's name, or a body sent without a length ended short of the declared size — investigate the peer |

When a blob has several peers, the reason counted is one for the whole
attempt: a reason from this node's own state if there was one, otherwise the
one that retries soonest, whatever the order of the peers. `404` from one
peer and a timeout from another count as `network`.

A peer is believed about a blob's length up to
`NGIT_GRASP_P_MAX_BLOB_BYTES`: a blob whose state root declared the wrong
size is mirrored and charged at its real size, to every repository that
references it. The mirror stores a blob only for a repository that still
references it on this node and adds no reference of its own; a fetch that
outlived its reference fails as `store` and the blob is left to the
repositories that still want it. Every peer is one the operator listed.

Because every class backs off, a few blobs that stay stuck fail a few times
an hour and this alert goes quiet; [Mirror lag](#mirror-lag) keeps firing
for them. A steady failure rate means many blobs are failing, or new ones
keep failing: an unreachable or misconfigured peer, or a quota refusal on
this node. Backoff state is in memory; a restart resets every blob to the
base interval (the boot repair scan queues every missing blob anyway).

### Registration conflict

**Alert:** `NgitPrivateRegistrationConflict` — ANY increase of
`ngit_private_registration_conflicts_total{resolution}` (critical, no `for`).

What it means: the deterministic `(created_at, id)` merge resolved a
cross-tenant conflict in the last 5m — every conflict is either a
split-brain heal or an attempted alias/key squat (metric help text,
src/metrics/mod.rs:318–326), or, since seats settle, a split that does not
heal (step 6).

- `resolution="stored_evicted"` — a previously accepted registration lost
  its seat: key claims freed, record dropped, relay-DB coordinate pruned.
- `resolution="incoming_rejected"` — the arriving registration lost.

The merge order alone (lowest `created_at` wins) can be beaten by anyone
who dates a registration before the holder's, so it is not the whole rule.
**A seat whose first edition is more than an hour older than the node's
clock is never the loser**, neither of its alias nor of any of its keys: a
registration dated before it is refused with the ordinary conflict message,
and its warning carries `incumbent_settled=true`. Seats younger than that
merge by the order alone. The hour is a constant (`SEAT_SETTLE_SECS` in
src/grasp_p/registration.rs), the same on both nodes, and counted from the
first edition's `created_at`, not from when the node stored it.

Only senders the node admits can cause either. In `whitelist` mode a
registration from an account that is not listed is refused by the mode before
any conflict is looked at (§1, "What a registration is checked for"), so
this alert means that a listed account, or the peer's copy of one, is in
conflict; strangers probing aliases do not reach it. The one exception is
start-up, where a stored loser is still reported as `incoming_rejected`
whoever its author is.

Remediate:

```bash
journalctl -u ngit-grasp --since -24h | grep 'private registration conflict'
```

Log fields — incoming loss: `alias`, `loser_tenant`, `loser_created_at`,
`loser_event_id`, `incumbent_settled`; eviction: `alias`, `loser_tenant`,
`winner_tenant`, `winner_created_at`, `winner_event_id` (both warnings in
`apply`, src/grasp_p/registration.rs).

1. Determine the genuine tenant. Lowest `created_at` wins, ties break to the
   lowest event id, compared against the seat's FIRST-edition anchor
   (`incoming_wins_conflict`), unless the seat had settled (`challenge`, both
   in src/grasp_p/registration.rs).
2. Split-brain (both sides genuine, admitted under partition): if each
   registration reached the other node while the seat it challenges there
   was under an hour old, nothing to repair — the merge is deterministic and
   both nodes converge on the earlier registration. Confirm parity with the
   watchdog (§7) before the next sync round. If one arrived after that seat
   had settled (a partition of more than an hour, or a delivery that waited
   for the hourly full re-issue), each node keeps its own seat, at least one
   node's warning carries `incumbent_settled=true`, and the split does not
   heal: step 6.
3. Squat attempt: note the squatter's tenant npub; if it repeats, escalate
   via `NGIT_EVENT_BLACKLIST` (§4 step 8).
4. `incumbent_settled=true`: a registration dated before a seat over an hour
   old claimed its alias or one of its keys, and was refused; nothing
   changed, nothing to repair. By the order alone it would have won, so it is
   never an ordinary merge. Usually `loser_tenant` backdated a claim against
   an established repository (every member holds a repository's shared aux
   key): handle it as a squat attempt (step 3). Two other cases look the
   same. If `loser_tenant` already holds an older repository and this was a
   new edition of it claiming a key (a widen), the squatter is the holder of
   that key, and the client falls back to a minimal widen (§5). If the peer
   was cut off for over an hour, a genuine registration may have reached
   this node after another account took the seat here: check the other node
   (step 6). The field describes only the first conflict the registration
   lost, in the order the node checks them (the alias, then its w keys, then
   its aux keys, each in tag order): one that loses by the order at an
   earlier check reports `false` even when a later claim of it was backdated
   against a settled seat, and the sender chooses the order of its keys. An
   `incumbent_settled=false` loss by an account with a history of conflicts
   is therefore still worth the squat check of step 3.
5. `stored_evicted` and the winner is not the genuine tenant: a repository
   was taken in its first hour, which the rule still allows (a seat under an
   hour old merges by the order alone). The offender is `winner_tenant`;
   close the account (§4 step 8). The victim registers the repository again
   (a new alias).
6. The two nodes disagree about a seat (watchdog registration parity FAILs
   for the alias, alerts on both nodes): a challenger reached them on either
   side of the moment the seat settled, or reached one of them first while
   the other already held a seat that was settled on arrival, so the two
   nodes kept different registrations. A rebuilt or late-joining node that
   anchored a seat on a recent edition ends the same way (§10). This does not heal by itself, since each
   node now holds a settled seat. There is no repair tool until the
   offboarding work (issue 1); until then the victim registers the
   repository again and the offender's account is closed.

Dedup note: the `incoming_rejected` counter increments once per loser EVENT
id per hour per process (FG dedup, in-memory — src/grasp_p/registration.rs:224–281);
a restart can re-fire at most one alert per TTL window for an old loser.

### Ledger budget

**Alerts:** `NgitPrivateLedgerBudgetHigh` — `ngit_private_ledger_bytes{scope="global"} > 80%` of budget for 30m; `NgitPrivateLedgerBudgetCritical` — `> 95%` for 15m.

What it means: the whole-subsystem ledger (events + the charges for blobs)
is pressing on `NGIT_GRASP_P_GLOBAL_BUDGET_BYTES` (default
53687091200 = 50 GiB). The literal in the rule file must match the deployed
value (prometheus-alerts.yaml:70–75). At 100%, new admissions and uploads
start failing with `quota exceeded` / HTTP 507.

The ledger counts charges, not bytes on disk. Every repository that
references a stored blob is charged its full size, so a blob that three
repositories reference counts three times here and once on disk (decision
D4), and the global gauge can be above what the blob store holds. Stored
bytes nobody references any more stay charged to their last referrer, a
repository that died included, until GC removes them.

Remediate:

1. Verify GC is running: `journalctl -u ngit-grasp | grep 'private blob GC'`.
   Passes run every `NGIT_GRASP_P_GC_INTERVAL_SECS` (default 3600) and free
   grace-expired (default `NGIT_GRASP_P_GC_GRACE_SECS` = 86400) unreferenced
   blobs, releasing the charge their last referrer still pays (`purge_blob`
   in src/grasp_p/gc.rs).
2. Have tenants **Blossom-DELETE** unneeded blobs: DELETE releases the
   repository's charge at once while another repository references the
   blob; as the last referrer it pays until GC's `purge_blob` unlinks the
   bytes after grace — this is the tenant-driven refund path
   (`blob_delete` in src/grasp_p/mod.rs, `claims.rs`).
3. Review quotas (`NGIT_GRASP_P_QUOTA_TENANT_BYTES` default 1 GiB,
   `NGIT_GRASP_P_QUOTA_REPO_BYTES` default 512 MiB) or raise the budget on
   BOTH nodes — the quota/budget knobs feed the fingerprint (§2) — and
   update the alert literal in the rule file.

Known stranding: ledger bytes billed to a registration that died
(merge-evicted / vanished / kind-5) are NOT fully reclaimed — the
event-bytes columns of `t:` and `g:` ride server issue **!1**. Blob
charges are not stranded: a dying registration's charges on blobs another
alias references, or that nobody stored, are released at once, those on
stored bytes it was the last to reference go with the bytes at GC, and a
surviving alias pays only its own. Do not chase the event bytes to zero;
budget headroom is the remedy.

### Admission rejection spike

**Alert:** `NgitPrivateAdmissionRejectionSpike` — `sum(rate(ngit_private_events_rejected_total[10m])) > 1` for 15m.

Remediate:

```bash
curl -s 127.0.0.1:9464/metrics | grep '^ngit_private_events_rejected_total'
```

Read the `kind` label mix: a single kind dominating = one misbehaving
writer (e.g. 21059 spam from one key — also see [Rate limited](#rate-limited));
kinds `5` and `62` are deletion requests and vanishes the node refused
(§5: members cannot delete, nothing may name a state root or a wrap, a
request that names a registration has the offboard shape whoever sends it,
and an account's vanish names both nodes);
a broad mix = flood, or a policy misconfiguration rejecting legitimate
members (check `NGIT_GRASP_P_TENANT_WHITELIST`, §1). Threshold is a starting
default — tune to the instance baseline. Flood → tighten the nginx zones
(nginx-upload-zones.conf); misconfiguration → §1/§2.

### Rate limited

**Alert:** `NgitPrivateRateLimited` — `sum by (path) (increase(ngit_private_rate_limited_total[10m])) > 0` for 30m.

Per-path meaning — the in-server per-write-key token bucket
(labels set at src/nostr/builder.rs:787–858 and src/http/blossom.rs:167–172):

| `path` label | gated traffic |
| --- | --- |
| `state_root` | kind-30641 publishes |
| `wrap` | kind-1059 gift wraps (quota-charged) |
| `ewrap` | kind-21059 ephemeral wraps (never quota-charged — the bucket is their only cost) |
| `upload` | blob `PUT /upload` (answered HTTP 429 + `Retry-After`) |

Paired with [Admission rejection spike](#admission-rejection-spike) = active
flood — tighten the nginx zone (§6). Isolated = a legit client in a retry
loop — identify it via nginx access logs before relaxing limits. Defaults
are sized so honest cord-git flows, including widen→narrow rotations, never
trip (src/config.rs:743–756).

### Upload slots exhausted

**Alert:** `NgitPrivateUploadSlotsExhausted` —
`increase(ngit_private_upload_refused_total{reason="node_slots"}[10m]) > 0`
for 15m.

What it means: the node serves at most 64 client uploads at once, and
clients have been turned away repeatedly over fifteen minutes with `503`
because all 64 were taken. Nothing stored is at risk and replication does
not wait for a slot (the blob mirror takes none); it can still be refused
with `quota` if the node is within the bytes reserved by uploads in flight
(up to 64 times the largest blob, 16 GiB at the defaults) of its global
budget. Clients cannot push new content while it lasts, and the client does
not retry by itself.

What the four reasons of `ngit_private_upload_refused_total` mean, and what a
client saw:

| `reason` | answer | cause | what to do |
| --- | --- | --- | --- |
| `account_slots` | `429`, `Retry-After: 5`, `X-Reason: too many uploads in progress for this account; retry later` | one account has `NGIT_GRASP_P_MAX_UPLOADS_PER_TENANT` (default 8) uploads in flight | nothing if occasional. Steady from honest users: a team sharing one hosting key pushes in parallel; raise the setting. Steady with `idle_timeout` or `deadline`: one account is stalling uploads, and the cap is doing its job |
| `node_slots` | `503`, `Retry-After: 30`, `X-Reason: all upload slots are in use; retry later` | 64 client uploads in flight on the node | see below |
| `idle_timeout` | `408`, `Connection: close`, `X-Reason: upload timed out waiting for the request body` | an upload sent nothing for 30 seconds | nothing if occasional (a client that lost its network). Many at once: stalled connections, deliberate or a broken path in front of the node |
| `deadline` | the same `408` | an upload took longer than 30 seconds plus its declared length at `NGIT_GRASP_P_UPLOAD_MIN_BYTES_PER_SEC` (default 16384); also any upload that stalls within 30 seconds of its deadline, which includes every stalled upload smaller than one second's worth at the minimum rate (under 16 KiB at the default) | honest clients on slow lines: lower the setting, or `0` to keep only the idle cut-off. Otherwise: slow senders holding slots, cut as intended |

None of these is `507`. `507` means storage (repository, account or node) is
full, and is handled under [Ledger budget](#ledger-budget).

Remediate a full node:

```bash
curl -s 127.0.0.1:9464/metrics | grep '^ngit_private_upload_refused_total'
```

- `node_slots` with `account_slots` and the timeouts rising too: several
  accounts are holding slots with slow or stalled uploads. Each account is
  already capped, so it takes at least eight accounts to fill the node at
  the default. Lower `NGIT_GRASP_P_MAX_UPLOADS_PER_TENANT` so that it takes
  more of them, raise `NGIT_GRASP_P_UPLOAD_MIN_BYTES_PER_SEC` so that slow
  uploads are cut sooner, and find where they come from in the front
  proxy's access log (requests to `/upload` answered `408`, or closed
  without a status). The log gives client addresses, not accounts; if the
  senders are not customers, the admission mode is the real control (§1).
- `node_slots` alone, no timeouts: honest load, more than 64 uploads at the
  same moment. It clears by itself; clients that were refused run their
  push again. If it is regular, the request-rate zone on `/upload` at the
  front proxy (§6) spreads it.
- Both settings are node-local and outside `policy_fingerprint`: change them
  on one node and restart it, without touching its peer.

What does not help: raising the storage quotas (these answers are not about
storage), and `NGIT_GRASP_P_MIRROR_MAX_CONCURRENCY` (the mirror has its own
bound and is not counted here).

The client uploads with a fixed 300 second timeout of its own and does not
retry a `429`, `503` or `408`; the user sees the push fail with the status
and the reason, and runs it again. A client that was still sending when the
node answered may report a reset connection in place of the status, because
the node closes the connection without reading the rest of the body.

### Hold saturated

**Alert:** `NgitPrivateHoldSaturated` —
`sum by (reason) (increase(ngit_private_hold_dropped_total{reason=~"count_cap|byte_budget|skip_set_full"}[10m])) > 0`
for 15m.

What it means: a state root or a stream wrap can reach a node before the
registration it depends on. The node rejects it, keeps it in memory, and
tries it again when the registration is accepted; that is how a pair
converges within seconds when events cross on the wire. The hold is
bounded, and this alert says a bound has been in force for 15 minutes:

| `reason` | bound | effect |
| --- | --- | --- |
| `count_cap` | 4096 held events, of which at most 1024 registrations | the new event is dropped and can be fetched again |
| `byte_budget` | 32 MiB of held events, or 64 x `NGIT_GRASP_P_MAX_EVENT_BYTES` when that is more; registrations may use a quarter. An event is charged its serialized size plus the fixed memory cost of each tag and tag element, so one built from many tiny tags is charged for the memory it takes | the same |
| `skip_set_full` | 65,536 remembered event ids, 4,096 of them reserved for held events, so 61,440 ids of events that were not kept | the id of a rejected event is not remembered, so the node validates it again when a peer offers it again |
| `not_holdable` | none: the rejection is one no registration can cure (quota, size, shape, date, a store fault) | not alerted on; a synced event's id is remembered, a client's event leaves nothing |

Nothing a peer holds is lost for good. A dropped event that came from the
peer is still there and is fetched again when the registration it was
waiting for is accepted (that changes the sync filters and triggers a
re-issue), or at the latest with the next full re-issue
(`NGIT_GRASP_P_FULL_REISSUE_INTERVAL_SECS`, default one hour). A dropped
event that came from a client is not kept anywhere: the client was told it
was rejected and must publish again. The visible effect on replication is
that pushes which arrive out of order can take up to the full re-issue
interval to appear on the second node, where they normally take seconds. Held
events expire after `NGIT_REJECTED_HOT_CACHE_DURATION_SECS` (default 120 s),
so the hold empties by itself once the cause stops. There is no setting
for the bounds; the byte budget follows `NGIT_GRASP_P_MAX_EVENT_BYTES`.

Remediate:

```bash
curl -s 127.0.0.1:9464/metrics | grep -E '^ngit_private_(hold_dropped|events_rejected|rate_limited)_total'
```

- Rejections rising with it (see [Admission rejection spike](#admission-rejection-spike)):
  someone is sending events for aliases or keys that are not registered.
  From a client, the per-write-key bucket does not stop it, because each
  unregistered key has a bucket of its own; tighten the connection and
  request limits at the front proxy (§6). From the sync side, the events
  come through the peer: look at the peer's own rejection counters and its
  clients.
- No rejection spike, and the peer was down or has just been restored: a
  backlog is arriving out of order. It clears with the next full
  re-issue; no action.
- `skip_set_full` alone: many distinct rejected events are being offered
  again and again. Find what the peer holds that this node refuses
  (compare `policy_fingerprint`, §2: a pair that disagrees on policy
  produces exactly this).

### Full re-issue silent

**Alert:** `NgitPrivateFullReissueSilent` —
`increase(ngit_private_full_reissue_total[2h]) == 0 and
increase(ngit_private_full_reissue_skipped_total[2h]) == 0` for 30m.

What it means: the Phase-4b B1 self-heal timer
(`NGIT_GRASP_P_FULL_REISSUE_INTERVAL_SECS`, default 3600, ±10% jitter —
src/sync/mod.rs:524–555) has not completed a round in over 2× the default
interval. FS-8 split the counter (src/metrics/mod.rs:353–380): delivered
rounds count into `ngit_private_full_reissue_total`, rounds where no
configured peer was live or every live peer was skipped (rate-limit
cooldown / the FS-3 `NGIT_GRASP_P_REISSUE_MIN_INTERVAL_SECS` floor) count
into `ngit_private_full_reissue_skipped_total` — so BOTH must be flat
before the timer is called dead. A re-issue goes to the configured peers
only. Live delivery still works, but redelivery-dependent
gaps — expired rejected-hot-cache entries, cadence-limited 30640
replacements that left the server-side hold unaccepted (expiry/overflow;
their PRIMARY heal is the hold-and-retry drain, this timer only the
backstop), negentropy blind spots — stop healing, so the pair drifts
slowly until the next reconnect or daily fresh sync.

Remediate: `journalctl -u ngit-grasp | grep 'full re-issue'` for the timer
start line; confirm `NGIT_GRASP_P_FULL_REISSUE_INTERVAL_SECS` is not `0`
(rule is inert by design when disabled — drop it from your ruleset then);
otherwise the sync task is wedged — check for a stalled peer connection
holding the sync-manager lock and restart the process as the last resort.
If the delivered counter is flat but `..._skipped_total` keeps rising, the
timer is alive and the peer is chronically skipped or down: check the FS-3
floor value, peer health, and that `NGIT_GRASP_P_SYNC_PEER_URLS` names the
peer. Caveat: the series appear only at their FIRST increment, so this
rule cannot detect a timer that never started since boot — add the
`absent()` variant from the rule-file comment if you want boot-silence
detection.

### Denylist entries dropped

**Alert:** `NgitPrivateDenylistEntriesDropped` —
`delta(ngit_private_denylist_entries[1h]) < 0` for 5m.

What it means: the live denylist shrank (gauge set at boot and on every
reload swap — `PRIVATE_DENYLIST_ENTRIES` in src/metrics/mod.rs). A file that
disappears, cannot be read, or had entries and reads back empty keeps its
entries (§9), so a drop means a readable file now lists
fewer hashes: an edit, intended or not, or a restart that came up with a
file missing (a file missing at boot is tolerated and counts as empty).
Already-purged bytes stay gone either way; any taken-down blob still on
disk becomes readable again at once.

Remediate: confirm whether the edit was intended (change management). If
not: restore the files, watch the gauge recover on the next reload, and
re-check mounts/permissions, above all after a restart. Un-blocked blobs
that a peer still holds will re-mirror; the §4 takedown procedure
re-applies if the purge must be re-driven. A file that went missing while
the node ran shows as the error `has disappeared; keeping last-known
entries`, not as a drop.

### Denylist purged

**Alert:** `NgitPrivateDenylistPurged` —
`increase(ngit_private_denylist_purged_total[10m]) > 0` (informational, no
`for`).

What it means: a takedown action executed — reload purge-on-add or the GC
denylist sweep freed claims, released ledger charges, and unlinked bytes
(metric: src/metrics/mod.rs:380–393). This is the expected signature of an
INTENDED takedown landing; the alert exists so an UNEXPECTED purge is
caught immediately.

Remediate: match the increase against your change log and the journal
(`denylist purge-on-add` / `GC purged denylisted`, §9 cheatsheet). If the
purge was intended, nothing to do — this is the confirmation signal. If
not, audit who/what wrote the denylist files (§4 step 3), and note the
removal semantics: purged bytes are not recoverable server-side; clients
must re-upload (§4 step 7).

### Report events

**Alert:** `NgitPrivateReportEvents` —
`increase(ngit_private_report_events_total[1h]) > 0` (no `for`).

What it means: kind-1984 (NIP-56 report) events that point at
private-repository content are arriving (`ngit_private_report_events_total`,
`record_private_report_event` in src/metrics/mod.rs). Such a report names a
registration, a state root or a wrap by coordinate or id, a blob this node
holds or has on its denylist, a hash beside a `server` tag naming either node
of the pair (this node, or a peer listed in `NGIT_GRASP_P_SYNC_PEER_URLS` or
`NGIT_GRASP_P_MIRROR_PEER_URLS`), or a write or aux key in `p`
(src/grasp_p/reports.rs). It is refused, never stored or served, so a key or
an accusation in it is not published beside the customer's repository; the
reporter is told `reports about private repositories are not stored on this
service`. The intake logs the event id, reporter, and up to 16 sha256-looking
tag values, the `x` values first and in lower case — never the content — once
per report, however often sync fetches it again, and v1 takes NO automatic
action, so the alert IS the page to work §4. Reports on public content are
upstream's, stored or refused as on any node, and are neither logged nor
counted here.

Remediate: `journalctl -u ngit-grasp | grep 'NIP-56 report event received'`
for the intake lines, then work the §4 takedown workflow: the hashes in the
line are the evidence, and the blob key comes from the reporter by direct
mail (§4 step 1). A report without the blob key is not actionable (§4 ToS
posture).

### Sync peer disconnected

**Alert:** `NgitSyncPeerDisconnected` —
`(ngit_sync_relay_connected{relay=~"peer-.+"} < 2) * 0 or absent(ngit_sync_relay_connected{relay="peer-1"})`
for 10m. The gauge is 0 for a disconnected relay and 1 while a dial runs;
both count, because a peer that is down is dialled every 5 minutes and a
dial against a silent host takes several seconds.

The alert names the peer by its alias, never by its URL
([Relays in the scrape](#relays-in-the-scrape)): on a pair `peer-1` is the
other node. With value 0 the alert's `instance` label is the node that
reports; with value 1 the alert has the `relay` label and no `instance`,
unless you gave that half an `instance` matcher (below). For a two-node
GRASP-P pair this halts 30640/30641 sync and grows the mirror backlog. The
alert's value, which its description starts with, says which half fired:

- **Value 0: the peer is tracked and has no session** (it is disconnected,
  or being dialled). Remediate: peer process
  (`systemctl status ngit-grasp` on the peer), DNS/TLS
  (`curl -sI https://<peer>/`), egress firewall, and the relay's last error
  in this node's log, which names it by URL
  (`journalctl -u ngit-grasp | grep '<peer host>'`). A DNS or certificate
  failure also puts the relay on the naughty list: the log line
  `added to naughty list` names it, and `ngit_sync_naughty_relays_total`
  counts it by category. For a configured peer that entry does not stop
  the dials (below); it stays for twelve hours, also after the peer is back.
- **Value 1: the scrape has no `peer-1` series.** The node does not track the
  peer, or is not scraped at all. The node's peers are the relays in
  `NGIT_GRASP_P_SYNC_PEER_URLS`: verify that the list names the peer,
  correctly, on both nodes. `NGIT_SYNC_BOOTSTRAP_RELAY_URL` alone does not
  make a peer ([Who a node replicates with](#who-a-node-replicates-with)).
  `Skipping private-repo peer relay` or
  `Rejecting event-directed sync relay target` in the log means the node
  refused the address of a listed peer: it is not `wss://`, it is not a
  public address, or its name did not resolve when the node tried. The node
  tries to register it again every minute. For a pair on a private link see
  [A pair on a private network](#a-pair-on-a-private-network). Then check
  that the collector reaches the endpoint
  ([Where the scrape comes from](#where-the-scrape-comes-from)). A node with
  no peer configured, or with GRASP-P off, never has the series: remove the
  rule there.

**What the node does by itself.** A configured peer is never dropped: when
its session ends or a dial fails it stays tracked and disconnected (value 0,
never value 1), and the node dials it again without a restart.

- After a session ends or a dial fails, the node redials with a wait that
  doubles from `NGIT_SYNC_BASE_BACKOFF_SECS` (5 seconds): 5, 10, 20, 40, 80,
  160 seconds.
- From there on, and from the first failure for a peer on the naughty list
  (a DNS, certificate or protocol failure), it dials once every 5 minutes
  for as long as the peer is down. The log line is
  `Redialling private-repo peer relay`. Neither the one-hour backoff, nor
  the one dial a day after 24 hours of failures, nor the twelve hours of
  the naughty list apply to a configured peer.
- So a peer that comes back is connected again within about 5 minutes at
  the latest, plus the dial itself; usually sooner. The alert waits 10
  minutes, so it clears by itself after an outage that has ended, and one
  that keeps firing means the peer still cannot be reached.
- After the reconnect the node catches up by itself; nothing has to be
  triggered.

The address of a peer that only the list names is checked again before
every dial, unless the link is declared private: a peer whose name stops
resolving, or resolves to an address the node may not dial, fails its dials
and is retried in the same way. The bootstrap relay's address is never
checked.

The half that fires on a missing series looks at everything the evaluating
Prometheus holds. Where one server evaluates the rules for both nodes, repeat
that half per node with an `instance` matcher, as the comment on the rule
says; a node with more than one peer repeats the half per alias.

There is no alert on a peer's consecutive failures. The gauge for it,
`ngit_sync_relay_failures`, is registered by the server and never set, so it
is in no scrape, and the former `NgitSyncPeerFailuresGrowing` could not
fire. A peer whose dials keep failing is disconnected and raises this alert;
its health is in `ngit_sync_relay_status{relay="peer-1"}` (1 healthy,
2 disconnected, 3 degraded, 4 dead, 5 rate limited, 6 policy limited).

### Sync all disconnected

**Alert:** `NgitSyncAllPeersDisconnected` — all tracked peers disconnected
for 10m (critical).

Almost always a LOCAL outage (network, DNS, sync subsystem), not a mass peer
failure. Remediate: local egress, resolver, and sync logs:
`journalctl -u ngit-grasp | grep -i sync`.

### Watchdog

**Alerts:** `NgitPrivateWatchdogFailing` / `NgitPrivateWatchdogStale` —
not scrapeable directly; bridge the watchdog's exit status per the
blackbox/textfile patterns in prometheus-alerts.yaml:184–225.

- Exit 1 (divergence): split-brain or operator-side withholding. Read the
  FAIL lines (`journalctl -u ngit-private-watchdog.service`), then work §7's
  failure taxonomy **before mutating either node** — see the T1 threat
  model (docs/grasp-p/plan-v2-fix-log.md:277–281).
- Exit 2 (operational error): a node unreachable, timeout, or unexpected
  response — connectivity, never divergence.
- Stale: the timer/cron died — restart it (watchdog.md §systemd).

**Coverage limit — stream wraps.** The data-parity checks
(`registration-parity`, `manifest-parity`, `blob-existence`)
compare kind-30640 registrations, kind-30641 editions and blobs. **No check
compares stream-wrap sets**, so a wrap-set divergence is invisible as a data
class. `kinds-parity` reports only that the two nodes disagree about which
wrap KINDS they admit (§2) — a mismatch there means wraps have almost
certainly diverged and there is no backfill for them; a match there does not
prove the wrap sets agree.

---

## 4. Takedown workflow (NORMATIVE)

**ToS posture.** The service is a content-blind host: blobs are client-side
encrypted under fresh random keys (cord-git `crypto::encrypt_blob_random`)
and the server verifies only outer signatures
(docs/grasp-p/phase1-design.md:12). **Proactive scanning is structurally
impossible** — the operator cannot see content. A hash-addressed takedown
IS honored, and the ToS must say so: actionable reports MUST include the
blob key (and its sha256), or the operator cannot verify and cannot act
(plan T7, docs/grasp-p/plan-v2-fix-log.md:308–311). The ToS and the report
page must also say HOW: the blob's sha256 in an `x` tag of the report (or in
the mail), and the blob key **only by direct mail to the operator, never in
an event** — a Nostr event is public, and anything in one can be copied to
other relays whatever this node does with it.

Procedure — verify-then-denylist:

1. **Accept evidence.** A report must carry (a) the blob sha256
   (hash-addressed) and (b) the blob key. The key arrives by direct operator
   mail only. The sha256 arrives in that mail, or in a kind-1984 NIP-56
   report with the hash in an `x` tag (beside a `server` tag naming the
   node, when the node does not hold the blob yet). A report that points at
   private-repository content is refused and never stored (D10), so it
   publishes nothing; the 1984 intake logs its event id, the reporter, and
   up to 16 sha256-looking tag values (the `x` values first, in lower case),
   and the event CONTENT is never logged
   (`log_report` in src/grasp_p/admission.rs, called from
   src/grasp_p/reports.rs). Metric: `ngit_private_report_events_total`,
   which counts those reports only. v1 takes NO automatic action — a rising
   count is a page to work this runbook. Reports on public content are
   upstream's and do not reach this intake.
2. **Operator decrypts to CONFIRM.** Fetch the blob (`GET /<sha256>` —
   public by design), decrypt with the supplied key, verify the sha256 of
   the plaintext. **This step creates actual knowledge of the content — and
   with it jurisdiction-specific duties (reporting obligations, liability
   timelines). Decrypt only to confirm an actionable report, never
   casually.**
3. **Denylist.** Append the sha256 (lowercase hex, one per line) to this
   node's jurisdiction denylist file. `NGIT_GRASP_P_DENYLIST_PATH` is a
   comma-separated list of files — mount per-node / per-jurisdiction lists
   (src/config.rs:682–687).
4. **Enforcement lands within one reload interval** (default 60s,
   `NGIT_GRASP_P_DENYLIST_RELOAD_SECS`): the reload swaps the live set, then
   purge-on-add immediately frees every claim (releasing ledger charges),
   unlinks the bytes, and GET/HEAD + upload preflight start answering 451
   (src/grasp_p/denylist.rs:150–198, src/http/blossom.rs:218–220,
   src/grasp_p/mod.rs:924–925). The mirror never re-fetches it — every
   mirror step (enqueue, scan, dispatch, fetch) consults `is_denylisted` — and the purged blob drops out
   of `ngit_private_mirror_lag_blobs`.

   **HTTP caches.** The node serves a blob with `Cache-Control: no-cache`
   and its sha256 as `ETag`: a browser or proxy may keep a copy but has to
   ask the node before each reuse, and for a denylisted blob that question
   is answered 451, never 304. So a takedown reaches every cache that
   honours those headers at its next request. Any reverse proxy or CDN put
   in front of the node MUST honour the origin's cache headers on the blob
   paths (`/<sha256>`): no forced TTL, no "cache everything", no serving
   stale content when the origin answers an error. If one is configured to
   override them anyway, purge the blob's URL there as part of every
   takedown, on both nodes of a pair. The 451 and the 404 are sent
   `no-store` and must not be cached either.
5. **GC sweep is the durable backstop**: every GC pass purges denylisted
   blobs bypassing both the grace period and the unreferenced requirement —
   even if the reload raced a claim that appeared later
   (src/grasp_p/gc.rs:106–157). Bound: `NGIT_GRASP_P_GC_INTERVAL_SECS`
   (default 3600).
6. **Verify.**

   ```bash
   curl -sI https://<node>/<sha256>     # expect HTTP 451
   curl -s 127.0.0.1:9464/metrics | grep -E 'ngit_private_denylist_(entries|purged_total)'
   journalctl -u ngit-grasp --since -10m | grep -E 'denylist purge-on-add|GC purged denylisted'
   ```

   On a two-node pair in different jurisdictions the lists legitimately
   differ — the denylist is NOT part of the `policy_fingerprint`
   (`policy_preimage` in src/grasp_p/mod.rs).
7. **Removal semantics.** Dropping the hash from the files unblocks reads on
   the next swap; bytes already purged stay gone — a client re-upload is
   required (src/grasp_p/denylist.rs:29–31, 174–175). Re-upload is possible
   (the sha is no longer blocked); the old copy is not recoverable.
8. **Repeat infringers.** Escalate to the relay's generic event blacklist:
   `NGIT_EVENT_BLACKLIST` — comma-separated npubs; ALL events from those
   authors are rejected before kind dispatch (`check_event_blacklist` in
   src/nostr/builder.rs). Relay-wide, not private-only; requires a restart
   (no reload path, §1). For a private-repository account, list its account
   npub: every write under its registrations is then refused, by any of its
   keys, on both nodes, while its data stays readable (§2, "The event
   blacklist"). The list is in the fingerprint: set it on both nodes and
   restart both.

---

## 5. Client-visible rejection strings (contract — do not change)

cord-git pattern-matches on these strings (verified:
cord-core/src/repo.rs:811 matches substring `unregistered` → widen;
repo.rs:1073 matches `write key already registered` → squat-tolerant minimal
widen; anything else is fatal with the server message). **Changing any of
these strings breaks the client.** WS rejections are NIP-20 OK false
rendered `{prefix}: {message}` (src/nostr/policy/result.rs:11–13).

| wire message | path | class | client behavior |
| --- | --- | --- | --- |
| `restricted: unregistered key` | 3359/23359 (and 1059/21059 while dual-accept is on) outer author not in w∪s of a live registration (src/nostr/builder.rs:865, 886) | genuine | widens (adds the key to the 30640) and retries |
| `restricted: legacy stream-wrap kind is not accepted on this node` | kind 1059/21059 submitted while `NGIT_GRASP_P_ACCEPT_LEGACY_WRAP_KIND=false` on a node with private repos enabled (src/nostr/builder.rs:889–910) | genuine | migrate the client to 3359/23359 — retrying and widening are both useless; deliberately does NOT contain `unregistered` |
| `restricted: unregistered alias` | 30641 for a dead/unknown alias (src/grasp_p/state_root.rs:143; renamed from `alias is not registered` in FS-7 — the cord-git widen trigger is the `unregistered` substring) | genuine | widens/re-registers and retries (recoverable; the old spelling was fatal client-side) |
| `restricted: registration changed; retry` | stream-wrap charge-txn identity race (src/grasp_p/mod.rs:856–867) | transient | retry succeeds; deliberately does NOT contain `unregistered` |
| `restricted: alias registration changed; retry` | 30641 txn identity race (src/grasp_p/state_root.rs:238–244) | transient | retry succeeds |
| `restricted: rate-limited; retry later` | 30641/wrap/ephemeral-wrap write bucket empty (src/nostr/builder.rs:815, 848, 879) | transient | back off, retry |
| `restricted: replacement rate-limited; retry later` | same-tenant 30640 replacement cadence (src/grasp_p/registration.rs:591–598) | transient | retry later; the server ALSO holds the newest rejected edition and retries it after bucket refill (below), so the client may never need to |
| `restricted: quota exceeded` | registration/wrap over quota (src/grasp_p/registration.rs:552, src/grasp_p/mod.rs:852) | genuine | free space or ask operator for quota |
| `restricted: tenant is not on the registration whitelist` | whitelist mode, for an alias the sender does not hold; decided before any proof is verified and before any conflict (`new_seat_admission` in src/grasp_p/registration.rs) | genuine | ask operator to admit the npub |
| `restricted: registration requires N bits of NIP-13 proof of work` | pow mode, same place | genuine | re-mine the 30640 |
| `restricted: alias already registered` / `restricted: write key already registered` | §3.2 conflict-merge loss, for a sender the mode admits: the holder's first edition is earlier, or the holder's seat is more than an hour old (`apply` in src/grasp_p/registration.rs) | genuine | pick another alias / minimal widen without the squatted keys |
| `invalid: registration relays tag must list this node` / `invalid: registration server tag must list this node` | no value of the tag names this node: its host and port, and its mount path when it runs under `NGIT_BASE_PATH` (`parse_shape`) | genuine | publish the registration with this node's full URL in both tags |
| `restricted: a repository's write and aux keys cannot delete; the account key deletes the whole repository` | kind 5 (except an offboard request: one with `["k","30640"]` or a 30640 coordinate, judged by the rows below) or kind 62 from a write or aux key of a registration on this node (`src/grasp_p/offboard.rs`) | genuine | none: members cannot delete from the server; the account deletes the repository |
| `restricted: state roots and stream wraps are removed only with their repository's registration` | kind 5 naming a 30641 or a stream wrap this node holds by `e` id, or any by an `a` coordinate of those kinds | genuine | never send it; the server removes them with the registration |
| `restricted: a registration can be deleted only by the account key that signed it` | kind 5 naming another pubkey's 30640, by coordinate or by `e` id | genuine | none |
| `restricted: a registration is deleted by its coordinate (a tag), not by its event id alone` | kind 5 naming a stored 30640 by `e` id without its coordinate, or carrying `["k","30640"]` with no coordinate of the signer's own 30640 | genuine | send the coordinate `30640:<account>:<alias>` |
| `invalid: deleting a registration requires a k tag of 30640` / `invalid: a registration coordinate must be written 30640:<pubkey>:<alias>` | offboard request without `["k","30640"]`, or with the kind spelled otherwise (`030640`) | genuine | fix the request; the k tag is what carries it to the other node |
| `restricted: a key that signed state roots or stream wraps cannot vanish; the account key deletes each repository by its registration` | kind 62 from a key with stored 30641s or wraps | genuine | offboard each repository by kind 5 |
| `invalid: an offboard request names nothing but its signer's registration coordinates and the k tag 30640` | a kind 5 with `["k","30640"]` (that text exactly) or a 30640 coordinate (its kind read as a number, so `030640:` counts) that also names a coordinate of another kind or a malformed one, or carries another `k` value (`030640` included), from any signer (D15-6) | genuine, final | send the offboard request alone; delete public events in a separate request without the k tag |
| `invalid: an offboard request names its registrations by coordinate only, with no event id` | an offboard request with any `e` tag, its own registration's id included: whether an id is one of the account's editions depends on which editions each node holds, so the two nodes would answer differently | genuine, final | send the coordinates alone |
| `invalid: an offboard request names more registrations than an account may hold` | an offboard request with more `a` tags than `NGIT_GRASP_P_MAX_ALIASES_PER_TENANT`, repeats counted | genuine, final | split it |
| `invalid: an offboard request or an account's vanish exceeds the private event size limit` | an offboard request, or the vanish of a key that holds registrations here, over `NGIT_GRASP_P_MAX_EVENT_BYTES` | genuine, final | send it with no content beyond what the request needs |
| `invalid: offboard requests are taken only from accounts this node admits` | whitelist mode: an offboard request from a key that is neither on `NGIT_GRASP_P_TENANT_WHITELIST` nor holds a registration here | genuine, final | none: such a key holds no repository on either node |
| `invalid: an account's vanish names ALL_RELAYS or every node its registrations list` | kind 62 from a key that holds live registrations here, with neither `["relay","ALL_RELAYS"]` nor a `relay` tag for this node, for each configured sync peer and for every node its registrations' `server` tags list, each value as written | genuine, final | send `["relay","ALL_RELAYS"]` |
| `blocked: Account <npub> is blacklisted` | 30641 or stream wrap (stored or ephemeral) made under a registration whose account is on `NGIT_EVENT_BLACKLIST` (`grasp_p::blacklist`), from a client or from sync | operator block | none — the account is frozen; reads still work (§2, "The event blacklist"); deliberately does NOT contain `unregistered` |
| `blocked: Event author <npub> is blacklisted` | any event signed by a key on `NGIT_EVENT_BLACKLIST` (upstream's check; the account's own registrations and deletions included) | operator block | none |
| `invalid: registrations and stream wraps carry no e, E, q, a or A tag` / `invalid: a state root carries one a tag and no e, E, q or A tag` | a 30640 or a stream wrap (any kind) with a reference tag; a 30641 with one beside its own `a`, or a second `a` (`attachment::reference_tag_refusal`) | genuine, final | none: cord-git sends no such tag; decided before the key lookup, so never held |
| `invalid: private repository events cannot carry the t tag grasp-audit-test-event` | any GRASP-P event with upstream's audit hashtag, which upstream's audit cleanup would delete past every hook | genuine, final | none |
| `restricted: events that reference private repositories are not stored on this service` | an event of any other kind but 5, 62 and 1984 with a coordinate of a GRASP-P kind, or the id of a stored GRASP-P event, in an `a`, `A`, `q`, `e` or `E` tag, whoever signs it (`attachment::judge`) | genuine | none: drop the reference; deliberately names no target and does NOT contain `unregistered` |
| `restricted: reports about private repositories are not stored on this service` | a kind 1984 that points at private-repository content (§3 Report events) | genuine | send the blob key by mail to the operator (§4 step 1) |
| `invalid: event carries too many references to check` | more than 2048 distinct `e`/`E`/`q` ids, or a report with more than 2048 distinct 64-hex values or, beside an `x` tag, `server` values | genuine | split the event |
| HTTP 403 + `X-Reason: Account <npub> is blacklisted` (or `Event author <npub> is blacklisted`) | `HEAD /upload`, `PUT /upload`, `DELETE /<sha256>` under a registration of a listed account, or signed by a listed key | operator block | none — `GET`/`HEAD /<sha256>` and `GET /list` still answer |
| HTTP 429 + `Retry-After: N` | `PUT /upload` write bucket empty (src/http/blossom.rs:167–172, 40–42) | transient | wait N seconds |
| HTTP 451 + `X-Reason: content unavailable for legal reasons` | GET/HEAD/upload-preflight/commit on a denylisted sha (src/grasp_p/mod.rs:175, 189) | takedown | none — operator action only |
| HTTP 507 + `X-Reason: quota exceeded` | blob routes over quota (src/grasp_p/mod.rs:176, 190) | genuine | DELETE blobs or ask for quota |
| HTTP 401 + `WWW-Authenticate: Nostr` | blob routes: missing, malformed, expired or mis-addressed kind-24242 authorization. Its `created_at` must be at most 1 hour old and at most 15 minutes ahead of the node's clock; a `server` tag, when present, must name this node (`NGIT_DOMAIN`), and `GET /list` requires one (src/grasp_p/blossom_auth.rs) | genuine | sign a fresh authorization; check the client's clock, and the node's own (a node more than 15 minutes slow or an hour fast refuses every authorization; keep both nodes of a pair time-synchronised) |
| HTTP 500 + `X-Reason: internal error` | any blob route; the client is never told more | node fault | read the node's log for `blob route internal error: <detail>` at the same time |

An event refused with `unregistered alias`, `unregistered key`, `event
author is not a registered write key for this alias`, `state root a tag
does not match the live registration` or one of the two `registration
changed; retry` messages may be accepted later without the client
sending it again: the relay keeps such an event for
`NGIT_REJECTED_HOT_CACHE_DURATION_SECS` and retries it when the
registration it was waiting for arrives. This is a best effort within the
hold's bounds (§3 Hold saturated), so a client must still be ready to
publish again. Apart from the cadence case below, an event refused for
any other reason is not kept. An
event larger than `NGIT_GRASP_P_MAX_EVENT_BYTES` is refused with
`restricted: event exceeds private repo size limit` before anything else
is looked at.

A cadence-rejected replacement (`replacement rate-limited; retry later`)
may be accepted LATER without the client republishing anything: the relay
holds the newest rejected edition per `(tenant, alias)` and re-offers it
after the cadence bucket refills (FS-2/R2-1, src/sync/private_index.rs,
src/sync/mod.rs:2388–2442) — reject-then-silent-accept is NIP-20-normal
for this path, not a bug. The hourly full re-issue is only the backstop
healer (hold expiry/overflow), not the convergence mechanism.

The retirement rejection (`legacy stream-wrap kind is not accepted on this
node`) is the opposite shape: GENUINE and permanent for as long as the knob
is off. It fires on every kind-1059/21059 submission once
`NGIT_GRASP_P_ACCEPT_LEGACY_WRAP_KIND=false` on a node with private repos
enabled (src/nostr/builder.rs:889–910); nodes with private repos disabled
never reach that arm and keep vanilla 1059 handling. Neither a retry nor a
30640 widen changes the verdict — the ONLY resolution is a client that emits
3359/23359 (§2 "Wire-kind migration"), so operator-side this string means
"finish the client migration", never "server fault". It deliberately does
NOT contain the substring `unregistered`: cord-git treats ANY message
containing `unregistered` as its widenable case
(cord-core/src/repo.rs:811), and widening a key cannot help against a
retired KIND — the client would republish its 30640 and retry the same dead
kind forever.

The other refusals of a malformed registration are stable too, all with
the `invalid:` prefix: `registration must carry a d tag`, `registration d tag
must be exactly 32 lowercase hex chars`, `registration must carry at least
one w (write key) tag`, `registration exceeds the N key limit`, `w/aux keys
must be 64 lowercase hex chars`, `registration lists the same key more than
once`, `w/aux keys must carry a proof-of-possession signature`, `w/aux key
is not a valid x-only pubkey`, `w/aux key proof-of-possession signature is
malformed` and `w/aux key proof-of-possession signature is invalid`. A
registration with more than one fault gets the first that applies in the
order of §1 ("What a registration is checked for"): shape before admission,
admission before proofs, proofs before conflicts. A client must not conclude
from a whitelist or key-limit refusal that its proofs were accepted.

Also stable: `restricted: event exceeds private repo size limit`,
`restricted: tenant has reached the alias limit`,
`invalid: event created_at is too far in the future`,
HTTP 413 `blob exceeds the maximum blob size`, and the 400/401/403/404/411
blossom shapes (`BlobError` in src/grasp_p/mod.rs).

Three more answers of `PUT /upload`, none of which the client matches on or
retries today (it reports the status and the reason, and the user runs the
push again):

| status | `X-Reason` | headers | class |
| --- | --- | --- | --- |
| 429 | `too many uploads in progress for this account; retry later` | `Retry-After: 5` | transient: the account has its maximum number of uploads in flight |
| 503 | `all upload slots are in use; retry later` | `Retry-After: 30` | transient: the node has 64 client uploads in flight (this was a 507 `quota exceeded` before) |
| 408 | `upload timed out waiting for the request body` | `Connection: close` | the upload stalled for 30 seconds or ran past its deadline; the whole upload has to be sent again |

What to tune is in §3, [Upload slots exhausted](#upload-slots-exhausted).

---

## 6. Rate-limit & cadence tuning

Four knobs (src/config.rs:743–773; reference: configuration.md Phase-4b
sections):

| knob | default | scope | meaning |
| --- | --- | --- | --- |
| `NGIT_GRASP_P_WRITE_RATE_CAPACITY` | 120 | per write key | burst tokens for CLIENT private writes: 30641/1059/21059 (1/event) + blob PUT (1/request) |
| `NGIT_GRASP_P_WRITE_RATE_REFILL_PER_MIN` | 60 | per write key | sustained refill, tokens/minute |
| `NGIT_GRASP_P_REGISTRATION_REPLACE_CAPACITY` | 8 | per (tenant, alias) | burst for same-tenant 30640 REPLACEMENTS |
| `NGIT_GRASP_P_REGISTRATION_REPLACE_REFILL_PER_HOUR` | 4 | per (tenant, alias) | sustained refill, replacements/hour |

- **Burst ≥ 4 on the replace bucket**: a §3.3 revocation rotation is
  widen→narrow = 2 replacements in quick succession, plus client error
  retries (src/config.rs:760–765). Defaults (8/4) already cover this — do
  not lower the capacity below 4.
- **Disable: set the CAPACITY to 0** — the limiter is fully off
  (src/grasp_p/rate.rs:33–56). Refill must be > 0 whenever capacity is
  non-zero; boot validation fails otherwise (src/config.rs:1099–1113).
- The **write bucket** gates client submissions only — synced/loopback
  traffic bypasses it (node-local DoS knob, deliberately NOT in the
  fingerprint). The **replace bucket** gates client AND synced live
  admission — it is consensus-relevant: paired nodes MUST run identical
  values (in the fingerprint since v2, §2).
- **Churn caveat (write bucket is per-KEY, not per-IP).** An attacker who
  cycles fresh keys gets a fresh bucket per key, so the write bucket does
  NOT bound a key-cycling flood — the effective per-IP bounds are the
  generic connection limit (`NGIT_MAX_CONNECTIONS`, src/config.rs:601–603,
  plus the `ngit_websocket_flagged_abusers` abuse detection,
  src/metrics/connection.rs:91) and the nginx zones (below). The bucket's
  real value is bounding **registered** keys gone rogue (a compromised or
  leaked w-key can't exceed its capacity/refill) and making quota-uncharged
  21059 spam cost a key per bucket instead of being free.
- Floods look like: `ngit_private_rate_limited_total{path}` rising from a
  single source; rejections are not extra-logged at info — the metric is
  the signal. Bucket state is in-memory: a restart resets every bucket;
  ≤ 65536 keys tracked per limiter, idle entries swept after 1h
  (src/grasp_p/rate.rs:18–25), so key-churn cannot exhaust memory.
- **Upload slots and body timeout** are separate from the two buckets:
  `NGIT_GRASP_P_MAX_UPLOADS_PER_TENANT` (default 8, `0` = off) caps the
  uploads one account has in flight, and
  `NGIT_GRASP_P_UPLOAD_MIN_BYTES_PER_SEC` (default 16384, `0` = idle
  cut-off only) sets how long an upload body may take. Both are node-local
  and outside the fingerprint. Meaning of each answer and what to change:
  §3, [Upload slots exhausted](#upload-slots-exhausted). The time limits
  need the front proxy to pass the body through as it arrives
  (`proxy_request_buffering off`, as in nginx-upload-zones.conf); a proxy
  that buffers the body hides a slow sender from the node.
- Outer per-IP layer: nginx zones (nginx-upload-zones.conf) —
  `blobput` 10r/s burst 20 on `/upload`, `blobdel` 2r/s burst 5 on
  `DELETE /<sha256>`, throttles answered 429 via `limit_req_status`.

---

## 7. Split-view drill (Phase-4b exit gate)

Goal: prove the external watchdog catches one node withholding a
kind-30641, and that pushes are halted while the pair is split. Run on
staging before go-live, and after any sync/topology change.

Prereqs: watchdog installed with its timer running against both nodes
(watchdog.md §systemd); a test alias with a live 30640 on both nodes.

1. **Baseline.**

   ```bash
   ngit-private-watchdog --relay-a wss://git-a.example --relay-b wss://git-b.example --json
   # expect exit 0
   ```

2. **Partition WITHOUT stopping either node** — a down node is exit 2
   (operational error), never divergence (watchdog.md §Exit codes). On node
   B, block its outbound sync path to A:

   ```bash
   iptables -A OUTPUT -p tcp -d <node-A-IP> --dport 443 -j REJECT
   ```

   (Equivalent: restart B with no `NGIT_GRASP_P_SYNC_PEER_URLS` entry for A;
   unsetting the bootstrap relay is not needed. The E2E restarts B with
   neither setting, on a new port: tests/private_watchdog.rs:513–525.)

3. **Withhold**: publish a new 30641 edition to node A (an ordinary
   cord-git push does this).
4. **Assert detection**: once the edition's `created_at` is older than
   `--max-skew-secs` (default 300), the watchdog exits **1** with
   `FAIL manifest-parity … reason=withheld-30641` on stdout and
   `WATCHDOG ALERT` on stderr. Expected collateral: `NgitSyncPeerDisconnected`
   fires at 10m; `blob-existence` may FAIL for blobs B never claimed.
5. **Push halt. Client-side gate: PENDING client issue** — cord-git has no
   two-node push gate yet: `push()` publishes only to `ks.relays.first()`
   with a CAS + same-relay read-back (cord-core/src/repo.rs:554–648), and
   the multi-relay cross-check (`cross_check_live_registration`, GitLab !14,
   repo.rs:2218–2263) runs on the FOLD path, not on push. Until that issue
   lands, **the watchdog is the halting mechanism**: treat watchdog exit 1
   as a push freeze for all tenants; if your pipeline can gate pushes, gate
   them on the watchdog's exit status.
6. **Restore.**

   ```bash
   iptables -D OUTPUT -p tcp -d <node-A-IP> --dport 443 -j REJECT
   ```

   Sync redelivery (5s index rebuild, src/sync/mod.rs:445–466) converges B;
   worst case waits for the hourly full re-issue
   (`NGIT_GRASP_P_FULL_REISSUE_INTERVAL_SECS`, default 3600,
   src/sync/mod.rs:481–518). Assert the watchdog exits **0**.

---

## 8. Sybil-load soak guidance

Run against staging, loopback-only, no sudo — the scripts/phase0/
discipline (g6_nginx_stream_shape.sh: 127.0.0.1 binds, cleanup on exit).

**Whitelist-mode soak (the shipped posture).** Script sketch: generate N
fresh keypairs; each signs a shape-valid 30640 (32-char lowercase-hex alias,
`relays` + `server` tags exactly listing the staging node — its host and
port, and its mount path if it has one (`parse_shape`); sole `w` = author
key); publish all N to node A. For the cost of a refusal, give half of them
64 `w` keys with well-formed signatures that do not verify: they must be
refused the same way and as fast, since no proof is verified for a sender
the mode refuses.

Assert:

- every publish returns OK false `tenant is not on the registration whitelist`
- `ngit_private_registration_conflicts_total` flat, also when the fresh keys
  aim at an alias that is taken
- `ngit_private_events_rejected_total{kind="30640"}` rises by N
- `ngit_private_registrations_total`, `ngit_private_aliases_total` flat
- `ngit_private_ledger_bytes{scope="global"}` flat — rejected registrations
  never charge (src/grasp_p/registration.rs:534–546)
- above 1 rejection/s for 15m, `NgitPrivateAdmissionRejectionSpike` fires —
  that is the alert working, not a fault

**Open-mode staging soak (staging only — §1).**

1. Flip BOTH staging nodes to `open`, restart, verify fingerprint parity (§2).
2. Drive fresh-key registrations + blob PUTs: admissions are accepted until
   the per-tenant quota (`NGIT_GRASP_P_QUOTA_TENANT_BYTES`) or the global
   budget binds. Watch `ngit_private_ledger_bytes{scope="global"}` climb;
   `NgitPrivateLedgerBudgetHigh` fires at 80% of the rule-file literal.
3. Assert the limiters hold: a sustained single-key write flood is capped at
   120 burst / 60 per min with `rate-limited; retry later` (429 +
   `Retry-After` on PUT); a same-tenant 30640 replacement flood is capped at
   8 burst / 4 per hour with `replacement rate-limited; retry later`;
   honest traffic still converges via the server-side hold-and-retry
   (§5), backstopped by the hourly re-issue.
4. Flip back to `whitelist`, restart, re-verify fingerprint parity before
   returning the pair to service.

---

## 9. Routine ops

**Denylist files.**

- Per-node / per-jurisdiction: `NGIT_GRASP_P_DENYLIST_PATH` takes a
  comma-separated list; mount only the lists this jurisdiction enforces.
- A file MISSING AT BOOT is tolerated (boot warn `private denylist file
  <path> not found; treating it as empty`); a present-but-UNREADABLE file is
  a hard boot error (`load_boot` in src/grasp_p/denylist.rs). During reload
  an unreadable file, one that no longer parses (over the size or line
  cap), or one that has disappeared keeps its last-known entries and is
  retried every tick (error-logged: `keeping last-known entries`) — a
  transient read error, an unmounted volume or a deploy that deletes before
  it writes never silently unblocks taken-down content.
- The reload starts from what the boot load read, file by file. The first
  reload after boot therefore changes nothing unless a file changed on
  disk, and "last-known entries" includes the ones a file had at boot.
  (Before this, a file that became unreadable after boot lost its boot
  entries as soon as any other file was reloaded.)
- A file that DISAPPEARS after it was read keeps its entries (decision
  D11): the error `has disappeared; keeping last-known entries` repeats on
  every reload tick until the file is back, and
  `ngit_private_denylist_entries` does not fall. A takedown is lifted only
  by a readable file that no longer lists the hash: to lift one, edit the
  file; to retire a whole list, replace its contents with a comment line
  (an emptied file keeps its entries, as a deploy that truncates before it
  writes would leave it), let one reload pass, then remove it from
  `NGIT_GRASP_P_DENYLIST_PATH` at the next restart. A list
  removed from disk alone stays enforced until the node restarts, and a
  restart reads a missing file as empty, so check the mounts before every
  restart. Still replace denylist files atomically (write a temp file,
  then rename): a write read half-done is read as it is.
- Reload every `NGIT_GRASP_P_DENYLIST_RELOAD_SECS` (default 60; 0 disables
  reload — the boot-time set is kept). Only mtime-changed files are
  re-read; the live set swaps atomically.
- Watch `ngit_private_denylist_entries`: a drop to 0 on a node that should
  be enforcing a list means its files were cleared, or were missing at the
  last restart (metric help, `PRIVATE_DENYLIST_ENTRIES` in
  src/metrics/mod.rs); a file that goes missing or reads back empty while
  the node runs shows as the error above instead.

**Backups.** The relay DB under `NGIT_RELAY_DATA_PATH` (default
`./data/relay`) is the source of truth for registrations — the private meta
index (`<relay_data_path>/private-meta`, override
`NGIT_GRASP_P_META_DATA_PATH`) is rebuilt from it by `boot_reconcile` (§1)
when it is missing. Blob bytes under `<relay_data_path>/blobs` (override
`NGIT_GRASP_P_BLOB_DATA_PATH`) are NOT rebuildable — losing them is data
loss; back them up. (Generic storage notes: configuration.md
§`NGIT_RELAY_DATA_PATH`.)

**Restores.** Never start a node on a meta index older than its relay DB.
At a restart the seats the meta index already holds are judged by their
age, so a registration the node accepted after that copy was taken is
refused against a settled seat there (kept in the relay DB, not deleted)
while the peer holds it: watchdog registration parity FAILs. Restore the
relay DB and the meta index from one snapshot taken with the service
stopped, or restore the relay DB alone and delete `private-meta`, so the
start rebuilds the index from it. The same applies to the rebuild under a
stricter mode (§1): delete the index, do not restore an old one.

**Config changes.** Keep all four sources in sync — src/config.rs,
docs/reference/configuration.md, nix/module.nix, .env.example (AGENTS.md
§Configuration Management). No runtime reload except the denylist (§4):
restart for everything else.

**Watchdog.** systemd install and alert consumption: watchdog.md §systemd
(oneshot + 5-minute timer). Prometheus bridge: prometheus-alerts.yaml:184–225.

**Log cheatsheet** (`journalctl -u ngit-grasp`):

```bash
journalctl -u ngit-grasp | grep 'GRASP-P private repositories enabled'   # boot line: mode, policy_fingerprint, policy_version, sync_peers, event_blacklist_keys — compare both nodes after ANY config change
journalctl -u ngit-grasp | grep 'NGIT_GRASP_P_SYNC_PEER_URLS names no peer'   # GRASP-P on, no sync peer, but a mirror or bootstrap relay set (§1)
journalctl -u ngit-grasp | grep -E 'a plaintext ws:// (peer|relay)|NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS=true on a node'   # the dial error and warnings at startup (§1, Which relays a node dials)
journalctl -u ngit-grasp | grep 'over wss:// only'                       # relays that events name, refused for ws:// (once per relay)
journalctl -u ngit-grasp | grep 'all new private-repo registrations'     # empty-whitelist warn (§1)
journalctl -u ngit-grasp | grep 'private registration conflict'          # conflict alerts (fields in §3)
journalctl -u ngit-grasp | grep -E 'denylist purge-on-add|GC purged denylisted|GC removed'   # purge lines (§4)
journalctl -u ngit-grasp | grep 'boot reconcile'                         # 'applied N registration(s)'; warns 'stored 30640 no longer passes registration checks'
journalctl -u ngit-grasp | grep 'private mirror'                         # warn 'blob fetch failed on all peers' carries the full reason; at most one per blob and reason per 10 min
journalctl -u ngit-grasp | grep 'NIP-56 report event received'           # report intake, private-pointing reports only (refused): event_id, reporter, sha256_tags (§4)
```

---

## 10. Known residuals / not in this runbook

Pointers, not procedures:

- **Server issue !1** — offboard/tombstone worker + event-byte stranding:
  kind-5'd / merge-evicted / vanished registrations leave `t:`/`g:` event
  bytes stranded; the tombstone purge worker is unbuilt. Operator-visible
  effect: ledger drift after registration deaths (§3 Ledger budget).
- **Server issue !4** — ledger refund-on-replace: replaced 30641 editions
  are not refunded; bounded, documented drift (docs/grasp-p/phase1-report.md:37).
- **Server issue !5** — dedup pinning: fixed in M3 (decision D4); every
  referencing repository pays its own charge (§3 Ledger budget).
- **Accepted residuals from prior verify rounds** (documented in code/issues):
  an active squatter who keeps their registration live AND saturates their
  own quota blocks the genuine rekey at the claimed address until operator
  action (their tenant npub is operator-visible — §3 Registration conflict);
  FG conflict-alert dedup is in-memory (one re-alert per restart/TTL at
  most); ≥3-party conflict chains converge only via sync redelivery.
- **Backdating in a seat's first hour.** A registration dated before a
  seat's first edition wins the §3.2 merge on every node, not only on nodes
  that missed an edition, while the seat is under an hour old: an admitted
  account can take a repository's alias in its first hour, or, holding one
  of its keys, the whole repository, and the repository's blobs are
  collected after the grace period. It raises `NgitPrivateRegistrationConflict`
  (`stored_evicted`, the offender in `winner_tenant`), and the account is
  closed ([Registration conflict](#registration-conflict) step 5). A seat
  older than an hour is never displaced. M4 binds the alias to the account
  key, so that no other account can register it at all.
- **The node's clock in the merge.** Whether a seat has settled is judged by
  each node's own clock, so a challenger that reaches the two nodes on either
  side of that moment is accepted by one and refused by the other, and so is
  one that reached the other node first when the seat was already over an
  hour old on arrival (backdated by its signer, or delivered late). The lag
  is seconds when live sync carries the challenger, but up to the hourly
  full re-issue (`NGIT_GRASP_P_FULL_REISSUE_INTERVAL_SECS`, 3600 s by
  default) when it does not, so a winner of a seat's first hour that misses
  live delivery to the peer can split the pair. Both alert, the watchdog
  reports it, and the split does not heal by itself. There is no repair
  tool until the offboarding work (issue 1). Keep both nodes' clocks
  synchronised. For the same reason a conflict planted across a partition
  longer than an hour no longer heals: each node keeps its seat.
- **Late-witness anchors.** On a node that never saw a seat's first edition
  (it was replaced everywhere before this node synced), any registration
  dated before the edition the node saw wins there while that edition is
  under an hour old, and the other node refuses it (by the order if it is
  dated after the first edition, as settled if before), so the pair splits
  (Registration conflict, step 6). A node whose meta store was rebuilt is
  in the same position for every seat. The victim's self-heal, re-minting
  with `created_at` ≤ the squatter's, works only while the squatter's seat
  on that node is under an hour old (the R2-B note in `apply`,
  src/grasp_p/registration.rs).
- **A rebuild meets leftovers.** A rebuild of a wiped meta store decides
  by the merge order alone and anchors each seat on its newest stored
  edition. A registration the node evicted but failed to prune then takes
  the seat back on this node, while the peer keeps the winner (Registration
  conflict, step 6), when the winner has published a later edition, or when
  the leftover's alias was freed and taken by another account dated after
  it. A restart over the same meta store keeps the first-edition anchors,
  and judges another account's seat by its age, so there a leftover can
  evict such a seat only while it is under an hour old.
- **Three or more parties.** A chain of conflicts (A and B share one key,
  B and C another) is not order-independent at a replay or a rebuild: a
  later registrant can lose its seat there until sync redelivers it.
- **Who may delete (D6).** Only the account key deletes, a whole
  repository by its 30640 coordinate with `["k","30640"]`; members cannot
  delete or vanish (§5), so a member who asks to delete is told to ask the
  account. A request that names a registration, by `["k","30640"]` or a
  30640 coordinate, carries nothing else, no event id either, and is
  refused otherwise, whoever sends it (D15-6); an account that also
  deletes public notes sends a second, ordinary request for them. A key whose membership one node has
  not yet seen can vanish there, and its own registrations go on that node
  only; with `NGIT_DELETION_REQUEST_DISRESPECTOR=true` no registration is
  ever deleted. See "Who may delete" in SEAMS.md.
- **Account closure.** A customer closes an account with a NIP-62 vanish
  that carries `["relay","ALL_RELAYS"]` or names both nodes of the pair
  (and every node its registrations' `server` values list, as written);
  each node refuses an account's vanish that names only one of them, which
  would close the account there and leave it open on the other. The vanish
  removes every registration of the account whatever its date, frees every
  alias and key at once (D15-7: there is no hold until merge request 18),
  and refuses the account key on both nodes for as long as upstream keeps
  the vanish (the `NGIT_DELETION_REQUEST_RETENTION_*` settings: by default
  360 days after it last removed or refused an event). A replayed old
  vanish of an account key closes the account the same way. A vanish that
  reached a node before the account registered there is that node's alone:
  if it named only that node, the account is refused there and stays open
  on the other; an `ALL_RELAYS` vanish closes it on both.
- **WS-path per-IP limiting gap**: nginx `limit_req` cannot inspect frames
  inside a long-lived WS connection — the per-IP outer layer covers the
  HTTP blob routes only; the inner layer is the per-write-key bucket
  (nginx-upload-zones.conf, KNOWN GAP, lines 66–78).
- **Stub knob**: `NGIT_GRASP_P_OFFBOARD_RETENTION_SECS` is read and not
  enforced yet (issue 1). The two settings that had no call sites at all
  (per-tenant metrics, direct invites; plan-v2-fix-log.md S6) were
  removed. `ngit_private_ledger_bytes` has only `scope="global"`.
- **Paid mode** is not built (boot-rejected, §1).
- **Mirror lookups**: the mirror connects to the addresses its client's
  resolver vetted (src/grasp_p/vetted_dns.rs), so a name cannot answer one
  address to the check and another to the connection; a connection kept in
  the client's pool stays on the address it was opened to. The relay dial
  is still vetted and not pinned (§1, "A pair on a private network").
