# GRASP-P and CORD-git: overview

A short map of the whole system. For exact rules read the two specs this page links to:

- [`grasp-xx-draft.md`](grasp-xx-draft.md): what a **server** must do (short, normative).
- [`CORD-git-v0-spec.md`](CORD-git-v0-spec.md): the **whole convention**, including client
  cryptography and key rotation (long, as built).
- [`nip-conformance.md`](nip-conformance.md): how each piece relates to existing NIPs and BUDs.
- [`ops/runbook.md`](ops/runbook.md): running a node.

## What it is

Private git repositories hosted on a public Nostr/GRASP server whose **operator is not
trusted**. The client encrypts everything before upload. The server stores ciphertext and
opaque public keys, checks signatures, enforces quotas, and moves bytes.

Two parts:

| Part | Repo | Role |
|---|---|---|
| **GRASP-P** | this one (`src/grasp_p/`, `src/http/blossom.rs`) | Server extension to ngit-grasp |
| **CORD-git** | `cord-git` (`cord-core` library, `cord-git` CLI) | Client: keys, encryption, membership |

This is a different model from GRASP-08. GRASP-08 puts an access gate in front of a server
that still reads plaintext. GRASP-P puts no gate in front of repository data (events and
blobs are public) and relies only on encryption. One node runs one or the other, not both.

## What the host can and cannot see

| The host never sees | The host does see (and so does anyone) |
|---|---|
| Repo names, branch and tag names | The hosting pubkey (a fresh pseudonym per repo by default) |
| File contents and commit history | A random 32-hex alias for the repo |
| Member identities (npubs) | The registered write and auxiliary pubkeys |
| Issue, PR and comment text | Blob hashes, sizes, counts and upload timing |
| Any key that decrypts the above | That a key rotation happened, and when |

Reads are public by design: any anonymous party can fetch the events and the encrypted
blobs. Harvesting ciphertext to attack later is a conceded risk, and the encryption is not
post-quantum.

## The pieces on the wire

Four event kinds reach the server, plus a blob store.

| Kind | Name | Signed by | Purpose |
|---|---|---|---|
| `30640` | Registration | Hosting key | Claims an alias and lists the keys allowed to write to it |
| `30641` | State root | A registered write key | Points at the current encrypted manifest and packs |
| `3359` | Stream wrap | A registered write or aux key | Encrypted group traffic: rekeys, joins, issues, PRs |
| `23359` | Ephemeral stream wrap | Same | As 3359 but never stored |

Kind `1059` (a genuine NIP-59 gift wrap) carries **invites and promotions**. Those go to the
recipient's own inbox relay and never to the git node.

**Registration (30640).** `d` is the alias. `w` tags list write keys; `aux` tags list keys
that may publish stream wraps but never state roots or blobs. Every listed key other than
the author proves possession with a signature bound to (hosting key, alias), which stops
one tenant from claiming another's keys. The event must name this server in its `relays`
and `server` tags.

**State root (30641).** One `m` tag names the manifest blob; `pack` tags name the pack
blobs. Each carries a sha256 and a size. The server uses those to charge quota, mirror
blobs and garbage-collect. It keeps the last 16 editions per alias for accounting.

**Stream wraps (3359).** Admitted only when the signer is a registered key of a live
registration. The server never looks inside. A wrap from an unregistered key is rejected
outright, not passed to the public event path.

**Blobs.** A subset of Blossom: `PUT /upload`, `GET` / `HEAD` / `DELETE /<sha256>`,
`GET /list/<pubkey>`. Upload and delete need a kind `24242` authorization event signed by a
registered write key and naming the registration. `GET /list/<pubkey>` needs one signed by
the listed pubkey itself, and every refusal is the same 401, so the route itself does not
say whether a pubkey is a tenant (its public registration events do). `GET /<sha256>` is
unauthenticated. The authorization token is accepted in standard base64 or in base64url.
An authorization is accepted from one hour before to fifteen minutes after the node's
clock, and one that names servers (BUD-11 `server` tags) only where it names this node; a
list must name it. A blob is served so that caches ask the node before each reuse, which is
how a takedown reaches them.

## Keys the client holds

| Secret | Who has it | Used for |
|---|---|---|
| Hosting key | Owner | Signs registrations |
| `write_secret` | Writers | Derives the per-epoch write key that signs state roots and uploads |
| `#state` key | All members | Decrypts manifests, and through them the packs |
| `#collab` key | All members | Issues, PRs, the guestbook; derives the shared stream key |
| Member identity (npub) | Each member | Signs the *inner* content; never appears on the git node |

Each pack is encrypted with ChaCha20-Poly1305 under a fresh random key. The manifest lists
refs and the pack keys, and is itself encrypted under a key derived from the `#state` key.
A reader therefore needs only the `#state` key to clone; a writer also needs `write_secret`.

An **epoch** is one generation of these secrets. Rotating moves the repo to a new epoch.

## The five flows

**1. Create.** The client generates the hosting key, alias and secrets, then publishes the
registration (write key plus the derived guestbook key). Nothing is pushed yet.

**2. Push.** Pack the objects, encrypt, upload the pack, build and encrypt the manifest,
upload it, publish a state root. Before publishing, the client checks that the server's
current state root is the one it started from, and afterwards reads back to confirm its own
event won. A relay saying "OK" is not treated as proof.

**3. Clone.** Fetch the newest state root that is validly signed by a key in the *current*
registration and not dated in the future. Download the manifest and packs, re-hash each one,
decrypt, unpack, set refs. Wrong or tampered bytes fail the hash or the decryption.

**4. Invite and join.** The owner wraps a bundle (repo coordinates, channel keys, and
`write_secret` for writers) to the invitee's inbox relay. The invitee imports it and
publishes a guestbook entry, signed on the outside by the shared stream key so their npub
stays hidden from the node.

**5. Revoke and rotate.** To remove a member the owner generates new secrets, then:

1. *Widen*: republish the registration with old and new keys both listed.
2. Wait until every relay has accepted it.
3. Publish *rekey* wraps that hand the new secrets to each remaining member, each in a slot
   only that member can open.
4. *Narrow*: republish the registration with only the new keys.
5. Sweep any relay still serving the wide registration, then push a fresh snapshot.

Remaining members run `fold` to pick up their slots. The removed member gets no slot, so
they cannot push, and cannot read anything created afterwards. They keep whatever they
already downloaded; that cannot be undone on a server that never held plaintext.

The whole rotation is written to a local file before anything is published, so an
interrupted rotation resumes with the same bytes instead of minting a second, conflicting set.

## What the server enforces

- **Admission**: who may register a new alias. `whitelist` (default), `pow`, or `open`
  (testing only). It is decided before any proof is verified or any conflict is looked at,
  and an account keeps control of the aliases it already holds.
- **Key rules**: proof of possession, no key reused across aliases, state roots only from
  write keys.
- **Conflicts**: if two tenants claim the same alias or key, the earliest first registration
  wins on every node, so nodes partitioned for less than an hour agree. Since anyone can
  date a registration early, that holds only while a repository is under an hour old: after
  that no other account can take its alias or any of its keys. In its first hour another
  admitted account can still take it; the node alerts with that account's key.
- **Quotas**: per tenant, per repo and global byte budgets. Every repository that references
  a blob pays its full size, even when another account stored it, and a state root is charged
  for the blobs it declares before they are uploaded; the disk keeps one copy. A repository
  that stops referencing a blob is released at once while another references it; the last one
  pays until GC deletes the bytes.
- **Rate limits**: per write key, and on how often a registration may be replaced.
- **Abuse**: a denylist that answers 451 and purges, and intake of kind `1984` reports that
  point at a private repository: they are logged and counted for the operator, and refused,
  so a blob key or an accusation in one is never published beside the repository. A
  reporter sends the blob key to the operator by mail. An account on the operator's event
  blacklist is frozen: no state root, stream wrap, upload or blob delete is accepted under
  its registrations, whichever of its keys signs it, and no registration by one of those
  keys, from clients or from the peer, while everything it stored stays readable.
- **Nothing attaches**: the node serves public repositories in the same process, under
  upstream's rules. An event of any other kind (deletion requests and vanishes aside, which
  the deletion rules judge) that tags a registration, a state root or a wrap, by its
  coordinate or by the id of one the node holds, is refused, whoever signs it; the private
  events themselves carry no such tags. Upstream would otherwise have
  stored it, and served it beside the repository, on the private event as its anchor.
- **Garbage collection**: blobs no state root references are removed after a grace period.

It advertises all of this in its NIP-11 document under `private_repos`, including a
`policy_fingerprint` so that paired nodes can prove they run the same rules. The fingerprint
covers the admission settings, the event blacklist, and the node's own address together with
the peers it lists, so two nodes that list each other and run the same rules show the same
value.

## Replication

Two nodes can mirror each other. Sync is pull-only: a node subscribes to its peer's
registrations, derives filters for the state roots and stream wraps that belong to them,
and fetches missing blobs over the peer's public `GET`. Registrations, state roots and stream
wraps travel only between the relays an operator lists in `NGIT_GRASP_P_SYNC_PEER_URLS`, in
both directions: only those are sent the GRASP-P filters, and a GRASP-P event that relay sync
brings from any other relay is refused before admission. The node's public sync, to the
bootstrap relay and every relay its public repositories name, runs beside it as upstream's
does, except that a relay an event names is dialled over `wss://` only; the bootstrap relay
keeps the scheme the operator gave it, and is a peer only when the list names it. A peer is
listed over `wss://`, or over `ws://` only on a link the operator declares private; the node
does not start with any other `ws://` peer unless `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS=true`, which
is for tests and closed networks. Relay and server tags in a
registration never decide who the node syncs events with, or where it fetches blobs from:
blob peers are the operator's list `NGIT_GRASP_P_MIRROR_PEER_URLS` alone, and a node without
one mirrors nothing. The mirror connects only to addresses its client's resolver vetted for a
peer; the connection makes no lookup of its own.

The relay connection to a configured peer is kept for the life of the process: when it
drops, or a dial fails for any reason, the node dials again by itself, at least once every
five minutes. The two nodes may talk over a private network while every relay that an
event names stays barred from internal addresses, including those reached through IPv6
translation or tunnel prefixes.

Missing blobs wait in one queue per account, and the accounts are served in turn, each
with at most half of the concurrent fetches, so one account whose blobs come slowly cannot
take every fetch. Two such accounts can fill the default four between them; a third then
waits for fetches of theirs to end. A scan of the claim table every minute, and at start, queues whatever is
still missing. A fetch that fails is tried again after a backoff, for as long as the blob
is referenced; nothing is given up on. A budget bounds how many fetches start per minute
over all accounts.

`ngit-private-watchdog` is a separate binary that probes two nodes anonymously and reports
when they disagree. It holds no keys.

## Known limits (as of this writing)

Design limits, which stay:

- Metadata is visible: sizes, timing, key sets, rotation history.
- Revocation is forward-only.
- The operator can refuse service or withhold data. It cannot forge or read.
- A public event that names a state root or a wrap by an id the node does not hold yet, one
  still on its way from the peer, is stored beside a public anchor and stays; a reference by
  coordinate is always refused (deletion requests aside).

Gaps being closed before production (tracked as issues on the two projects):

- An operator can serve an **older** validly signed state root; the client has no
  monotonic floor yet.
- Invite bundles do not prove who sent them.
- Every push uploads the full history as one pack. There is no fetch into an existing clone
  and no `git` remote helper; the working path is the `cord-git` CLI.
- Member keys are passed as an nsec, and the keystore is unencrypted on disk.
- No paid admission mode. Only the account key deletes, and only a whole repository, by its
  registration; members cannot delete from the server, and the deletion reaches both nodes of
  a pair. A deletion request that names a registration carries nothing but its signer's
  registration coordinates and the k tag, no event id either, whoever sends it; other
  deletion requests and vanishes go to upstream as on a node without private repositories,
  unless a member key signs them, they name a repository's state, or, for a vanish, its key
  signed stored state roots or wraps. An account closes with a vanish that names both nodes
  of the pair or all relays, and that vanish frees every registration of the account
  whatever its date. Deleting a registration
  frees its alias and keys at once and drops its claim on its blobs, which garbage collection
  removes after the grace period if nothing else references them; the tombstone, the
  retention window and the purge of stored state roots and wraps are not implemented.

The server runs on ngit-grasp v3.0.8. Its code is in `src/grasp_p/` and its settings are
`NGIT_GRASP_P_*`; `src/private/` and `NGIT_PRIVATE_*` belong to upstream's GRASP-08 mode,
and the server refuses to start with both enabled.
