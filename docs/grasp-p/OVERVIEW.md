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
that still reads plaintext. GRASP-P has no read gate at all and relies only on encryption.
One node runs one or the other, not both.

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
registered write key and naming the registration. `GET /<sha256>` is unauthenticated.

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
  (testing only).
- **Key rules**: proof of possession, no key reused across aliases, state roots only from
  write keys.
- **Conflicts**: if two tenants claim the same alias or key, the earliest first registration
  wins on every node, so partitioned nodes agree.
- **Quotas**: per tenant, per repo and global byte budgets. A state root is charged for the
  blobs it declares even before they are uploaded.
- **Rate limits**: per write key, and on how often a registration may be replaced.
- **Abuse**: a denylist that answers 451 and purges, and intake of kind `1984` reports.
- **Garbage collection**: blobs no state root references are removed after a grace period.

It advertises all of this in its NIP-11 document under `private_repos`, including a
`policy_fingerprint` so that paired nodes can prove they run the same rules.

## Replication

Two nodes can mirror each other. Sync is pull-only: a node subscribes to its peer's
registrations, derives filters for the state roots and stream wraps that belong to them,
and fetches missing blobs over the peer's public `GET`. Peers come from an operator
allowlist only; URLs inside tenant events never trigger a connection.

`ngit-private-watchdog` is a separate binary that probes two nodes anonymously and reports
when they disagree. It holds no keys.

## Known limits (as of this writing)

Design limits, which stay:

- Metadata is visible: sizes, timing, key sets, rotation history.
- Revocation is forward-only.
- The operator can refuse service or withhold data. It cannot forge or read.

Gaps being closed before production (tracked as issues on the two projects):

- `GET /list/<pubkey>` needs no authorization, so anyone can list a tenant's whole blob
  inventory in one request.
- An operator can serve an **older** validly signed state root; the client has no
  monotonic floor yet.
- Invite bundles do not prove who sent them.
- Every push uploads the full history as one pack. There is no fetch into an existing clone
  and no `git` remote helper; the working path is the `cord-git` CLI.
- Member keys are passed as an nsec, and the keystore is unencrypted on disk.
- No paid admission mode, and offboarding (tombstone and purge) is not implemented.
- The server extension is based on ngit-grasp v1.2.0 and is being ported to v3.x, where the
  module moves out of `src/grasp_p/` and the `NGIT_GRASP_P_*` settings are renamed.
