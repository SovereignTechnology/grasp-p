# GRASP-P Phase 3 — CORD-git client core design contract

Status: implementation contract for the CLIENT side. The client is NEW code in a SEPARATE
cargo workspace at `~/ngit-private-impl/cord-git/` — it does NOT live in the ngit-grasp server
tree. It talks to a running GRASP-P server (the Phase 1/2 `ngit-grasp` binary with
`NGIT_GRASP_P_REPOS_ENABLE=true`) over ws:// (relay) and http(s):// (Blossom blobs).

## 0. Honest scope note (R1 — Concord conformance)

The plan pins Concord commit 23dcea57 as the membership/key spec. That spec is NOT available in
this environment, and the server is **content-blind** (it verifies only outer signatures against
registered opaque pubkeys and moves ciphertext — it never inspects wrap contents). Therefore
Phase 3 implements a **CORD-git-native** membership/crypto layer that is self-consistent and
produces the exact server-visible wire shapes (30640/30641/1059/blobs) the server already
enforces. It is designed behind a `KeyBackend` trait so a byte-conformant Concord backend can
replace it later without touching the git/transport code (the plan's "clean key-module
separation so a future backend swap is possible engineering, not a promise"). This is stated as
the current limitation; full Concord/Marmot conformance is deferred (R1 risk accepted).

## 1. Workspace layout (`~/ngit-private-impl/cord-git/`)

```
Cargo.toml                 # workspace: members = [crates/*]
crates/cord-core/          # lib: keystore, crypto, wrap/seal, manifest, roster, server client
  src/{lib,keystore,crypto,wrap,manifest,roster,registration,relay_client,blob_client,git,error}.rs
crates/cord-git/           # bin: the `cord-git` CLI (create/join/invite/revoke/clone/push/roster/status/doctor)
crates/git-remote-cord/    # bin: git remote helper for cord://<community_id>[?relay=&blob=]
```

Deps (pin to what the workspace can compile): `nostr = { version = "0.45.0-alpha.3", features =
["std","nip44","nip59"] }` (+ `nostr-sdk` if useful for relay I/O), `chacha20poly1305 = "0.10"`,
`sha2 = "0.10"`, `hex = "0.4"`, `rand = "0.8"`, `hkdf = "0.12"`, `serde`/`serde_json`, `clap =
"4"`, `reqwest = { version = "0.13", features = ["blocking","native-tls"] }` (blocking is fine
for a CLI), `anyhow`, `tokio` (only if using async relay I/O). Shell out to system `git` for pack
operations (no git2/gix native dep) — like git-remote-gcrypt.

## 2. Crypto & key hierarchy (`cord-core::crypto`, `::keystore`)

- **community_id / repo identity**: `sha256("cord-git/community/v1" || owner_npub || owner_salt)`
  (32 bytes, hex). Self-certifying. `owner_salt` = 32 random bytes. The d-identifier convention
  for a future public flip is `cg-<community_id-hex>` (not used server-side in P3).
- **Channel keys**: two independent random 32-byte keys, `#state` and `#collab`. In P3 `#collab`
  is generated + stored but only exercised in P4; `#state` carries manifests.
- **write_secret**: 32 random bytes held only by push-role members. Registered write keypair
  derived per-epoch: `sk = HKDF-SHA256(salt="cord-git/write-auth/v1", ikm=write_secret,
  info=epoch_le)`, `pk = secp xonly`. Epoch is a u32 (0 in P3; rotation is P4). The 30640 `w`
  tag lists `pk`; the 24242 blob-auth events and 30641 are signed by this derived key.
- **Blob encryption (keystone)**: every blob (pack, manifest) = ChaCha20-Poly1305 under a FRESH
  random 32-byte key + random 12-byte nonce. Wire blob bytes = `nonce(12) || ciphertext||tag`.
  `blob_id = sha256(wire_blob_bytes)` (matches the server's `sha256(ciphertext)` addressing).
  The random key (+ nonce is in the blob) is recorded in the manifest per blob. NOT
  epoch-derived (late joiners must clone history; revocation stays forward-only + O(1)). NO
  convergent encryption.
- **Stream encryption**: `#state`/`#collab` rumors are NIP-44-encrypted to the channel key and
  wrapped as kind-1059 gift wraps (NIP-59) whose OUTER signer is the derived write key (so the
  server admits them: outer pubkey ∈ registered w-set). The inner rumor is signed by the
  member's own identity key (roster-verifiable authorship). Enforce the NIP-44 65408-byte
  plaintext cap; manifests larger than ~48 KB spill to an encrypted manifest BLOB and the rumor
  carries only the manifest blob pointer {blob_id, key}.
- **KeyBackend trait**: abstract `derive_write_key(epoch)`, `channel_key(plane)`,
  `wrap_rumor`/`unwrap`, `new_blob_key` behind a trait; the CORD-git-native impl is the only one
  in P3; a `ConcordBackend` is a documented TODO.

## 3. Manifest & state (`cord-core::manifest`)

Manifest (serde JSON, then encrypted to a blob):
```
{ "v":1, "community_id":hex, "epoch":u32,
  "refs": { "refs/heads/main": "<git-oid>", ... },
  "packs": [ { "blob_id":hex, "key":hex, "nonce":hex, "size":u64,
               "covers":"<oid-range-or-tip>" }, ... ],
  "manifest_prev": "<prev 30641 event id or null>",   // CAS chain
  "ts": u64 }
```
- `push` computes the delta pack (`git pack-objects` over `rev-list new ^old`), encrypts it,
  PUTs the blob, appends to `packs`, updates `refs`, sets `manifest_prev` = the 30641 event id
  this push is based on, re-encrypts the manifest to a fresh blob, PUTs it, then publishes BOTH:
  the public 30641 (`m`=manifest blob, `pack`×N=all pack blob ids) AND a `#state` rumor carrying
  the manifest blob pointer {blob_id, key, nonce}.
- `clone/fetch` = read latest 30641 → fold `#state` rumors to get the manifest blob key → GET +
  decrypt the manifest → GET + decrypt every pack → `git index-pack` / `git unpack-objects` into
  the local repo → set refs. Manifests carry ALL pack keys so a late joiner's clone always works.

## 4. Membership & roster (`cord-core::roster`, `::registration`)

- **Roster**: an owner-signed JSON document {members:[{npub, role:read|write, added_ts}],
  banned:[npub], epoch} published as a `#state` rumor (owner-signed inner). Members verify the
  owner signature chains from `community_id` (owner npub is recoverable). "Authority is
  rejection": a manifest/rumor whose inner author is not a current write-role member is ignored.
- **create** (`cord-git create <name>`): generate hosting npub (fresh pseudonym by default) +
  owner identity + owner_salt + channel keys + write_secret; derive write key (epoch 0); publish
  30640 (d=random 32-hex alias, w=[write_pk], relays+server listing the node); write the initial
  roster rumor (owner as write member); first push = full-history pack.
- **invite** (`cord-git invite <npub> [--write] --via <relay>`): add the invitee to the roster
  (role), publish the updated roster rumor, and send a **3313 giftwrap** (NIP-59, ephemeral
  signer) to the invitee's npub carrying the bundle: {community_id, alias, node relays+servers,
  #state key (+#collab key), write_secret IFF --write, role, roster snapshot}. Delivered to the
  invitee's own inbox relay (`--via`), NEVER the git node (leak management).
- **join** (`cord-git join`): receive the 3313 on the inbox relay, unwrap, persist the bundle to
  the local keystore.
- **revoke** (`cord-git revoke <npub>`): P4 (refounding + rekey). P3 stub: mark banned in roster
  + document that key rotation lands in Phase 4.

## 5. Keystore on disk (`cord-core::keystore`)

`~/.config/cord-git/<community_id>/keystore.json` (0600): owner/identity nsec, owner_salt,
channel keys, write_secret, alias, node relays+servers, epoch, roster cache, manifest_prev
cache. A separate `identity.json` holds the user's long-term identity nsec (reused across
communities). NEVER logged. Loaded per-command. (The server holds none of this — client-only.)

## 6. CLI surface (`cord-git`)

`create <name>` · `join [--bundle <file>|--relay <url>]` · `invite <npub> [--write] --via <relay>`
· `revoke <npub>` (P4 stub) · `clone cord://<community_id> [dir]` · `push [--force]` · `roster` ·
`status` · `doctor`. Plus the `git-remote-cord` helper so `git clone cord://…` and `git push`
work — but PRIORITIZE a working `cord-git clone`/`cord-git push` CLI for the E2E; the remote
helper is additive and may follow if budget allows.

`doctor`: connectivity to the node relay + blob server, keystore integrity, roster/write-key
consistency, and a self-test round-trip (create throwaway → push → clone → compare) against a
`--server` URL — the client-side analog of the Phase-0 gate suite.

## 7. Push CAS (concurrent-write safety)

The server does not enforce CAS in P1/P2. CORD-git enforces it client-side: `push` first fetches
the latest 30641 for the alias; if its event id != the local `manifest_prev` the push is based
on, REFUSE with "remote moved — fetch/merge first" (unless `--force`). On success, the new 30641
sets `manifest_prev` = the id it observed. Two concurrent pushers → the second's prev is stale →
refused. (Server-side CAS is a documented P5 nicety.)

## 8. Exit tests (E2E against a live server)

A test harness (`crates/cord-git/tests/e2e.rs` or a `scripts/e2e.sh`) that:
1. Spawns `ngit-grasp` (release binary) with `NGIT_GRASP_P_REPOS_ENABLE=true` on a localhost
   port (relay ws + blob http), memory or temp LMDB backend.
2. **create + push**: `cord-git create` a repo from a throwaway git repo with a couple of
   commits; assert the 30640 + 30641 land and blobs PUT succeed.
3. **clone (owner)**: `cord-git clone cord://<id>` into a fresh dir; assert the working tree
   matches the original (same HEAD oid, same file contents).
4. **invite + join + clone (contributor)**: invite a SECOND identity `--write` via a local inbox
   relay; `join`; clone as the contributor; assert match. Repeat read-only (no write_secret ⇒
   push is refused client-side AND the server PUT/30641 fails).
5. **push (contributor) round-trip**: contributor commits + pushes; owner fetches; assert the new
   commit is visible.
6. **concurrent-push CAS**: two pushers based on the same manifest_prev; the second is refused
   with the fork message; after fetch+retry it succeeds.
Exit = scenarios 2–6 green. Keep it hermetic (temp dirs, isolated keystore via
`CORD_GIT_HOME` env, throwaway npubs); never touch real `~/.config/cord-git` or `~/.gnupg`.

## 9. Non-goals (deferred)
- Byte-conformant Concord wire format (R1; KeyBackend trait leaves the seam).
- Revocation/refounding/rekey (Phase 4).
- #collab issues/PRs/comments (Phase 4).
- WASM viewer, flip-public, paid mode (Phase 5).
- The full git-remote-cord protocol is best-effort in P3; `cord-git clone/push` is the
  guaranteed deliverable.
