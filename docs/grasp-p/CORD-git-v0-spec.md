# CORD-git v0 — protocol convention for multi-tenant private git repos on public GRASP nodes

Status: **v0, written from the as-built** (Phases 0–4 of the GRASP-P/CORD-git plan). This is the
protocol convention layer; `GRASP-P` is the server implementation (an ngit-grasp v1.2.0
extension) and `cord-core`/`cord-git` is the reference client. Conformance markers: **[N]**
normative, **[I]** informative, **[D]** deferred (named but not yet in v0).

## 1. Model & trust

CORD-git provides GitHub-style private repositories — per-repo contributor sets, read vs write
roles, invite/revoke, (later) issues/PRs — where the **host is a public Nostr/GRASP relay whose
operator is untrusted**. **[N]** The server stores only ciphertext and opaque public keys; it
verifies outer signatures against a registered key set and moves bytes. Confidentiality never
depends on server read-gating (the relay stays public-read; ciphertext harvest is a conceded,
documented residual — store-now/decrypt-later). Membership, keys, invites, and revocation are
tenant-side.

**[N]** What "private" means: the server and world learn only
`(hosting npub → random 32-hex alias → registered write/aux pubkeys → blob hashes/sizes/timing →
epoch lineage across rotations)`. Never on the server in plaintext: repo names, refs, file
contents, contributor identities.

## 2. Server-visible wire kinds

### 2.1 kind 30640 — registration [N]
Addressable event signed by the **hosting npub** (a fresh pseudonym per repo by default).
- `d` = **alias**: exactly 32 lowercase-hex chars, random (never the repo name).
- `w` = `["w", <write-pubkey-hex>, <pop-sig-hex>]` ×N — registered write keys.
- `aux` = `["aux", <pubkey-hex>, <pop-sig-hex>]` ×N — optional publish keys for read-only
  members' events.
- **Proof-of-possession [N]**: every `w`/`aux` key that is not the event author carries, as the
  tag's third value, a 128-hex BIP-340 schnorr signature by that key over
  `SHA256("grasp-p key-claim:" || <tenant-hex> || ":" || <alias>)`, where `<tenant-hex>` is the
  hosting npub's x-only hex. Binds the claim to (tenant, alias); prevents key-namespace squatting.
- `relays` and `server` tags: at least one of **each** must contain the serving node's domain.
- First-registrant-wins on `w`/`aux` keys across tenants; alias owned by first tenant.

### 2.2 kind 30641 — state root [N]
Addressable event signed by a **registered write key**.
- `d` = alias; `a` = `30640:<tenant-hex>:<alias>` (must match the live registration).
- `m` = `["m", <manifest-blob-sha256>, <bytes>]`; `pack` = `["pack", <sha256>, <bytes>]` ×N.
- Plaintext hashes are what quota/mirror/GC consume; they reveal only pack count/sizes/timing.
- Server retains the last N editions per (author, alias) in an edition ring (default 16).

### 2.3 kind 1059 / 21059 — encrypted streams [N] / [D]
1059 (stored) and 21059 (ephemeral) are admitted iff the outer signer ∈ any live registration's
`w ∪ aux` set. Contents are never inspected. In v0 these carry **[D]** roster/collab rumors
(Phase 4-full); the client MAY use them, the server only gates by outer key.

### 2.4 Blossom-subset blobs [N]
Content-addressed encrypted blobs over HTTP: `PUT /upload` (kind-24242 authorization),
`GET /<sha256>` (public), `HEAD`, `DELETE`, `GET /list/<pubkey>`. Auth event (kind 24242):
tags `t`∈{upload,delete}, `x`=<sha256>, `expiration`=<future>, `a`=`30640:<tenant>:<alias>`;
signed by a `w`-set key (aux keys cannot write blobs). Header:
`Authorization: Nostr <base64(event-json)>`. `blob sha256 = SHA256(exact PUT bytes)`.

Size limits **[N]**: event JSON ≤ 128 KiB; blob ≤ 256 MiB (configurable).

## 3. Client cryptography [N]

- **community_id** = `SHA256("cord-git/community/v1" || owner_xonly(32) || owner_salt(32))`
  (self-certifying; d-convention for a future public flip is `cg-<community_id>`).
- **Channel keys**: independent random 32-byte keys per plane — `#state` (manifests) and
  `#collab` (issues/PRs, Phase 4).
- **write_secret** → per-epoch write keypair:
  `sk = HKDF-SHA256(salt="cord-git/write-auth/v1", ikm=write_secret, info=epoch_le32)`. Only
  write-role members hold `write_secret`.
- **Blob encryption (keystone)**: every pack blob is ChaCha20-Poly1305 under a **fresh random
  32-byte key + fresh random 12-byte nonce**; wire = `nonce(12) || ct||tag`; `blob_id =
  SHA256(wire)`. No convergent encryption. The random key is recorded in the manifest.
- **Manifest**: JSON `{v, community_id, epoch, refs{name→oid}, packs[{blob_id,key,nonce,size}],
  manifest_prev, ts}`, encrypted under `HKDF(#state key, "cord-git/manifest/v1")` and stored as
  the 30641 `m` blob. (v0 deviation from the plan's random-key-manifest-in-rumor: the
  `#state`-derived key gives the same read-scope without a rumor fold; **[D]** the rumor path
  returns for multi-writer roster/collab.)
- **Integrity vs a malicious operator [N]**: on fetch, the client re-hashes every blob against
  its addressed sha256 and AEAD-authenticates on decrypt; wrong bytes are detected, never
  silently accepted.
- **Authenticated state-root selection [N]**: a client must accept a 30641 only if it is (a)
  signature-valid, (b) authored by a pubkey in the CURRENT live 30640's `w`-set (the 30640 itself
  signature-verified against the tenant npub), and (c) not future-dated beyond clock skew
  (≤15 min). This is what makes revocation effective: a removed member's planted or future-dated
  state roots are never selected, and server-side admission also refuses future-dated private
  events (≤15 min skew) so they cannot evict the real latest edition via addressable replacement.
- **Publish confirmation [N]**: relay OK=true is not a commit marker (addressable replacement may
  silently discard a not-newest edition); a client must read back the authenticated latest after
  publishing and confirm its own event id won before recording the new base.

## 4. Lifecycle

- **create [N]**: generate hosting npub + salt + channel keys + write_secret + alias; publish
  30640 (with PoP); first `push`.
- **push [N]**: `git rev-list --objects --all | git pack-objects` → encrypt (random key) → PUT
  → build+encrypt manifest → PUT → publish 30641. **Client-side CAS**: refuse if the remote
  latest 30641 ≠ the local base (`manifest_prev`) unless `--force` (fork = fetch/merge first).
- **clone [N]**: fetch latest 30641 → GET+verify+decrypt manifest (`#state` key) → GET+verify+
  decrypt every pack (recorded keys) → `git unpack-objects` → set refs (validated: `refs/…`
  prefix, hex oids — anti git-flag-injection) → checkout.
- **revoke / rotate [N, partial]**: generate fresh `write_secret` + `#state` key, re-register
  30640 with only the new write key (server frees the old key's claim), re-push under the new
  secrets. A holder of old secrets can no longer push (write key deregistered) nor read new
  content (rekeyed `#state`); their existing clone persists (forward-only, C7). **[D]** roster
  removal, Concord refounding, and re-provisioning retained members via invite.
- **invite / join [D]**: 3313 giftwrap (NIP-59) of the bundle (community_id, alias, node relays/
  servers, channel keys, `write_secret` iff write role, role) to the invitee's own inbox relay —
  never the git node.
- **export / offboard [D]**: decrypted portable bundle; NIP-09 kind-5 tombstone; retention purge.

## 5. Server extension (GRASP-P) [N]

Additive to ngit-grasp v1.2.0, gated on `NGIT_PRIVATE_REPOS_ENABLE` (disabled = byte-identical to
upstream). Registration policy (open/whitelist/pow; paid **[D]**), write-key index with PoP,
per-tenant/per-repo/global quota ledger + in-flight reservation, Blossom-subset blob store
(streamed PUT, sha-verified, GC), 30641 edition ring, aggregate metrics, NIP-11 `private_repos`
advert + `policy_fingerprint`. Two-node replication: 30640 L1 sync filter → registration-driven
30641 `#d` + 1059 `authors` derived filters; out-of-order reprocess; **pull-only blob mirror**
over the peer's public GET (SSRF-guarded: private-IP block + no redirects + https-only by
default). Denylist→451, kind-1984 intake, offboard kind-5: **[D]/stub**.

## 6. Threat model summary

| Adversary | Defense |
|---|---|
| Operator / disk / coercion | Ciphertext-only; server verifies signatures against opaque keys |
| Scraper / negentropy harvest | Same encryption; ciphertext harvest CONCEDED (not PQ) |
| Non-member npub | No keys ⇒ cannot read; blob PUT gated by registered write key + PoP |
| Malicious reader-member | Blobs content-addressed immutable; 30641 needs a write key; **[D]** roster authorship check |
| Removed member | Forward-only: keeps old clone; post-rotation cannot push, learn new keys, or read new content |
| Malicious tenant (abuse) | Quotas, global budget, admission modes, per-IP nginx, denylist **[D]** |
| Mirror SSRF | Private-IP block, no redirect-follow, https-only default, sha+size-bounded |

## 7. Conformance & residuals

- **[D] Concord byte-conformance**: the membership/crypto layer is CORD-git-native behind a
  `KeyBackend` seam; a Concord backend (pinned commit 23dcea57) is future engineering, not a
  promise (R1). Marmot remains a risk-register fallback.
- **Residuals**: ciphertext store-now/decrypt-later; removed-member re-fetch of old ciphertext;
  epoch lineage visible to the operator (the price of quotas); mirror DNS-rebinding (mitigated
  by an explicit peer-URL override); sizes/timing side channels (padding defaults **[D]**).
- **[D] remaining**: #collab issues/PRs (NIP-34/22 rumors in `#state`/`#collab`), invite/join,
  export/offboard, abuse hardening (denylist/451, 1984, per-IP zones, ops runbook), paid mode,
  flip-public, Tier-H migration, 30643 snapshots, WASM viewer.
