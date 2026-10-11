# CORD-git v0.1 — protocol convention for multi-tenant private git repos on public GRASP nodes

Status: **v0.1, written from the as-built** at server `master` **c5301bb** (GRASP-P phases 0–4b plus
the 3359 stream-wrap migration) and client `main` **eb1e5e2** (cord-core/cord-git phase-4a + harness
compat plus the client half of that migration). This is the protocol
convention layer; `GRASP-P` is the server implementation (an ngit-grasp v1.2.0 extension) and
`cord-core`/`cord-git` is the reference client. Conformance markers: **[N]** normative, **[I]**
informative, **[D]** deferred. "plan §3.2/§3.3" references the executing implementation plan, not
sections of this document.

## 1. Model & trust

CORD-git provides GitHub-style private repositories — per-repo contributor sets, read vs write
roles, invite/revoke/promote/demote, issues/PRs — where the **host is a public Nostr/GRASP relay
whose operator is untrusted**. **[N]** The server stores only ciphertext and opaque public keys; it
verifies outer signatures against a registered key set and moves bytes. Confidentiality never
depends on server read-gating (the relay stays public-read; ciphertext harvest is a conceded
residual — store-now/decrypt-later). Membership, keys, invites, and revocation are tenant-side.

**[N]** What "private" means: the server and world learn only
`(hosting npub → random 32-hex alias → registered write/aux pubkeys → blob hashes/sizes/timing →
epoch lineage across rotations)`. Never on the server in plaintext: repo names, refs, file
contents, contributor identities.

**[N]** `GET /list/<pubkey>` answers only the listed pubkey (§2.4), with one identical refusal
for everyone else, so that route no longer hands an anonymous caller a hosting npub's stored
inventory and does not say whether the npub is a tenant. That closes one route, not the leak
above: the set stays public and enumerable through the events. Kind-30640 registrations are
served to any anonymous REQ, so whether an npub is a tenant, its aliases and its registered keys
are public; the kind-30641 state roots those keys sign name their manifest and packs by hash and
size, and `GET /<sha256>` is open. Two anonymous queries therefore still yield the hashes, sizes
and count of every blob a tenant's current state roots name, and watching the events yields push
cadence. What `/list` alone showed, and now shows only to the listed key, is stored blobs that no
currently served state root names. Blob *content* stays encrypted.

## 2. Server-visible wire kinds

### 2.1 kind 30640 — registration [N]
Addressable event signed by the **hosting npub** (a fresh pseudonym per repo by default).
- `d` = **alias**: exactly 32 lowercase-hex chars, random (never the repo name).
- `w` = `["w", <write-pubkey-hex>, <pop-sig-hex>]` ×N, ≥1 required — registered write keys.
- `aux` = `["aux", <pubkey-hex>, <pop-sig-hex>]` ×N — publish keys for read-only members' streams
  and for rekey addresses. Aux keys can never publish 30641s or blobs.
- **Proof-of-possession [N]**: every `w`/`aux` key that is not the event author carries, as the
  tag's third value, a 128-hex BIP-340 schnorr signature by that key over
  `SHA256("grasp-p key-claim:" || <tenant-hex> || ":" || <alias>)` (`<tenant-hex>` = the hosting
  npub's x-only hex). Binds the claim to (tenant, alias); prevents key-namespace squatting. The
  author key is exempt — the event signature is its proof.
- `|w| + |aux| ≤ NGIT_GRASP_P_MAX_WRITE_KEYS_PER_ALIAS` (default 64); a key repeated across
  `w ∪ aux` is rejected (it would corrupt claim-index diffing).
- `relays` and `server` tags: ≥1 value of **each** must denote the serving node's domain by
  **exact host match** (the pre-4b substring test admitted `wss://evil.com/x?example.com` and
  `example.com.attacker.tld`).
- **Deterministic cross-node conflict merge [N]** (plan §3.2): when an incoming 30640 claims an
  alias held by a different tenant, or any `w`/`aux` key claimed by a different alias, the winner
  is the one with the **lowest created_at**, ties to the **lowest event id** — compared against the
  holder's **FIRST-edition anchor** (`first_created_at`/`first_event_id`), never the latest edition
  and never node-local `registered_at`. Both operands are event-intrinsic, so partitioned nodes
  converge on the same winner. Same-tenant replacement PRESERVES the anchor; authentic older
  same-tenant evidence LOWERS it (late-witness self-heal). This comparator and same-tenant
  replacement ordering (newest wins) are strict duals — pinned by test, never merged.
- **Merge-winner exemptions [N]**: node-local state **that is not in the `policy_fingerprint`
  preimage** must never gate a merge winner — a winner is exempt from the alias-count limit, the
  quota *check* (never the charge), and the replacement-cadence bucket. Fresh non-conflict
  registrations keep all three. Admission-mode gates (whitelist/pow) **do** apply to a conflict-merge
  alias takeover (§5), because paired nodes are required to run identical, fingerprint-verified
  admission config — so those gates cannot diverge the merge.
- **Loser eviction [N]**: in the winner's meta txn the loser's record, key claims, alias slot,
  blob-claim references, orphaned speculative charges, alias event-bytes column, and state-ring
  editions are all freed; its relay-DB 30640 coordinate is pruned by the async caller. Both conflict
  arms fire an operator alert, but only one is deduped: an **incoming** registration that loses
  alerts at most once per loser event id (1 h TTL), so boot-reconcile and sync redelivery of an
  already-resolved loser cannot re-alert forever; an **evicted stored** registration alerts
  unconditionally on every eviction.
- **Claim death [N]**: key claims are also freed by an author-valid NIP-09 kind-5 deletion of a
  30640 (by `a` coordinate or `e` id) and by a NIP-62 vanish, both honoring a `created_at` cutoff —
  an edition NEWER than the deletion keeps its claims, so a replayed stale deletion cannot wipe a
  live edition; vanish freeing runs only when the request targets this relay. Without this, a
  member could squat a future epoch's derivable rekey addresses, delete their own 30640, and wedge
  every later rotation.

### 2.2 kind 30641 — state root [N]
Addressable event signed by a **registered write key** (aux keys refused).
- `d` = alias; `a` = `30640:<tenant-hex>:<alias>`, must equal the live registration's coordinate
  (first `d`/`a` tag wins, matching the addressable identifier).
- `m` = `["m", <manifest-sha256>, <bytes>]`, exactly one; `pack` = `["pack", <sha256>, <bytes>]`
  ×N. Total refs ≤ **256** per edition; each declared size ≤ the per-blob cap.
- Plaintext hashes are what quota/mirror/GC consume; they reveal only pack count/sizes/timing.
- Server retains the last N editions per **alias** in an edition ring (default 16), shared across
  all of that alias's write keys — the ring key is `(alias, created_at, event id)` and the trim
  scans by alias prefix; the author is not part of it. Relay-DB **addressable replacement** is
  separately per `(author, alias)`, as NIP-01 requires. **[N]** Consequence for multi-writer
  aliases (§2.1 permits `|w| + |aux| ≤ 64`): two active pushers share one 16-slot ring, so they
  halve each other's retained history and can trim-supersede each other's blob claims — a trimmed
  edition's referenced hashes lose this alias's claim, which releases the speculative charge *if
  other aliases still reference it*, or starts the GC grace clock *if it was the last*.
- **Speculative blob-claim charging [N]**: a referenced sha256 that is not yet stored and carries
  no earlier speculative charge is charged NOW, at its DECLARED size, to the declaring
  `(tenant, alias)` as a `stored=false` claim (`SpecCharge{tenant, alias, bytes}`); the quota
  decision covers event bytes + all new speculative bytes in one check. Released **exactly once**,
  against the recorded scope/bytes (never `claim.size`): (a) on upload — the upload txn releases
  before it charges, so a same-scope declare-then-upload nets out; (b) when the CHARGING alias
  stops referencing it while others remain (ring-trim supersede, registration death, Blossom
  DELETE), the survivor re-charging on its next 30641 (a deliberate bounded unbilled window);
  (c) on GC deletion after the claim loses its last alias and grace expires. `Option::take()`
  makes double-release structurally impossible.
- **In-transaction identity re-check [N]**: liveness is read outside the meta write txn, so the txn
  re-verifies `(alias, tenant, latest event id)` before ANY mutation and rejects otherwise — a
  footprint born after a death would have no cleanup trigger left.

### 2.3 kind 3359 / 23359 — encrypted streams [N]
The wire kinds are **3359** ("CORD stream wrap", stored) and **23359** (its ephemeral analog)
— `src/grasp_p/mod.rs:58,62`, client `cord-core/src/events.rs:41`. Admitted **only if** the outer
signer is in the `w ∪ aux` set of a live registration, **and** it satisfies the size, skew, quota
and rate gates below — membership is necessary, not sufficient. Contents are never inspected.
- **[N] Why not 1059.** These wraps are NIP-59-*shaped* but are not gift wraps: tagless (no `p`),
  author-addressed, symmetric AEAD rather than NIP-44, a derived signer shared by the group rather
  than a one-time random one, and a *signed* inner rumor where NIP-59 rumors are definitionally
  unsigned. Riding 1059 bought nothing and inherited NIP-59's relay AUTH-gating SHOULD, under which
  a p-tag-less wrap is servable to nobody. Genuine NIP-59 gift-wrapped **invites and promotions
  stay on 1059** and are delivered to the recipient's own inbox relay, never to a git node
  (`cord-core/src/events.rs:55`) — that split is deliberate and load-bearing; re-collapsing the two
  constants breaks either every invite or every stream read.
- **[N]** An unregistered outer author is **rejected outright** — never routed to the public
  related-event path. Accepting referenced wraps from unregistered keys made every deregistered
  rekey address permanently floodable and charged to nobody, defeating the client's epoch-scoped
  admission windows (plan §3.2). A rejected **3359** is held in the out-of-order index keyed by its
  outer author, so a later 30640 registering that key reprocesses it; **23359** is never stored and
  never held.
- **[N]** 3359 bytes are quota-charged once per event id (idempotent inside the serialized meta
  txn, so concurrent deliveries of one id cannot double-charge); 23359 is never charged — which is
  why the per-write-key rate bucket is its only cost.
- These carry the client's rekey (3303), guestbook (3314), and `#collab` (NIP-34/NIP-22) rumors.
  The server gates only by outer key. The reference client emits no ephemeral wraps at all; 23359 is
  a server admission capability.
- **[N] Tagless admission is gated.** A shipped wrap carries no `p` and no `a` tag, so it is an
  *orphan* to the public related-event policy and can only be admitted by the private arm. The full
  contract — admitted from a registered outer key, quota-charged, stored, and served to a
  never-AUTHed anonymous reader — is pinned on both wire kinds by `tests/private_repos.rs:4881`
  (legacy) and `:4892` (3359).

**[I] Transitional legacy window.** The server ALSO accepts the pre-migration kinds **1059/21059**
while `NGIT_GRASP_P_ACCEPT_LEGACY_WRAP_KIND` is true — its shipped default (`src/config.rs:746-767`,
`src/grasp_p/mod.rs:72-80`) — so wraps published by pre-migration clients, and legacy wraps still
held for out-of-order reprocess, keep draining. This is a migration window on *our* nodes, not a
protocol element: a new implementation speaks 3359/23359 only. Ordering is what the window buys —
a node must accept 3359 *before* any client emits it. Setting the flag false RETIRES the legacy
kinds outright (§5.2); it deliberately does not reclassify them onto the public related-event path,
which would be *wider* than the default. The reference client has completed its half: it emits and
reads 3359 only, with **no dual-kind read window** (`cord-core/src/relay.rs:237`), so stream wraps
stored at 1059 before the migration are invisible to it.

### 2.4 Blossom-subset blobs [N]
Content-addressed encrypted blobs over HTTP: `PUT /upload` (kind-24242 authorization),
`GET /<sha256>` (**public/unauthenticated**), `HEAD`, `DELETE`, `GET /list/<pubkey>`
(kind-24242 authorization signed by the listed pubkey).
Auth event (kind 24242) for upload and delete: tags
`t`∈{upload,delete}, `x`=<sha256>, `expiration`=<future>, `a`=`30640:<tenant>:<alias>`;
`created_at` from one hour before to 15 minutes after the node's clock; id + signature verified by
the route itself (no relay pipeline has seen it); signed by a `w`-set key. For list the required
tags are `t`=list, `expiration`=<future> and a `server` tag naming this node (no `x` or `a`; other
tags are ignored), with the same freshness and verification, and the signer
MUST be the pubkey in the path; a write key does not qualify. A path segment that does not parse
as a pubkey is a `400`. Every other refused list is the same `401` with the same `X-Reason` and no
body, whether the pubkey has blobs, has none or is unknown to the node, and nothing is looked up
before the authorization is checked; a list authorization without a `server` tag for this node is
refused the same way.
Header: `Authorization: Nostr <token>`, where `<token>` is the event JSON in standard base64 or in
base64url, padded or not; the server accepts all four forms.

**Replay of an authorization [N].** Whoever captures an authorization can use it again while the
node accepts it. Two stateless checks bound that, the same on both nodes of a pair:
- *Time.* `created_at` must lie in `[now - 3600 s, now + 900 s]` and `expiration` must not have
  passed, so a captured event is good for at most 75 minutes whatever `expiration` says. The
  client's own tokens expire after an hour. A client whose clock runs more than 15 minutes fast is
  refused, as its events of the kinds in §2 already are.
- *Server.* The BUD-11 `server` tag carries a bare domain (`host` or `host:port`, no scheme and no
  path). An authorization with one or more `server` tags is accepted only if one of them names the
  node: its configured domain, compared on the host without regard to case, plus the port when the
  configured domain has one. A mount path (`NGIT_BASE_PATH`) is not part of the comparison, so two
  services under different paths of one host are not told apart by it. The tag is REQUIRED for
  list, which nothing else binds to a node. For upload and delete it is checked when present and
  not yet required, because the client does not send it; it becomes required with protocol v0.2.
  Until then an upload or delete authorization without it is valid on any node that has the same
  registration, which a pair has by design.

The node keeps **no record of authorization ids it has already seen**, deliberately. What a
captured authorization can still do inside its window (75 minutes at most): a list authorization
returns that key's inventory to whoever presents it; an upload authorization, together with the
bytes, stores the blob again if its owner deleted it meanwhile; a delete authorization removes the
claim again if its owner uploaded the blob again meanwhile. Nothing else: no other blob, no other
alias, and where the event carries a `server` tag no other server. A record of used ids would
close these three only on one node and only until its next restart, because a table kept in one
process is neither shared with the node's peer nor kept across a restart, so the node does not
promise it. Neither check is part of `policy_fingerprint`:
authorization events are never replicated between nodes, so two nodes cannot come to hold
different data because of them, and both nodes of a pair run the same build.

**Responses [N].** A `401` carries `WWW-Authenticate: Nostr`; no other status does. `X-Reason`
never carries the text of an internal failure (the client reads `internal error`; the detail is in
the node's log). `X-Reason` and `Retry-After` are exposed to browser clients (CORS). Every response
of these routes says `X-Content-Type-Options: nosniff`. A served blob also carries
`Content-Security-Policy: default-src 'none'; sandbox`, `Cache-Control: no-cache` and a strong
`ETag` that is the sha256 in quotes: a cache may keep the bytes but must ask the node before each
reuse. `If-None-Match` is answered `304` only after the denylist and existence checks, so
revalidating a blob that was taken down gets the `451`. Errors and `404`s say
`Cache-Control: no-store`. Blobs were served `immutable` for a year before; a blob that was taken
down would have stayed in caches for that long.

**Descriptors [N].** `PUT /upload` and `GET /list` return `{url, sha256, size, uploaded}`.
`uploaded` is the time this node first stored the bytes, by upload or by mirroring, so the two
nodes of a pair report different times for one blob, and a repeat upload reports the first time.
`blob sha256 = SHA256(exact PUT bytes)`. `/list` aggregates only that tenant's own aliases via the
per-alias claim index (never a cross-tenant scan).

Size limits **[N]**: event JSON ≤ 128 KiB; blob ≤ 256 MiB (both configurable). Concurrent uploads
are capped (64) and reserved against the global byte budget BEFORE any body byte lands on disk.

## 3. Client cryptography [N]

- **community_id** = `SHA256("cord-git/community/v1" || owner_xonly(32) || owner_salt(32))`
  (self-certifying). The `cg-<community_id>` d-convention is live as the `#collab` binding
  coordinate `30617:<tenant>:cg-<community_id>`; **[D]** the public flip that would publish at it.
- **Channel keys**: independent random 32-byte keys per plane — `#state` (manifests) and `#collab`
  (issues/PRs/guestbook).
- **HKDF shape [N]**: every derivation below is HKDF-SHA256 with **`L = 32`** and the stated
  `salt`/`ikm`/`info`; where `info` is not stated it is the **empty string**, not the label. A
  derivation whose output must be a secp256k1 scalar (the write and guestbook keypairs, and
  `group_key` in §4.1) rerolls on the astronomically unlikely invalid-scalar case by **appending
  one attempt byte (0x00, 0x01, …) to `info`** and re-expanding. Guessing `info = label` yields a
  different key and fails silently.
- **write_secret** → per-epoch write keypair:
  `sk = HKDF-SHA256(salt="cord-git/write-auth/v1", ikm=write_secret, info=epoch_le32, L=32)`. Only
  write-role members hold `write_secret`.
- **Derived stream keys**: the `#collab` key derives the shared guestbook/stream keypair
  (`salt="cord-git/guestbook-stream/v1"`, `ikm=#collab key`, `info=""`, `L=32`), registered in the
  30640 `aux` set — it signs the outer 3359 of every guestbook Join and `#collab` message, so member
  npubs never appear on the git node. Symmetric seal keys are separately domain-separated and share
  that shape: `HKDF-SHA256(salt="cord-git/guestbook-seal/v1", ikm=#collab key, info="", L=32)` and
  `HKDF-SHA256(salt="cord-git/collab-seal/v1", ikm=#collab key, info="", L=32)`.
- **Blob encryption (keystone)**: every pack blob is ChaCha20-Poly1305 under a **fresh random
  32-byte key + fresh random 12-byte nonce**; wire = `nonce(12) || ct||tag`; `blob_id =
  SHA256(wire)`. No convergent encryption. The random key is recorded in the manifest.
- **Manifest**: JSON `{v, community_id, epoch, refs{name→oid}, packs[{blob_id,key,nonce,size}],
  manifest_prev, ts}`, encrypted under
  `HKDF-SHA256(salt="cord-git/manifest/v1", ikm=#state key, info="", L=32)` and stored as the 30641
  `m` blob.
- **Fixed keys + random 96-bit nonces [N]**: fresh-key-per-message is the **blob** case only. The
  manifest key, the guestbook and `#collab` seal keys, and the rekey envelope seal key (§4.1) are
  **fixed for the lifetime of the channel key they derive from** — an entire epoch at minimum, and
  spanning multiple epochs when a rotation rekeys only the `write` scope (a demote), since
  `#state`/`#collab` are not rolled then. The rekey envelope seal key is strictly per-epoch. Each
  message gets a fresh random **96-bit** nonce, prepended as
  `nonce(12) || ct||tag`. Nonce-reuse safety is therefore a birthday bound in 2^96 — comfortable at
  any realistic per-epoch message volume, but it is an assumption an implementation inherits, not a
  property it can skip: nonces MUST come from a CSPRNG, and a 192-bit-nonce AEAD (XChaCha20-
  Poly1305) would remove the analysis entirely. **[D]** the framing choice is not yet frozen.
- **Integrity vs a malicious operator [N]**: on fetch, the client re-hashes every blob against its
  addressed sha256 and AEAD-authenticates on decrypt; wrong bytes are detected, never silently
  accepted.
- **Authenticated state-root selection [N]**: accept a 30641 only if it is (a) signature-valid,
  (b) authored by a pubkey in the CURRENT live 30640's `w`-set (that 30640 itself verified as
  tenant-authored), and (c) not future-dated beyond `FUTURE_SLACK_SECS` = 900 s (matching the
  server's `MAX_FUTURE_SKEW_SECS`); sort created_at desc, tie → lowest id. This is what makes
  revocation effective: a removed member's planted or future-dated state roots are never selected,
  and server-side admission also refuses future-dated private events so they cannot evict the real
  latest edition via addressable replacement. The same 900 s bound guards the encrypted `#collab`
  and guestbook inner rumors.
- **Publish confirmation [N]**: relay OK=true is not a commit marker (addressable replacement may
  silently discard a not-newest edition); read back the authenticated latest and confirm your own
  event id won. Wrap read-backs are **id-pinned** — an author-scoped read at a stream address can
  be buried by a flood of junk wraps.

## 4. Lifecycle

- **create [N]**: generate hosting npub (or take a pre-admitted one from `CORD_GIT_HOSTING_NSEC`,
  never argv) + salt + channel keys + write_secret + alias; publish 30640 (write key + derived
  guestbook aux key, both with PoP); publish the genesis guestbook Join. `create` ends there — it
  does **not** push; a fresh community has no 30641 until the first explicit `push`.
- **push [N]**: `git pack-objects` → encrypt (fresh random key) → PUT → build+encrypt manifest →
  PUT → publish 30641. **Client-side CAS**: refuse if the authenticated remote latest ≠ the local
  base (`manifest_prev`) unless `--force`; then read back and confirm the new edition won.
- **clone [N]**: fetch authenticated latest 30641 → GET+verify+decrypt manifest (`#state` key) →
  GET+verify+decrypt every pack → `git unpack-objects` → set refs (validated: `refs/…` prefix,
  conservative charset, no `..`, hex oids — anti git-flag-injection) → checkout. Refuses a
  non-empty destination.
- **invite / join [N]**: kind-3313 NIP-59 giftwrap of the bundle (community_id, alias, node
  relays/servers, channel keys, `write_secret` iff write role, role) to the invitee's OWN inbox
  relay — the client REFUSES to deliver to any configured git node. Join publishes a kind-3314
  guestbook rumor, sealed under the guestbook seal key, wrapped by the derived guestbook key.
  **[I]** The server has no setting for this: the knob `NGIT_GRASP_P_ACCEPT_DIRECT_INVITES` was
  never consulted by any admission path and has been removed. The never-to-the-git-node rule is
  enforced client-side only.
- **#collab issues/PRs [N]**: author-signed inner rumors (1621 issue, 1111 comment, 1617 patch,
  1630/1631/1632/1633 status) carrying `a`/`channel`/`epoch` binding tags, sealed under the
  `#collab` seal key and wrapped in a 3359 signed by the derived stream key with a past-tweaked
  created_at (≤48 h). Any member (read or write) may post. **[I]** The Concord seal kind 20013 is
  named in the client but no 20013 event is emitted — the seal is realized as the symmetric AEAD
  layer inside the wrap content. History survives refoundings via the retained **prior `#collab`
  key ring** (`epoch → {key, retired_at}`, capped, handed to retained members in the collab rekey
  slot). A retired key is READ-ONLY history: a rumor under it is rejected when
  `inner.created_at > retired_at + FUTURE_SLACK_SECS` — i.e. the admissible window is
  `retired_at + 900 s`, not `retired_at` exactly, so an in-flight rumor at the moment of retirement
  is not lost while a post-revocation injection by an old-key holder still is.
- **rotate [N]**: single-relay revocation primitive — fresh `write_secret` + `#state` key,
  re-register with only the new write key (server frees the old claim), re-push.
- **revoke / demote [N]**: plan-§3.3 sequencing, epoch-atomic — see §4.1.
- **promote [N]**: roster grant + `write_secret` whisper to the member's own inbox relay; no
  rotation. The member trusts the delivered secret only after it derives a write key present in the
  live 30640, verified against the tenant pubkey from the EXISTING keystore. The never-to-a-git-node
  delivery rule is enforced here by its own guard, independently of the invite path's — promotion
  carries `write_secret`, so it is the higher-value of the two leaks.
- **export / offboard [D]**: decrypted portable bundle; kind-5 tombstone; retention purge.

### 4.1 Rotation: pending-epoch lifecycle and §3.3 sequencing [N]

- **Order (NORMATIVE)**: `30640′` widen (w = old ∪ new, aux = old ∪ new ∪ **this epoch's** rekey
  addresses) → wait for confirmed acceptance on **every** configured relay → publish the 3303 rekey
  wraps → `30640″` narrow (new-only sets), per relay → a **final sweep** re-narrowing any relay not
  serving the narrow's key sets (per-relay created_at chains can tie cross-relay, and sync can
  transiently serve a widen edition over the narrow) → adopt the refounded secrets into the
  keystore → re-push the snapshot.
- **[N] The sweep MUST precede the re-push, and this is not an optimisation target.** Until every
  relay serves the narrow, a laggard may still serve a **widen** edition whose `w` set contains the
  revoked member's OLD write key — under which their 30641 still satisfies the §3 authenticated
  state-root rule and is selected as latest. Sweeping first closes that bypass window before any
  new snapshot exists; deferring the sweep until after the push extends it by a full
  pack→encrypt→upload→publish cycle, on exactly the relay least likely to have converged.
- **No idle rekey-address admission [N]**: next-epoch rekey addresses are never precomputed or
  pre-registered; an address is listed only between its widen and its narrow. Deregistration stops
  only NEW admissions — already-stored wraps stay readable.
- **Registrations are rebuildable TEMPLATES [N]**: the persisted widen/narrow are templates,
  re-signed per relay per attempt with **`created_at = live.created_at + 1`**, where `live` is the
  registration that relay is serving at that moment; where a relay serves **no** live registration
  the fallback is **`created_at = now`**. Addressable
  replacement resolves same-second ties by **lowest id**, so a registration built with
  `Timestamp::now()` can lose FOREVER (reproduced: create→demote inside one second wedged a
  rotation at publish). PoP signatures bind only (tenant, alias) and survive rebuilds; only the
  secret-bearing rekey wraps must republish byte-identically.
- **Pending-epoch file [N]**: the ENTIRE rotation — refounded secrets, roster/banlist snapshots,
  built widen/rekeys/narrow — is persisted to `pending-epoch.json` (0600, tmp+rename) BEFORE
  anything is published; a retry RESUMES from it and republishes the same rekey bytes (relays dedup
  by id), so one epoch can never carry two genuine rekey sets. Secrets are adopted into the
  keystore only after publication, so an aborted rotation leaves no half-applied state.
- **Rival-resume guard [N]**: before publishing over a live registration matching none of this
  rotation's own artifacts, its `created_at` is compared to the widen template's — anything newer
  means a rival rotation landed elsewhere (two-device case), and the resume aborts loudly rather
  than regressing to the stale epoch. The trigger is the **landed registration**, never a stray wrap.
- **Fork prevention at mint [N]**: before building a NEW rotation the client checks the derived
  addresses for genuine tenant-signed rekeys of that epoch and refuses to mint a rival set.
- **Squat tolerance [N]**: any member can derive an epoch's rekey addresses and claim them under
  their own alias, making the full widen fail with `write key already registered`. The client then
  publishes a MINIMAL widen (all rekey addresses stripped — w/guestbook keys are random and can
  never conflict) and re-adds individual addresses **on demand**, cumulatively, only when a rekey
  publish is refused with a message containing `unregistered`. Any other rejection is fatal and
  loud (a squatter saturating their own quota needs operator action, not a doomed retry).
- **Tenant-signed `scopes` tag [N]**: every 3303 carries `scopes` = the epoch's FULL scope set
  (`state,collab,write` for a revoke/refounding; `write` alone for a demote) in canonical order,
  inside the tenant-signed inner rumor. "Canonical" is the **scope enum's declaration order —
  `state`, `collab`, `write` — not lexicographic**; comma-joined, no spaces. No interop break
  either way: the fold re-sorts by the same order before comparing two rekeys' sets, so a
  lexicographic emitter still agrees — but the emitted bytes are `state,collab,write`. The fold
  requires all genuine rekeys of an epoch to agree on it exactly and refuses to apply ANYTHING
  until every listed scope is observed and verified — this is what distinguishes a write-only demote epoch (by design) from a partially
  withheld refounding, and what makes the fold epoch-atomic.
- **Fold rules [N]**: two genuine same-scope rekeys with different slots for this identity, or
  disagreeing `scopes` sets, = forked epoch → loud fatal, never a silent side-pick. No write-scope
  slot = demoted/never-had-push (keep reading); no state-scope slot = revoked. Rekeys are gathered
  from ALL configured relays (a withholding relay must not hide a scope). After folding, the
  post-fold keys are cross-checked against the live 30640 — a withheld rotation is a loud desync,
  never "already up to date".
- **Rekey wire [I]**: inner kind-3303 rumor **signed by the tenant** (authority is rejection — any
  member can derive the outer address key, so only the tenant signature authenticates it), tags
  `cgc`/`scope`/`epoch`/`scopes` (+ `prevcommit` for the write scope, over the PRIOR
  `(write_secret, epoch)`); per-member slots = opaque hint + NIP-44 ciphertext from a fresh
  ephemeral key. Outer 3359 signed by
  `group_key("concord/rekey-pseudonym", prior_root, scope_id, epoch)`, content sealed under a
  prior-root-derived key. The write scope uses a DEDICATED `scope_id` bound to the community id
  (stable across refoundings), so "no slot" cannot be confused with removal.
- **Rekey derivation family [N]** — wire-visible constants; an implementation that gets any label,
  separator or integer encoding wrong computes different addresses and is invisible to every other
  implementation. `‖` is byte concatenation, `epoch_le32` is the **u32 epoch, 4 bytes
  little-endian**, `community_id_bytes` is the **raw 32 bytes** decoded from the 64-hex
  `community_id`, and `member_xonly` is the member's **32-byte x-only** pubkey. Except where noted,
  `epoch` is the **NEW** epoch being minted and `prior_root` is the **PRIOR** community root.

  | Value | Derivation |
  |---|---|
  | `scope_id` | `SHA256(scope_label ‖ 0x00 ‖ community_id_bytes)` |
  | scope labels | `cord-git/state-scope-id/v1`, `cord-git/collab-scope-id/v1`, `cord-git/write-scope-id/v1` |
  | `group_key(label, root, scope_id, epoch)` | `sk = HKDF-SHA256(salt=label, ikm=root, info=scope_id ‖ epoch_le32, L=32)`, rerolled into the valid secp256k1 scalar range per §3 |
  | rekey address | `group_key("concord/rekey-pseudonym", prior_root, scope_id, epoch)` — its x-only pubkey is the address: the `aux` entry, and the outer wrap's signer |
  | `rekey_seal_key` | `HKDF-SHA256(salt="cord-git/rekey-seal/v1", ikm=prior_root, info=scope_id ‖ epoch_le32, L=32)` — symmetric; seals the outer content |
  | `slot_hint` | `SHA256("cord-git/rekey-slot/v1" ‖ 0x00 ‖ prior_root ‖ scope_id ‖ epoch_le32 ‖ member_xonly)`, lowercase hex — **plain SHA-256, not HKDF** |
  | `prevcommit` | `SHA256("cord-git/write-scope-prevcommit/v1" ‖ 0x00 ‖ write_secret ‖ epoch_le32)`, lowercase hex — over the **PRIOR** `(write_secret, epoch)` pair |

  On the inner rumor the `scope` tag value is the **hex-encoded `scope_id`**, not the scope name;
  `epoch` is the new epoch in decimal; `scopes` is per the bullet above. Anyone holding the prior
  root can derive every address and seal key of the epoch — which is exactly why authority rests on
  the inner tenant signature, and why an address is registered only between its widen and its
  narrow.

## 5. Server extension (GRASP-P) [N]

Additive to ngit-grasp v1.2.0, gated on `NGIT_GRASP_P_REPOS_ENABLE` (disabled = **behaviourally**
identical to upstream — the binary is not; all four kinds fall through to existing dispatch).
Admission mode **defaults to `whitelist`** — the safe "accept nothing without an explicit tenant list" posture; `open` is
staging/self-use only; `pow` (NIP-13, default 20 bits) is available; `paid` is **[D]** and rejected
by config validation. Admission modes gate NEW aliases only (including conflict-merge takeovers and
meta-index rebuilds); a boot reconcile of an already-admitted same-tenant edition skips them, and a
rejected replay is non-destructive (no meta mutation, no pruning).

Also: write-key index with PoP, per-tenant/per-repo/global quota ledger + in-flight reservation,
Blossom-subset blob store (streamed PUT, sha-verified, GC with grace), 30641 edition ring,
aggregate metrics (no per-tenant labels), NIP-11 `private_repos` advert (`kinds`,
`registration_mode`, size caps, quotas, `blob_endpoints`, `policy_fingerprint`, `policy_version`,
plus `pow_bits` only in pow mode) — `src/grasp_p/mod.rs:1564-1601`. `policy_version` is the
`policy_fingerprint` PREIMAGE-FORMAT label published verbatim beside the digest, so a pair whose
digests differ can tell a mid-rolling-upgrade version skew from a real same-version knob split
(§5.1). The `kinds` array is the discovery signal for "does this node speak the private extension",
and is built from the same helpers the admission arms use (`stream_wrap_kinds` /
`ephemeral_stream_wrap_kinds`, `mod.rs:94-110`) so it cannot drift from the accepted set:
`30640, 30641, 3359, 23359`, plus `1059, 21059` for as long as the legacy window (§2.3) is open.

Two-node replication: 30640 L1 sync filter → registration-driven 30641 `#d` +
3359 `authors` derived filters (plus 1059 while the legacy window is open — the same helper again,
`src/sync/filters.rs:104`); out-of-order reprocess hold; hourly `since=None` full re-issue with
a per-peer minimum interval; **pull-only blob mirror** over the peer's public GET with per-blob
exponential backoff. **[N]** Outbound private-sync connections are *initiated* ONLY to the operator
allowlist `NGIT_GRASP_P_SYNC_PEER_URLS` — tenant `relays` tags are advisory metadata and never
trigger a connection (SSRF + membership-map-leak guard). **One exception, by design**: a configured
`NGIT_SYNC_BOOTSTRAP_RELAY_URL` is connected unconditionally at startup and also carries the
derived private filters, so it MUST be treated as a trusted private-sync peer — it learns the same
registration-derived `#d`/`authors` filter set as an allowlisted peer, i.e. the tenant's alias and
key map. Do not point it at a relay you would not put on the allowlist. Mirror SSRF guard:
private-IP block, no redirect-following, https-only by default, sha+size-bounded.

### 5.1 Abuse hardening (phase-4b) [N]

- **Per-write-key token bucket** on CLIENT-submitted private writes (30641 / stream wraps / blob PUT):
  default capacity 120, refill 60/min. Synced and reprocess traffic (loopback:0) bypasses it, so it
  has no convergence impact — and is deliberately NOT in the policy fingerprint. Blob route answers
  429 with `Retry-After`.
- **30640 replacement-cadence limit**: per-`(tenant, alias)` bucket on same-tenant REPLACEMENTS,
  default capacity 8, refill 4/hour; burst must stay ≥ 4 (a §3.3 rotation is widen→narrow = 2
  replacements plus retries). **Hold semantics [N]**: a cadence-rejected replacement is both
  rejected to the client AND held in the rejected index, then re-offered by the sync layer after
  refill (hourly full re-issue as backstop) — convergence must not depend on the client retrying.
  Applies to live admission from clients AND peers; boot-reconcile replays and merge winners are
  exempt.
- **`policy_fingerprint` v3**: `sha256(preimage)[..16]`, label `grasp-p-policy-v3`
  (`src/grasp_p/mod.rs:326`), over
  `mode, pow_bits, whitelist, max_event_bytes, max_blob_bytes, quota_tenant, quota_repo,
  global_budget, max_aliases, max_keys, replace_capacity, replace_refill_per_hour,
  accept_legacy_wrap_kind, domains`
  (domains = sorted `{own domain} ∪ {bootstrap peer}`; the raw whitelist feeds the hash but is
  never exposed). Everything not named in that preimage is excluded; among the excluded knobs are
  client-write-rate, denylist, sync-re-issue and mirror-retry, GC grace/interval,
  offboard retention, the mirror knobs, and **`state_history_editions`** (the §2.2 ring depth) —
  the rationale being that they are node-local and do not affect acceptance. **[N] That rationale
  does not fully hold for `state_history_editions`**: ring depth decides which editions are trimmed,
  trimming releases blob claims and their speculative charges, released charges change the quota
  ledger, and quota decides acceptance. Two paired nodes on different ring depths can therefore
  diverge on a `quota exceeded` verdict for the same 30641. Pair them on the same value, or add it
  to a future preimage revision. **`accept_legacy_wrap_kind` joined the preimage at v3** because it
  decides which stream-wrap KINDS a node admits, which is direct acceptance behaviour: a peer with
  the legacy window closed rejects a 1059 wrap its pair accepted and stored — exactly the split view
  the fingerprint exists to detect. Paired nodes must advertise the same fingerprint; a label
  mismatch (v2/v3) is itself the divergence signal, and is published as `policy_version` (§5) so an
  operator can tell an unfinished rolling upgrade from a genuine knob split.
- **Denylist → 451**: node-local, multi-file, periodically reloaded (default 60 s), enforced on the
  read path AND the upload preflight, with purge-on-add and a GC sweep that bypasses the grace
  period. Deliberately not fingerprinted — per-jurisdiction lists legitimately differ. A file that
  cannot be read or parsed on a reload keeps the entries it last had, those read at boot included;
  a file that is missing counts as empty (an open question, see `PLAN.md`). Blobs are served
  `no-cache` (§2.4) so that a takedown reaches HTTP caches as well.
- **Authorization window and `server` tag** (§2.4): fixed in the code, the same on every node, and
  not in the fingerprint, because authorization events are never replicated.
- **kind-1984 (NIP-56) intake**: observe-then-defer. Event id, reporter, and sha256-looking tag
  values are logged (never the content) and metered; admission then runs the existing related-event
  rules unchanged. No automatic action in v1.
- **`ngit-private-watchdog` [I]**: a separate binary that anonymously probes TWO nodes and alerts
  on split-view divergence (NIP-11 fingerprint, registrations, state roots, blob existence).
  Holds no keys, signs nothing, publishes nothing, and so cannot read `/list`. Exit 0 = parity, 1 = divergence, 2 =
  operational error; an unreachable node is never reported as divergence. Ops artifacts (runbook,
  nginx zones, Prometheus alerts) live in `docs/grasp-p/ops/`.

### 5.2 Rejection-string contract [N]

| Condition | NIP-20 message | Class |
|---|---|---|
| 30641: no live registration for the alias | `unregistered alias` | genuine, **widenable** |
| stream wrap: outer key unclaimed, or alias not live | `unregistered key` | genuine, **widenable** |
| 30641: registration identity changed inside the txn | `alias registration changed; retry` | **transient** |
| stream wrap: registration identity changed inside the txn | `registration changed; retry` | **transient** |
| 30640: same-tenant replacement over cadence | `replacement rate-limited; retry later` | **transient** (held + re-offered) |
| client write bucket exhausted | `rate-limited; retry later` | **transient** |
| 30640: lost an alias conflict | `alias already registered` | genuine |
| 30640: lost a key conflict | `write key already registered` | genuine (drives the squat-tolerant widen) |
| whitelist / pow / alias limit / quota | `tenant is not on the registration whitelist` / `registration requires N bits of NIP-13 proof of work` / `tenant has reached the alias limit` / `quota exceeded` | genuine |
| any private kind, created_at > now + 900 s | `event created_at is too far in the future` | genuine |
| 1059/21059 while the legacy window is CLOSED | `legacy stream-wrap kind is not accepted on this node` | genuine, **not** widenable |

**[N]** The cord-git client treats any message containing the substring `unregistered` as its
widenable case. The two transient identity-race strings are therefore deliberately worded to avoid
that substring: an honest same-tenant rotation trips them, and a plain retry under the new record
succeeds. **The retired-legacy-kind string avoids it too, for the opposite reason**
(`src/nostr/builder.rs:910`): it fires only when `NGIT_GRASP_P_ACCEPT_LEGACY_WRAP_KIND=false`
(§2.3), it is GENUINE rather than transient, and no amount of widening can help — the kind itself is
retired on that node, so the only fix is for the client to emit 3359. A retired legacy wrap is
refused here rather than falling through to the public related-event path, which would accept it
from ANY key, uncapped, uncharged and never GC'd. **[I]** cord-git `push()` currently treats `unregistered alias` on a 30641 as fatal
rather than re-registering and retrying once (client issue !34); widen is the wrong primitive there.

## 6. Threat model summary

| Adversary | Defense |
|---|---|
| Operator / disk / coercion | Ciphertext-only; server verifies signatures against opaque keys |
| Scraper / negentropy harvest | Same encryption; ciphertext harvest CONCEDED (not PQ) |
| Non-member npub | No keys ⇒ cannot read; blob PUT and 30641 gated by registered write key + PoP. **Not** gated: `GET /<sha256>` is unauthenticated, so a non-member who learns a hash (state roots are public and name them) can download that (encrypted) blob. `GET /list/<pubkey>` answers only the listed pubkey (§1, §2.4) |
| Malicious reader-member | Blobs content-addressed immutable; 30641 needs a `w` key; rekeys authenticated by the tenant signature, not by the derivable outer key |
| Removed member | Forward-only: keeps old clone; post-rotation cannot push, learn new keys, or read new content |
| Rekey-address squatter | PoP + §3.2 merge (an honest-created_at squat loses to the live+1 widen and is evicted); minimal-widen fallback for claim-winning squats; claim death on kind-5/vanish |
| Cross-node split-brain | First-edition-anchored deterministic merge; node-local state never gates a winner; `policy_fingerprint` parity; watchdog |
| Malicious tenant (abuse) | Quotas, speculative-claim charging, global budget, admission modes, per-write-key + cadence buckets, per-IP nginx zones, denylist/451, 1984 intake |
| Mirror SSRF | Private-IP block, no redirect-follow, https-only default, sha+size-bounded, peer allowlist |

## 7. Conformance & residuals

- **[D] Concord byte-conformance**: the membership/crypto layer is CORD-git-native behind a
  `KeyBackend` seam; a Concord backend (pinned commit 23dcea57) is future engineering, not a
  promise (R1). Marmot remains a risk-register fallback.
- **Residuals [I]**: ciphertext store-now/decrypt-later; removed-member re-fetch of old ciphertext;
  epoch lineage visible to the operator (the price of quotas); mirror DNS-rebinding (mitigated by
  an explicit peer-URL override); sizes/timing side channels (padding defaults **[D]**); an
  attacker backdating BELOW the true first edition wins the §3.2 merge (inherent to the created_at
  anchor); if edition 1 is purged from every sync source, a late-joining node anchors on its
  first-witnessed edition until the victim re-mints an earlier registration; ≥3-party conflict
  chains converge only with sync redelivery (the earliest registrant always keeps its seat); spec
  charges carried by a dead scope leave a bounded unbilled window until the survivor's next 30641;
  `t:`/`g:` event-byte stranding on registration death; a live squatter saturating their own quota
  blocks a rekey at their claimed address until operator action; byte quotas do not bound
  claim/file COUNTS (server issue !25).
- **Landed since v0.1**: the **1059→3359 / 21059→23359 stream-wrap migration** (§2.3), on both the
  server (`c5301bb`) and the client (`eb1e5e2`), with the NIP-11 `kinds` advert, the sync filters and
  the `policy_fingerprint` moving in lockstep. What remains of it is not spec work but an operational
  step: closing the legacy window per node once every client on it has migrated. Kind numbers 3359 /
  23359 are still **unregistered** in the nips README table (see `nip-conformance.md` item 11).
- **Landed after the `c5301bb` as-built (2026-10)**: `GET /list/<pubkey>` answers only the listed
  pubkey, on its own `t`=list authorization, with one identical refusal (§1, §2.4, §6); the
  authorization token is accepted in base64url as well as standard base64 (§2.4); the watchdog no
  longer compares `/list` (§5.1). At `c5301bb` the route was unauthenticated.
- **[D] remaining**: paid mode, flip-public, export/offboard tombstone worker, 30643
  snapshots, WASM viewer, Tier-H migration, Concord byte-conformance, padding defaults, AEAD nonce
  width (§3), gated-GET, Cashu.

## 8. Amendments since v0

- §2.1 — §3.2 deterministic merge + FIRST-edition anchor + winner exemptions + loser eviction (v0: bare "first-registrant-wins").
- §2.1 — kind-5/kind-62 claim freeing with the created_at cutoff; vanish must target this relay.
- §2.1 — `relays`/`server` matching is exact-host, not substring; key-count and duplicate-key rules.
- §2.2 — speculative (`stored=false`) claim charging + exactly-once release; 256-ref cap; in-txn identity re-check.
- §2.3 — unregistered stream wraps rejected outright (never the public path); stored held, ephemeral not; **[D]** on collab rumors dropped.
- §2.3 — **stream wraps moved to their own kinds 3359/23359** (server `c5301bb`, client `eb1e5e2`); 1059 retained ONLY for genuine NIP-59 invites/promotions; legacy 1059/21059 dual-accept as a transitional window, default on; retired-kind rejection string (§5.2); tagless-admission gate written (`tests/private_repos.rs:4881,4892`), closing the hole `nip-conformance.md` item 7b recorded.
- §2.4 — authorization window narrowed from ±24 h to one hour back and 15 minutes ahead; BUD-11 `server` tag (required for list); no used-id record, and why; response headers (`nosniff`, CSP, `no-cache` + `ETag` in place of a one-year `immutable`, `no-store` on errors, `WWW-Authenticate` on 401 only); `uploaded` is the stored time.
- §5/§5.1 — NIP-11 gained `policy_version`; `policy_fingerprint` bumped to **v3** with `accept_legacy_wrap_kind` in the preimage.
- §3 — derived stream/seal keys, prior-`#collab` key ring, precise HKDF shapes, the 900 s constant, id-pinned read-backs.
- §4 — invite/join, #collab, revoke/rotate/demote/promote re-marked **[N]**; `ACCEPT_DIRECT_INVITES` noted unenforced server-side.
- §4.1 (new) — pending-epoch lifecycle; templates at `created_at = live+1`; no idle rekey-address admission; rival-resume guard; mint-time fork prevention; squat-tolerant widen; tenant-signed `scopes` + epoch-atomic fold.
- §5 — whitelist is the SHIPPED DEFAULT (v0 implied open); paid config-rejected; sync peers only from the operator allowlist.
- §5.1 (new) — per-write-key bucket; cadence limit with hold semantics; fingerprint v2 + exclusions; denylist/1984 re-marked **[N]**; watchdog.
- §5.2 (new) — exact transient-vs-genuine rejection strings and the `unregistered` substring contract.
- §6/§7 — squatter + split-brain adversary rows; residuals expanded with the accepted anchor/merge/spec-charge findings; **[D]** narrowed.
