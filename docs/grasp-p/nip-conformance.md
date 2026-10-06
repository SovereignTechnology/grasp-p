# CORD-git / GRASP-P — NIP & BUD conformance inventory

Audit date **2026-07-28**, against server `master` **c5301bb** and client `main` **eb1e5e2**.
The inventory was first taken at server `2e6e01a` / client `9562385`; items 3c, 4b, 5c, 7b, 10, 11
and 12 were re-verified after the **1059 → 3359 stream-wrap migration landed on both sides** and now
record shipped state rather than a decision. Migration hazards are kept as historical notes: they
are what a future reader needs to understand why the code is split the way it is.
Every claim about our code carries a `file:line`. Upstream claims are limited to what was verified
against live sources on the audit date; anything not verified is marked as such rather than asserted.

**Purpose.** An inventory of every place CORD-git / GRASP-P hand-rolled something an existing NIP or
Blossom BUD already covers, with a per-item verdict. Feeds a public standards proposal.

**Hard invariant — the server stays content-blind.** The server's `nostr` deps carry no feature list
(`Cargo.toml:20-26`), and `src/` contains **zero** references to `nip44`/`nip59` (verified by grep);
`tests/phase0_gates.rs:20` records the same via `cargo tree -e features -i nostr`. No verdict below
may require the server to decrypt, or to link NIP-44/NIP-59. Where an upstream SHOULD would require
that, the divergence is stated explicitly rather than papered over.

**Verdict vocabulary.** `ADOPT` = change our code to match upstream. `KEEP-BESPOKE` = deliberate,
documented divergence. `MIGRATE` = decided change of our own wire kind, away from a reused upstream
number; `MIGRATED` = that change has SHIPPED. `CONFORMANT` = we already consume the NIP correctly. `N-A` = the upstream spec does not apply
to this surface.

**Phase column.** `now` = defect, fix in the current line; `v0.2` = next spec revision; `P3` = the
GRASP-08-composition phase; `landed` = shipped since the inventory was first taken; `—` = no action.

---

## Summary verdicts

| # | Item | Upstream spec | Status today | Verdict | Phase |
|---|------|---------------|--------------|---------|-------|
| 1 | Blob auth event (kind 24242) | BUD-01/02/06/11/12 | partial — 3 BUD-11 MUSTs unmet | **ADOPT** (content, `server`, base64url) + **KEEP-BESPOKE** (`a` tag) | now |
| 2 | Blob / manifest encryption | NIP-44 v2 | bespoke ChaCha20-Poly1305 + HKDF | **KEEP-BESPOKE** | — |
| 3a | Invite bundle (3313 rumor) | NIP-17 / NIP-59 | genuine NIP-59 gift wrap, custom rumor kind | **KEEP-BESPOKE** (kind sanctioned) | — |
| 3b | Invite delivery discovery | NIP-17 kind 10050 | not implemented | **ADOPT** | P3 |
| 3c | Guestbook Join (3314) | NIP-59 | on kind **3359**; NIP-59-shaped, not a gift wrap | **MIGRATED** off 1059 (item 12) | landed |
| 4 | Rekey slots (3303) | NIP-44 v2 | correct `nip44::encrypt` V2, fresh eph. key per slot | **CONFORMANT** | — |
| 4b | Rekey outer wrap | NIP-59 | on kind **3359**; NIP-59-shaped, not a gift wrap | **MIGRATED** off 1059 (item 12) | landed |
| 5 | `#collab` issues/PRs | NIP-34 / NIP-22 | upstream kinds reused verbatim as rumors | **CONFORMANT-BY-REUSE** | — |
| 5b | `KIND_SEAL = 20013` | NIP-59 kind 13 | **not a wire kind** — comment-only const | **N-A** | — |
| 5c | `#collab` outer wrap | NIP-59 | on kind **3359**; NIP-59-shaped, not a gift wrap | **MIGRATED** off 1059 (item 12) | landed |
| 6 | Private-repo discovery (10318, `["private","true"]` 30617) | GRASP-08 draft, NIP-51 | not implemented | **ADOPT** | P3 |
| 7 | Client-side AUTH | NIP-42 | not implemented (client) | **ADOPT** | P3 |
| 7b | Relay AUTH-gating of stored stream wraps | NIP-59 SHOULD | deliberately **not** gated; the missing tagless gate has been **written** (exit36/exit39) | **N-A** — the wraps left kind 1059 (item 12), so there is no NIP-59 rule to except | landed |
| 8 | HTTP auth on the private surface | NIP-98 / NWT (PR #2187) | no NIP-98 surface anywhere | **N-A** | — |
| 9 | Deletion / vanish claim freeing | NIP-09 / NIP-62 | implemented with cutoff + relay targeting | **CONFORMANT** | — |
| 10 | NIP-11 `private_repos` advert | NIP-11 | custom top-level object, no `limitation` | **CONFORMANT-BY-EXTENSION** + **ADOPT** companions | P3 |
| 11 | Kind-number registration | nips `README.md` kind table | all 7 unregistered — 3359/23359 now in use but still unminted | **ADOPT** (open a README-table PR) | v0.2 |
| 12 | kind-1059 semantic overload | NIP-59 | resolved — the 3 shaped-not-conformant uses are on 3359; 1059 keeps only the genuine gift wraps | **MIGRATED** to 3359 / 23359 — **SHIPPED both sides** | landed |

---

## 1. Blossom blob auth — kind 24242

**Emit** (`cord-core/src/events.rs:151-177`), **verify** (`src/grasp_p/blossom_auth.rs:102-207`),
**transport** (`cord-core/src/blob.rs:24-44` — passes the pre-built header through; header
construction is in `events.rs:172-175`, *not* in `blob.rs` as sometimes described).

BUD-11 MUSTs we satisfy today:

- kind is 24242 — `events.rs:169`; server rejects otherwise at `blossom_auth.rs:124-128`.
- `expiration` tag present and numeric — emitted `now+3600` at `events.rs:158,163-166`; server
  requires it and requires it to be in the future, `blossom_auth.rs:156-165`.
- `t` tag from the verb set — `events.rs:161` emits `upload`/`delete` (`events.rs:140-147`); server
  requires an exact match against the operation, `blossom_auth.rs:145-154`.
- `x` tag, 64 lowercase hex, present on upload and delete — `events.rs:162`; server
  requires it *and* requires it to equal the sha256 actually being operated on
  (`verify_auth_shape` in `blossom_auth.rs`), which is stricter than BUD-11 requires. The `list`
  authorization (2026-10) carries no `x`, as BUD-11 has it.
- id + signature are verified server-side (`blossom_auth.rs:130-134`) — these routes sit outside the
  relay pipeline, so nothing else would.

BUD-11 MUSTs we **violate or omit**:

- **`content` is empty.** `EventBuilder::new(Kind::Custom(24242), "")` — `events.rs:169`. BUD-11
  requires human-readable content. The server does not check it either.
- **No `server` tag.** The tag list at `events.rs:160-168` has none, and `blossom_auth.rs` never
  looks for one. BUD-11's repeated lowercase-domain `server` tags are its replay-across-servers
  mitigation; absent on both sides, a 24242 minted for node A is replayable at node B for the same
  sha. Our `a` tag limits the blast radius to the same `(tenant, alias)` but not to the same host.
  A `list` authorization has neither `x` nor `a`, so nothing narrows it: one signed by key K for
  any Blossom server opens K's whole list on every GRASP-P node, as often as it is presented,
  until its `expiration` passes or its `created_at` is 24 h old, whichever comes first (48 h
  after signing at most, for an event post-dated by the full window). It is read-only, and only K
  can mint one.
- **Base64, not base64url (server half closed 2026-10, issue 14).** Client encodes
  `BASE64_STANDARD` (`events.rs:174`), which BUD-11's `Authorization: Nostr <base64url-no-padding>`
  does not allow. The server decoded `BASE64_STANDARD` only until 2026-10; it now accepts standard
  base64 and base64url, padded or not (`decode_token` in `src/grasp_p/blossom_auth.rs`), so a
  conformant third-party Blossom client is no longer refused over the alphabet. Still unmet: the
  client emitting base64url.

Extra requirements we impose beyond BUD-11 (interop hazards for third-party clients, not violations):

- **Mandatory `a` tag `30640:<tenant-hex>:<alias>` on upload and delete** (the `list`
  authorization carries none) — `blossom_auth.rs:182-200`, emitted at
  `events.rs:159,167`. This is what makes multi-tenancy work: it attributes the upload to a
  registration whose `w` set is then checked against the signing key — enforcement at
  `src/grasp_p/mod.rs:907-916` (tenant match `:907-911`, `w`-set membership `:912-916`; `:889-892`
  is only the rustdoc header).
  **KEEP-BESPOKE**, documented as a GRASP-P extension.
- **±24 h `created_at` window** — `blossom_auth.rs:15,136-143`. BUD-11 relies on `expiration` alone;
  a conformant client with a long-dated auth and a skewed clock gets a 401 from us.
- **`list` signer must be the pubkey in the path** — `authorize_list` in
  `src/grasp_p/blossom_auth.rs`. BUD-11 does not say whose token may list whose blobs; a client
  listing another pubkey gets the same 401 as an anonymous one.
- Scheme prefix accepted for exactly the two literal spellings `Nostr `/`nostr `
  (`blossom_auth.rs:77-79`, `:112-114`) — *not* case-insensitive: `NOSTR ` is rejected 401. Lenient
  enough to be harmless, strict enough to be worth stating.

Route coverage vs the BUD split:

| Route | Ours | BUD |
|---|---|---|
| `GET /<sha256>` | `src/http/blossom.rs:212` — public, unauthenticated **by design** | BUD-01 |
| `PUT /upload` | `src/http/blossom.rs:111` | BUD-02 |
| `HEAD /upload` | `src/http/blossom.rs:67` | BUD-06 preflight |
| `DELETE /<sha256>` | `src/http/blossom.rs:278` | **BUD-12** |
| `GET /list/<pubkey>` | `handle_blob_list` in `src/http/blossom.rs` — needs a kind-24242 `t=list` authorization signed by the listed pubkey (`authorize_list` in `src/grasp_p/blossom_auth.rs`); every refusal is one identical 401 | **BUD-12**, marked *unrecommended* |
| `PUT /mirror`, `/media` | not implemented | BUD-04 / BUD-05 |

DELETE and `/list` have moved to BUD-12 and `/list` is now marked unrecommended upstream; we should
cite BUD-12 rather than BUD-02 for both. Our `/list` took no `Authorization` at all until
2026-10 — see gap C below, now closed.

Client-side coverage is narrower than the server's: `blob.rs` implements only `put`, `get`, and an
`exists` that issues a **full GET** (`blob.rs:69-71`). No DELETE, no BUD-06 `HEAD /upload` preflight.

**Verdict.** ADOPT: emit base64url-no-padding (the server accepts both since 2026-10); emit a
human-readable `content`; emit and verify `server` tags. KEEP-BESPOKE: the `a` tag, as a documented GRASP-P
extension for multi-tenant attribution.

## 2. Blob and manifest encryption vs NIP-44

`cord-core/src/crypto.rs`. Blobs: fresh random 32-byte key + fresh random 96-bit nonce per blob,
ChaCha20-Poly1305, wire = `nonce(12) || ct||tag`, `blob_id = sha256(wire)`
(`crypto.rs:151-174`, framing at `:209-229`). Manifests: same framing under
`HKDF(salt="cord-git/manifest/v1", ikm=state_key)` (`crypto.rs:176-207`). Channel seals derive the
same way (`crypto.rs:94-110`).

NIP-44 v2 is ECDH-conversation-key oriented, base64-payload oriented, and event-`content` oriented.
Our blob layer is none of those: the key is per-blob random (deliberately non-convergent —
`crypto.rs:265-277` asserts it), the payload is raw bytes streamed to an HTTP body, and the
ciphertext is *content-addressed* (`blob_id = sha256(wire)`) because the server's blob identity is
the sha of exactly the bytes PUT. NIP-44 v2's extended length prefix (up to ~4 GB) removes the size
objection, but not the shape mismatch: adopting it would mean inventing a recipient keypair per blob
purely to satisfy an ECDH step whose output we would then have to re-derive per pack anyway.

**Verdict: KEEP-BESPOKE.** NIP-44 stays the right tool for the per-member rekey slots (item 4), which
*are* pairwise; it is the wrong tool for streamed content-addressed bulk. Document the AEAD framing
normatively in the spec so a second implementation is possible.

See gap E: manifest/collab/guestbook/rekey seal keys are **long-lived fixed keys with random 96-bit
nonces**, unlike the per-blob case.

## 3. Invite bundles (3313) and guestbook joins (3314)

**3a — invite is a genuine NIP-59 gift wrap.** `wrap_invite` (`invite.rs:233-243`) generates a fresh
`Keys::generate()` ephemeral signer, builds the kind-3313 rumor unsigned under that ephemeral pubkey,
and hands it to `nostr::nips::nip59::GiftWrapBuilder` — so the kind-13 seal and the kind-1059 outer
are produced by the upstream NIP-59 implementation, not by us. Unwrap verifies the outer signature
*before* decrypting (`invite.rs:248-249`) and delegates the seal to `UnwrappedGift`
(`invite.rs:253-254`). Promotions take the identical path (`invite.rs:314-335`). Test asserts no
tenant pubkey and no secret appears in the wrap JSON (`invite.rs:534-538`).

The **rumor kind** 3313 is custom. NIP-17 explicitly says the gift-wrapped rumor "could also be a
different kind" than 14, and Marmot's 444/446 rumor kinds are precedent. **KEEP-BESPOKE.**

**3b — delivery discovery.** NIP-17's kind-10050 DM-relay list is the standard way to find an
invitee's inbox. We do not implement it: grep for `10050` across `crates/` returns a single comment
in `crates/inbox-relay/Cargo.toml:8`. Today the inviter must be told the invitee's inbox relay
out-of-band. **ADOPT** — this is pure gain, costs the server nothing, and is what makes invites work
without a side channel.

**3c — the guestbook Join is *not* a gift wrap.** `build_join` (`invite.rs:355-375`) builds a
kind-**3359** event directly via `EventBuilder` (`invite.rs:371`, `KIND_STREAM_WRAP` =
`cord-core/src/events.rs:41`), with:
- content = base64 of a **symmetric** ChaCha20-Poly1305 envelope under a `#collab`-derived seal key
  (`invite.rs:364-366`), not a NIP-44 ciphertext;
- **no `p` tag** — there is no recipient pubkey; the addressing is by *author*;
- a signer that is **deterministically derived and shared by every member**
  (`crypto::derive_guestbook_keys`, `crypto.rs:79-92`), not the one-time random key NIP-59 requires;
- no kind-13 seal layer.

It does keep NIP-59's past-tweaked timestamp discipline (`Timestamp::tweaked(0..172_800)`,
`invite.rs:372`).

**MIGRATED to kind 3359 — shipped** (client `eb1e5e2`, server `c5301bb`); rationale and the full
argument in item 12. *Historically*, this rode the 1059 *number* to reach the server's existing
admission path for opaque encrypted streams — a semantic overload of a NIP-59 kind that read to a
reviewer as squatting it. The wire shape is unchanged apart from the number: kind + past-tweaked
`created_at` + base64 AEAD content, no tags. The join READ moved with the emit (`invite.rs:422`).

**Security note (not a NIP question).** The invite bundle carries **no inviter authentication**: the
rumor is authored by the throwaway ephemeral key (`invite.rs:237-238`), so `unwrap_invite` proves
only "someone who knew your npub sent this", never "the owner sent this". The self-certifying
community-id check (`invite.rs:158-161`) binds `(tenant_pub, owner_salt) → community_id` but a
forger can pick their own tenant. Client backlog issue !17. Flagged here because a standards reader
will ask.

## 4. Rekey wraps — inner 3303, per-member NIP-44 slots, outer 3359

`cord-core/src/rekey.rs`. **NIP-44 usage is correct and idiomatic:** each slot encrypts with a
**freshly generated ephemeral key** to the member's own npub via
`nip44::encrypt(eph.secret_key(), member_pub, payload, nip44::Version::V2)` (`rekey.rs:327-335`),
and decrypts with `nip44::decrypt_to_bytes(member_keys.secret_key(), &eph_pub, &ws.ct)`
(`rekey.rs:492-493`). Slots are located by an opaque `hint` — **plain SHA-256, not HKDF**:
`sha256("cord-git/rekey-slot/v1" ‖ 0x00 ‖ prior_root ‖ scope_id ‖ epoch_le ‖ member_xonly)`
(`rekey.rs:61,221-230`) — so member npubs never appear on the wire; test asserts this
(`rekey.rs:646`). **CONFORMANT.**

Timestamp discipline: the outer wrap is past-tweaked, `Timestamp::tweaked(0..172_800)`
(`rekey.rs:368`), matching NIP-59's SHOULD.

**4b — the outer wrap had the same overload as 3c, and moved with it.** `rekey.rs:367-369`: kind
**3359**, content base64 of a symmetric envelope under `rekey_seal_key` (`rekey.rs:207-215`), signed by the derived
rekey-pseudonym address key (`rekey.rs:183-191`), **no `p` tag, no kind-13 seal, not NIP-44**. The
authenticity root is the *inner* 3303's tenant signature (`rekey.rs:355-360`, enforced at
`rekey.rs:430-432`) precisely because every member can derive the outer key. Correct design for the
threat model, but again: not a NIP-59 gift wrap.

**MIGRATED to kind 3359** alongside 3c and 5c — item 12; read side at `rekey.rs:411`. Note that this
signed inner rumor is exactly why full NIP-59 conformance was *impossible* here, not merely
inconvenient (item 12) — which is what made a fresh kind the only coherent outcome.

## 5. `#collab` (issues / PRs) vs NIP-34 / NIP-22

`cord-core/src/collab.rs`. The inner rumors are **literal upstream kinds**, signed by the author's
real identity key: 1621 issue, 1111 comment, 1617 patch, 1630/1631/1632/1633 status
(`collab.rs:47-59`, gated by `is_collab_kind` at `:69-80`, built at `:159-161`). Raw rumor bytes are
retained verbatim (`collab.rs:162,176`) so a future flip-public can republish them with
ids/threading/signatures intact.

**This is a deliberate interop choice**: reusing upstream NIP-34/NIP-22 kinds *inside* the encrypted
envelope means a private repo that later goes public becomes a normal NIP-34 repo with no
translation layer, and any NIP-34 client can render the republished history.

Binding tags on the inner rumor are `a` = `30617:<tenant>:cg-<community_id>`, `channel`, `epoch`
(`collab.rs:132-144`). Note the `a` coordinate references kind 30617 as a *string* — no 30617 event
is ever published (see item 6).

**5b — `KIND_SEAL = 20013` is not a wire kind.** `collab.rs:61` declares the const; the only other
occurrences in the entire client are doc comments (`collab.rs:10`, `:12`, `:164`) — verified by grep
across `crates/`. No kind-20013 event is ever constructed. The "seal" is realized as the symmetric
AEAD envelope inside the outer wrap's content (`collab.rs:164-167`). **It therefore needs no kind
registration and there is nothing to reconcile against NIP-59's kind 13.** Stated explicitly because
a reviewer scanning for kind constants will otherwise flag it. Consider deleting the const.

**5c — the outer wrap was the third 1059 overload, and moved with the other two.**
`collab.rs:164-176` builds the same shape as 3c and 4b: kind-**3359** (`collab.rs:171`), base64
symmetric AEAD under `collab_seal_key`, no `p` tag, no kind-13 seal, signed by the derived `#collab`
stream key. **MIGRATED to kind 3359** — item 12; read side at `collab.rs:315`. The inner rumors kept
their upstream NIP-34/NIP-22 kinds; only the outer number changed.

## 6. Discovery — kind 10318 and the opt-in `["private","true"]` 30617

**Neither is implemented.** Grep across `crates/` for `10318` returns zero hits. Grep for `30617`
returns only the `a`-coordinate string construction (`collab.rs:22-23,132-134`) — never an
`EventBuilder` for kind 30617. The server handles `Kind::GitRepoAnnouncement`
(`src/nostr/builder.rs:884`), but that is the public GRASP path, unrelated to GRASP-P.

GRASP-08's kind 10318 carries `g` tags as **NIP-51 private items** — a stringified JSON array
mimicking the tags array, NIP-44-encrypted to the author's own key, in `.content`. That mechanism is
entirely client-side: the server stores an opaque replaceable event. **Compatible with the
content-blind invariant. ADOPT at P3.**

**Metadata-leak delta of the opt-in `["private","true"]` 30617.** Today an observer of a GRASP-P node
learns `hosting npub → random 32-hex alias → registered w/aux pubkeys → blob hashes/sizes/timing →
epoch lineage`, and nothing links the alias to a human-meaningful repo. Publishing a 30617 marked
private additionally reveals, **by construction**: that the pubkey hosts a repo at all, the repo's
`d` identifier and any `name`/`description`/`clone`/`relays` tags the announcement carries, the
maintainer set in `maintainers` tags, and a stable public coordinate that can be correlated across
relays and over time. That is the whole point — it makes a private repo *findable* — but it converts
"an opaque alias exists" into "this named repo, owned by these people, exists and is private". This
is why it must stay **opt-in per repo**, never a default, and why the alias-only mode has to remain
fully supported.

## 7. NIP-42 AUTH

**7 — client side: not implemented. ADOPT.** `cord-core/src/relay.rs` handles `OK`
(`:50-62`), `EVENT` (`:103`), `EOSE` (`:110`), `CLOSED` (`:114`), `NOTICE` (`:123`), `Ping`
(`:64,134`) — an inbound `["AUTH", <challenge>]` falls into the catch-all `_ => {}` at `:131` and is
silently dropped. No kind-22242 event is constructed anywhere in `crates/` (grep: zero hits). A
relay that AUTH-gates simply makes our fetch fail: `CLOSED` with an `auth-required:` prefix surfaces
as an opaque error string (`relay.rs:114-122`).

Needed for two reasons: GRASP-08 composition (an 08 deployment may gate reads), and NIP-59's SHOULD
that relays serve 1059 only to the p-tagged recipient — which is how the *invitee's own inbox relay*
is expected to behave when we fetch invites (`relay.rs:171-174`).

**7b — server side: we deliberately do NOT AUTH-gate stored stream wraps. N-A: the item-12 migration
has landed, so no NIP-59 relay rule reaches our wraps at all.** This is a deliberate property, not an
oversight — but be precise about what is *tested*. **G3 pins the substrate property that ngit-grasp's read path applies no NIP-42/p-tag guard
to stored kind-1059 events**: `tests/phase0_gates.rs:11` names it "no hidden read guard on stored
kind-1059 gift wraps", and `:452-512` asserts an anonymous client that never AUTHs **must** be served
a stored wrap, both via `kinds=[1059]` and via a bare `ids=[…]` filter.
`src/bin/ngit-private-watchdog.rs:954` fails with "GRASP-P anonymous reads must not require NIP-42
auth".

**G3 does not exercise the wraps we actually emit.** Its fixture is a **p-tagged and `a`-tagged**
wrap (`["a","30617:<hex>:<d>"]`, added expressly "to satisfy the related-events write policy" —
`phase0_gates.rs:24-25`), admitted through the **public** related-event policy on a relay started by
`TestRelay::start()` (`phase0_gates.rs:453`) = `RelayOptions::default()` (`tests/common/relay.rs:120-122`),
which does **not** set `NGIT_GRASP_P_REPOS_ENABLE` (default `false`, `src/config.rs:613`; only
`start_with_private_repos` / `start_private_pair_node` set it). The private wrap admission arm
(`src/nostr/builder.rs:832-861`) therefore never runs, and the assertion at `:463` is that the relay
accepts the **a-ref'd** wrap. Real GRASP-P stream wraps are **tagless** (item 12) and admitted only
by outer-author key claim. **That gate has since been written, as the migration required
(`tests/private_repos.rs:4822` `assert_tagless_wrap_admitted`)**: private repos enabled, a registered
outer author, an assertion that the fixture carries NO tags at all, then the full contract —
admitted, quota-charged exactly its event bytes, stored, and served to a never-AUTHed anonymous
reader. It runs on **both** wire kinds: `exit36_tagless_stream_wrap_legacy_kind` (`:4881`, kind 1059
under the dual-accept default) and `exit39_tagless_stream_wrap_new_kind` (`:4892`, kind 3359).
`exit37` (`:4900`) additionally pins §3.2 gating and non-storage on 3359/23359, and `exit38`
(`:4996`) pins that the legacy kinds can be retired. This section is where we ask to be excused from
a NIP-59 SHOULD, so it will be scrutinised hardest; the paragraphs below record what the *older*
gates do and do not cover, because a reviewer who finds G3 first will otherwise over-read it.

**The nearest neighbour is `exit3_wrap_admission` (`tests/private_repos.rs:633`) — name it, because
a hostile reviewer will find it.** Unlike G3 it *does* run the private arm: private repos are
enabled (`:636`, `start_with_private_repos`), the wrap is signed by the **registered write key**
(`:653`), and `:659-669` asserts the stored wrap is served to a **completely anonymous** client
(`connect_anonymous_client`, no AUTH) — which is exactly the anonymous-read property 7b claims, on
the private admission path. What it does **not** cover is the shipped wire shape: its fixture
`wrap_event` (`:218-227`) attaches `Tag::public_key(recipient)`, so the event is **p-tagged**, not
tagless. So exit3 closes the "private arm + anonymous read" half and leaves the "tagless" half open.
That remaining half is what exit36/exit39 now close — they are, as predicted, tagless variants of
the exit3 fixture.

Rationale for the divergence itself: GRASP-P's stream wraps are addressed by *author* (derived
stream/rekey keys), not by `p` tag, so the p-tag serving rule has no target to filter on; and
content-blind replication (negentropy sync between nodes, `phase0_gates.rs:379,427`) depends on wraps
being anonymously readable. Confidentiality never rests on read-gating — that is stated normatively
in `CORD-git-v0-spec.md:14-18`.

**The migration retired this divergence rather than declaring it.** NIP-59's relay SHOULD binds kind
1059; now that the three stream wraps are kind 3359 (item 12), no NIP-59 relay rule applies to them
and there is nothing to except ourselves from. The only 1059s we still touch are genuine
gift-wrapped invites and promotions, which live on the *invitee's inbox relay* and where AUTH-gating
is the expected, desired behaviour — that is precisely what item 7 (client AUTH) exists to satisfy.
One residual survives the migration: while `NGIT_GRASP_P_ACCEPT_LEGACY_WRAP_KIND` is true (the
shipped default, `src/config.rs:767`) the node still admits and anonymously serves 1059 stream
wraps, so the exemption argument still has to be made for the length of the legacy window — it is
the window, not the design, that keeps it alive. **Historical note on G3, still accurate:** its
fixture builds a p-tagged, a-tagged `Kind::GiftWrap` (`phase0_gates.rs:461`). Retiring 1059 did not
make that fixture cover 3359 — the new gate had to be *written*, not re-pointed, and G3 stays on
1059 as what it actually is: a characterization of the upstream public read path.

The server does implement NIP-42 as a *client* when syncing outbound
(`src/sync/relay_connection.rs:371`).

## 8. NIP-98 / Nostr Web Token — N-A

Grep for `27235` and `nip98` returns zero hits in both `src/` (server) and `crates/` (client).
Correct: the only authenticated HTTP surface in the private model is the Blossom blob route, and that
is Blossom's own kind 24242 (item 1). There is no plaintext git-smart-HTTP surface in GRASP-P — the
private data plane is blobs plus relay events, and `GET /<sha256>` is unauthenticated by design
(`src/http/blossom.rs:212`).

NWT (kind 27519) exists only in the **still-open, still-unnumbered** nips PR #2187 and must not be
cited as an existing standard. Both NIP-98 and NWT become relevant only if a future GRASP-08 server
mode exposes an authenticated HTTP surface. **N-A today.**

## 9. NIP-09 / NIP-62 — deletion and vanish claim freeing — CONFORMANT

This is us *consuming* two NIPs, not hand-rolling. The backend's built-in auto-processing is disabled
(`src/nostr/builder.rs:1028-1038,1059`) so the policy layer can run its own gate, and tombstones
persist across restarts (`builder.rs:749-758,970`).

- **kind 5 (NIP-09):** `builder.rs:899-912` — on an author-valid, honored deletion, GRASP-P frees the
  registration's key claims. Without this, dangling claims wedge future rotations with
  "write key already registered".
- **kind 62 (NIP-62):** `builder.rs:914-928` — freeing runs only when the vanish is `Accept`ed, the
  node actions deletions, **and** `vanish_targets_this_relay(event)` is true. That helper
  (`src/nostr/lifecycle/deletion/service.rs:455-467`) delegates to
  `nip62::is_valid_vanish_request_for_relay`, checking every `RelayUrl` candidate derived from the
  configured domain and falling back to `ALL_RELAYS`-only matching when the domain yields no valid
  `RelayUrl` (`:458-462`). **Relay-targeting requirement: satisfied.**
- **`created_at` cutoff:** both paths pass the death event's `created_at` as `max_created_at` into
  `free_registration_claims` — kind 5 at `src/grasp_p/mod.rs:792` (cutoff) with the calls at `:824`
  (`a` coordinate) and `:835` (`e` id), vanish at `:863`/`:868` — which returns 0 without freeing anything
  when `record.created_at > max_created_at` (`mod.rs:1293-1295`). A replayed stale vanish or deletion
  therefore cannot wipe a *re-registered* newer edition. **Cutoff: satisfied.** Documented at
  `mod.rs:853-860`.

**CONFORMANT.** Consuming these NIPs correctly requires no decryption and no NIP-44/59 linkage.

## 10. NIP-11 advert — `private_repos` + `policy_fingerprint`

`RelayInformationDocument.private_repos: Option<serde_json::Value>` (`src/http/nip11.rs:58-59`),
populated from config at `nip11.rs:147` via `private::nip11_private_repos_from_config`
(`src/grasp_p/mod.rs:1610-1622`), which emits `kinds`, `registration_mode`, `max_blob_bytes`,
`max_event_bytes`, `quota_tenant_bytes`, `quota_repo_bytes`, `blob_endpoints`, `policy_fingerprint`,
`policy_version`, and `pow_bits` when in PoW mode (`mod.rs:1564-1601`). Absent entirely when private
repos are disabled (`mod.rs:1611-1613`).

**`policy_version` (`mod.rs:1596`, value `grasp-p-policy-v3` from `mod.rs:326`) is new since the
first revision of this inventory.** It publishes the `policy_fingerprint` PREIMAGE-FORMAT label
verbatim beside the digest, because the digest alone cannot distinguish the two very different
reasons a pair's fingerprints differ: a version skew mid-rolling-upgrade (every node's digest moves
on a label bump) versus a same-version knob split, which is a real and lasting divergence in what
the two nodes accept. Not a NIP question — NIP-11 permits the field — but it is part of the advert a
standards reader will enumerate.

**The advertised `kinds` array moved with item 12, and now cannot drift.** `mod.rs:1577-1579` builds
it from the *same* helpers the admission arms and sync filters use
(`stream_wrap_kinds`/`ephemeral_stream_wrap_kinds`, `mod.rs:94-110`), so "what we advertise", "what
we admit" and "what we ask peers for" are one definition. Today that yields 30640, 30641, 3359,
23359, plus 1059 and 21059 for as long as `NGIT_GRASP_P_ACCEPT_LEGACY_WRAP_KIND` (the transitional
window, on by default) is set. This array is the natural discovery signal for "does this node speak
GRASP-XX".

NIP-11 registers no extension convention beyond "clients MUST ignore fields they do not understand",
so a custom top-level object is legal. The comment at `nip11.rs:55-57` correctly keeps the Blossom
BUDs out of `supported_nips` — they are HTTP-side, not NIPs. **CONFORMANT-BY-EXTENSION.**

**ADOPT the standard companion signals.** The document has **no `limitation` object at all** — the
struct fields are enumerated at `nip11.rs:13-59` and none is `limitation` (gap D). An 08-composed
deployment that AUTH-gates reads or restricts writes must set `limitation.auth_required` and
`limitation.restricted_writes`; without them a conformant client cannot tell why its REQ was closed.
Adding `limitation` is orthogonal to the content-blind invariant.

## 11. Kind-number registration status

**There is no machine-readable kind registry.** The de-facto registry is the **kind table in
`README.md`** of nostr-protocol/nips; registering a kind means opening a PR that adds a row to that
table. No schema file, no YAML, no JSON: the repo's master tree is 99 files and **every one of them
is a `.md`** (verified 2026-07-28).

**The README table lags the NIP text and is not authoritative on its own.** Two live
counter-examples: kind `10317` (NIP-34 user grasp list) is defined at `34.md:243` but has **no row**
in the README table, and `21059` (ephemeral gift wrap) is defined at `59.md:77` with no README row
either. A README-only grep therefore returns **false "free" results** for both. The only sound
method is a full-corpus grep.

> **Provenance.** Freeness below was verified against the **full nips corpus** (all 99 `.md` files of
> nostr-protocol/nips master) on **2026-07-28**. Method: fetch the whole repo, grep every `.md` for
> the bare number. Re-run before filing — this is a point-in-time snapshot.

| Kind | Use | Defined at | Corpus status |
|------|-----|------------|---------------|
| 30640 | registration | `src/grasp_p/mod.rs:43`, `cord-core/src/events.rs:152` | free — 0 occurrences |
| 30641 | state root | `src/grasp_p/mod.rs:44`, `cord-core/src/events.rs:182` | free — 0 occurrences |
| 3313 | invite + promotion rumor | `cord-core/src/invite.rs:39` | free — 0 occurrences |
| 3314 | guestbook Join rumor | `cord-core/src/invite.rs:41` | free — 0 occurrences |
| 3303 | rekey rumor | `cord-core/src/rekey.rs:45` | free — 0 occurrences |
| **3359** | **CORD stream wrap** — **now in use** (item 12) | `src/grasp_p/mod.rs:58`, `cord-core/src/events.rs:41`; emitted at `invite.rs:371`, `collab.rs:171`, `rekey.rs:367` and read at `invite.rs:423`, `collab.rs:315`, `rekey.rs:411` — see the const-split hazard below, which is now the *shipped* shape | free — 0 occurrences; **still unminted** |
| **23359** | **ephemeral stream wrap**, reserved | `src/grasp_p/mod.rs:62`; server admission capability only, no client emits it | free — 0 occurrences; **still unminted** |

Numbers confirmed **taken** in the same sweep, for contrast: `1059` (`59.md`, Gift Wrap — also
`17.md`, `45.md`, README), `21059` (`59.md:77`), `10317` (`34.md:243`), `24242`
(`README.md:237`, attributed to `B7.md`).

**Absent from the corpus but *not* available.** A zero-hit grep is necessary, not sufficient — three
numbers we must avoid do not appear in nips at all: Marmot's `30443`/`444`/`445`/`446`, whose spec
lives at `github.com/marmot-protocol/marmot`, and `27519` (Nostr Web Token), still an unmerged nips
PR #2187 (item 8). Check external specs and open PRs before treating a free number as mintable.

Not requiring registration: 1059 (NIP-59 — since item 12 landed it is retained only for genuine
gift-wrapped invites and promotions, plus the transitional legacy stream-wrap window on the server),
24242 (Blossom BUD-11), 1621 / 1111 / 1617 / 1630-1633 (NIP-34 / NIP-22, reused verbatim), 1984
(NIP-56 reports, `src/grasp_p/mod.rs:47`), and **20013** (item 5b — never constructed).

**Why the rumor kinds are on this list.** 3313 / 3314 / 3303 are sealed inside an AEAD or NIP-59
layer and never appear in plaintext on a relay, and NIP-17 explicitly sanctions arbitrary rumor kinds
(Marmot's 444/446 are precedent). They are registered anyway because **flip-public makes them
public**: a repo that goes public republishes retained rumor bytes verbatim (`collab.rs:162,176`), so
3314 Joins would someday be openly published. Register them in the same PR as 3359/23359.

**Near-neighbour warnings — this range is actively being consumed.** 10317 "User grasp list" was
recently allocated to NIP-34 and we already handle it (`src/nostr/builder.rs:889`), one number below
GRASP-08's 10318 (which is itself corpus-free today). Marmot took 30443 (KeyPackage), 444 (Welcome),
445 (Group Event) and 446 — none of which appear in the nips corpus, which is exactly why the
corpus grep alone is not a sufficient test. NIP-EE is now `final unrecommended`, superseded by
Marmot. Our 3313/3314/3303/3359 cluster sits in a sparse but unreserved band.

**ADOPT: open a PR against nostr-protocol/nips adding rows to the kind table in `README.md`** for all
seven (30640, 30641, 3313, 3314, 3303, 3359, 23359) before publishing the proposal. Re-run the
full-corpus grep at filing time — the table above is a 2026-07-28 snapshot, and the README table's
own lag means a row's absence there proves nothing. **This is now the only unfinished half of item
12:** 3359/23359 are on the wire in both implementations while still unminted upstream, so the
window in which someone else could claim the numbers is open and running. Filing is no longer
optional tidying.

## 12. SHIPPED — the kind-1059 overload: stream wraps migrated to kind 3359

**Verdict: MIGRATED — landed on both sides** (server `c5301bb`, client `eb1e5e2`). The three
non-NIP-59 stream wraps — guestbook Join (`invite.rs:355-375`), `#collab` (`collab.rs:164-176`),
rekey (`rekey.rs:367-369`) — moved off kind 1059 onto a single new **regular** kind **3359**, "CORD
stream wrap", with **23359** as its ephemeral analog. Genuine NIP-59 wraps stayed on 1059:
`wrap_invite` (`invite.rs:236-245`, kind-3313 rumor) and promotions (`invite.rs:334`) really are
`GiftWrapBuilder` output and were unaffected.

**Transitional window on the server, not in the protocol.** `NGIT_GRASP_P_ACCEPT_LEGACY_WRAP_KIND`
(`src/config.rs:746-767`, default **true**) keeps 1059/21059 admissible alongside 3359/23359 so a
node accepts the new kind before any client emits it and pre-migration wraps keep draining; it is in
the `policy_fingerprint` preimage (v3) because it is direct acceptance behaviour. Setting it false
retires the legacy kinds with `restricted: legacy stream-wrap kind is not accepted on this node`
(`src/nostr/builder.rs:889-910`) rather than letting them fall through to the public related-event
path, which would be *wider* than the default. The client took **no** dual-kind read window
(`relay.rs:216-236` documents why: no production repo predated the migration), so pre-migration
stream wraps are simply unreadable — a deliberate, operator-confirmed data loss of nothing.

The hazard notes below are kept as **history**: they describe what the migration had to get right,
and they are the explanation for why the code is shaped the way it is now.

**One kind, not three, and no discriminating tag.** The server dispatches wraps purely by outer-author
key claim (`find_claim`, `src/grasp_p/mod.rs:661`) and never by stream type — it deliberately cannot
see into them. The client disambiguates by outer signer too: guestbook and `#collab` via
`ring.match_author` (`invite.rs:426`, `collab.rs:323`), rekeys via the locally derived address key
(`rekey.rs:415`). Nothing on either side needs to be told which stream a wrap belongs to, so a `type`
tag would be a **privacy regression**: it would let an observer cheaply label which wraps are rekeys
and which are collab traffic, which the current tagless shape denies them. **Wire shape is unchanged
apart from the number:** kind + past-tweaked `created_at` + base64 AEAD content, no tags.

**Migration hazard (HISTORICAL, and it is why the code looks the way it does) — `KIND_WRAP` was
three constants, one of them dual-purpose. It had to be SPLIT, not retargeted.** The client declared
`KIND_WRAP = 1059` three times: `invite.rs:36`,
`collab.rs:63`, `rekey.rs:46`. The latter two are stream-wrap-only and can be retargeted wholesale.
**`invite.rs:36` cannot**: the same const gates the *genuine* NIP-59 path — `unwrap_3313`'s outer
kind check at `invite.rs:250`, which serves both invites (`wrap_invite`, `:233`) and promotions
(`:314-335`) — **and** the guestbook join, which emits at `:368` and reads at `:419`. Flipping that
one number to 3359 would silently make every real gift-wrapped invite fail to unwrap ("not a gift
wrap"), with no test in the migration's own path to catch it. Invite/promotion keep 1059; the join
moves to 3359, which means `invite.rs` needs **two** constants and the join READ must move with the
emit. **How it was resolved:** the three per-module constants were replaced by exactly two, hoisted
into one module — `KIND_STREAM_WRAP = 3359` (`cord-core/src/events.rs:41`) and
`KIND_NIP59_GIFT_WRAP = 1059` (`:55`) — each carrying a doc comment stating why it is not the other,
and `events.rs:55-56` explicitly forbids re-merging them. `invite.rs:35` now imports both: the
gift-wrap check stays on 1059 (`:253`) while the join emits (`:371`) and reads (`:423`) on 3359.

Migration is also not confined to construction sites: the REQ filters that name the kind move too —
`repo.rs:1404`, `repo.rs:2086` and `crates/cord-git/src/main.rs:793` all build `kinds:
[rekey::KIND_WRAP]`, and a filter left on 1059 fetches nothing after the switch while failing
loudly nowhere. Test fixtures asserting the outer kind (`invite.rs:534,623,634,692`;
`collab.rs:686,769`) must be split the same way, or they will keep passing against the wrong number.

**Second hazard (HISTORICAL) — the two stream READ paths were invisible to a `KIND_WRAP` grep,
because they used a bare integer literal.**
Those three filter sites are all the *rekey* read path. The reads that actually serve the migrating
streams (items 3c and 5c) live in `crates/cord-core/src/relay.rs:190`, where `wraps_by_authors`
builds `{"kinds": [1059], "authors": …}` as a **literal `1059`**, not `KIND_WRAP` — so any grep
built on the constant misses it entirely. It must move to 3359. Its two callers are the guestbook
and `#collab` read paths: `repo.rs:421` (`roster()` — Joins) and `repo.rs:561` (`collab_threads()`
— issues/PRs). **Consequence if missed:** joins and collab rumors would be EMITTED at 3359
(`invite.rs:368`, `collab.rs:171`) but still FETCHED at 1059, so `cord-git roster`, `issue list`,
`pr list` and `show` would silently return **empty** — precisely the "fails loudly nowhere" mode
above.

**`relay.rs:172` MUST STAY on 1059.** In the same file, `giftwraps_for` builds `{"kinds": [1059],
"#p": …}` and fetches *genuine* NIP-59 gift-wrapped whispers — the invite and promotion inboxes
(`repo.rs:339` `join()`, `repo.rs:1912` `promote_accept()`, both feeding `unwrap_3313`). This is
the mirror image of the `invite.rs:36` const-split hazard: **within one file, one literal moves
(`:190`) and one must not (`:172`)**, and here neither is behind a named constant to make the split
reviewable. Retargeting both would break every real invite; retargeting neither would break roster
and collab reads. **How it was resolved:** both literals are gone. `giftwrap_filter`
(`relay.rs:183`) names `KIND_NIP59_GIFT_WRAP` and `stream_wrap_filter` (`relay.rs:237`) names
`KIND_STREAM_WRAP`, each split out as its own function so an emit-site test can assert the kind, and
each carrying prose stating which plane it belongs to and what breaks if it is changed
(`relay.rs:168-176`, `:186-236`). Every stream-wrap REQ is now required to build its filter through
`stream_wrap_filter`, including the multi-relay fetches in `repo::fold` and
`repo::ensure_no_existing_rekeys` that do not go via `wraps_by_authors`.

Cosmetic follow-up (no behaviour, but the docs would have gone stale at migration): the error
strings `"not a 1059 wrap"` and ~12 prose doc-comments naming 1059. **Done in the same commit**, and
better than asked: the three parsers now share one message builder,
`events::unexpected_stream_wrap_kind` (`events.rs:66-75`), called at `collab.rs:315`,
`invite.rs:423` and `rekey.rs:411`. It special-cases a 1059 outer with "legacy kind-1059 stream wrap
from before the 3359 migration; this client no longer reads it" — because the person most likely to
hit it is not an attacker but a member holding pre-migration history, whom a bare "wrong kind" tells
nothing.

**Ephemeral.** The client emits no ephemeral wrap at all — it has no constant for one. The kind
exists only as a server admission capability (`src/grasp_p/mod.rs:62`,
`src/nostr/builder.rs:889`), now numbered **23359**, with 21059 accepted only inside the legacy
window. The NIP-11 `kinds` array moved in the same commit (item 10) and can no longer drift from the
admission arms: both read the set from `ephemeral_stream_wrap_kinds` (`mod.rs:104-110`). The spec
declares 23359 **reserved, unused by the reference client** (`CORD-git-v0-spec.md` §2.3).

**Why riding 1059 was not defensible.** This is the decisive argument, and it is now stated in the
GRASP-XX text (`grasp-xx-draft.md`, "Why not kind `1059`"): riding 1059 bought nothing we actually
had.

- Our stream wraps are **tagless**, and vanilla ngit-grasp's related-event policy rejects tagless
  1059s as orphans (`src/nostr/builder.rs:701-717`); our own nodes reject 1059s from unregistered
  authors outright since MR !2. These wraps are therefore only ever admissible on **GRASP-XX-aware
  nodes anyway** — there is no population of vanilla relays quietly carrying them.
- No free relay-side handling is lost. Negentropy is kind-agnostic and driven by filters we build
  ourselves (`src/sync/filters.rs:96-110`). Existing clients fetch 1059 by `#p` for their own key,
  which a tagless wrap never matches.
- The cost is real and asymmetric: a relay that implements NIP-59's AUTH-gating SHOULD makes
  p-tag-less wraps **silently unservable to everyone**, because no recipient exists to AUTH as. Our
  design requires the exact opposite — characterized for the upstream read path by gate G3
  (`tests/phase0_gates.rs:452-512`) and, for our own tagless wrap shape, by exit36/exit39
  (`tests/private_repos.rs:4881,4892`); see item 7b. Sitting on 1059 would have meant one conformant
  upstream relay upgrade could black-hole a repo.
- Coexistence breaks: if GRASP-08 and GRASP-XX ever share a relay, kind 1059 would need two
  contradictory relay treatments at once — AUTH-gated for 08's p-tagged wraps, anonymously readable
  for ours. (This assumes 08 wraps with genuine NIP-59; **not verified against the 08 draft** — open
  question 1. The argument's force scales with that assumption, but the three points above stand
  without it.)

**Two corrections to claims made elsewhere in this document.**

1. **The NIP-59/NIP-09 deletion hazard does not apply to our wraps.** NIP-09 deletion of a gift wrap
   keys on a `p`-tag match; ours carry no `p` tag, so there is nothing to match. Not a risk we carry.
2. **Full NIP-59 conformance for these three is architecturally impossible, and the reason is *not*
   membership linkage.** The derived address pubkey already appears in the author field, so a `p` tag
   pointing at it would leak nothing new. The real reasons are structural: (a) NIP-59 rumors are
   definitionally **unsigned**, but our inner events must be **signed** — the tenant signature is the
   sole authenticity root for rekeys (`rekey.rs:355-360`, enforced at `rekey.rs:430-432`), and
   byte-exact signed rumors are what make flip-public possible for collab and join
   (`collab.rs:16-19`); and (b) NIP-44 to the derived address is decryptable by every holder of the
   derivable secret anyway — cryptographically equivalent to our symmetric AEAD, but with a
   per-recipient fan-out model that destroys the single-address stream. This impossibility is itself
   a strong argument **for** a fresh kind: we cannot converge on 1059's semantics even in principle.

**Inner rumor kinds are unaffected.** 3313 / 3314 / 3303 stay as they are — see item 11 for why they
are registered regardless.

---

## Conformance-adjacent findings

Not NIP questions, but a standards reader will surface them.

- **A. (closed 2026-10: the setting was removed; the never-to-the-git-node rule stays
  client-side only. The text below is the finding as it stood.)
  `NGIT_GRASP_P_ACCEPT_DIRECT_INVITES` is a dead knob.** Declared at `src/config.rs:740-741`
  (`default_value_t = false` on the `#[arg]` at `:740` — `:1420` is only the `Config::for_testing()`
  literal, `for_testing` starting at `:1344`), plumbed into `PrivateConfig` at
  `src/grasp_p/mod.rs:152` and `:215` — and **never read by any admission path**. The only other
  occurrence is a test fixture (`src/grasp_p/blob_store.rs:417`). The normative "never deliver to a
  git node" rule is therefore enforced entirely client-side, and by *two* separate guards, both of
  which reject when the target relay normalizes to one of the keystore's own node relays: the invite
  path at `cord-core/src/repo.rs:277-286` (module prose only at `invite.rs:6-8`) and — undocumented
  until now — the promotion path at `repo.rs:1869-1875`, which carries the `write_secret` and is
  therefore the higher-value leak of the two. The server-side switch the invite guard cites in its
  own comment (`repo.rs:278-279`) does nothing. Either wire it into admission or delete it — a
  documented safety control that is not enforced is worse than no control.
- **B. `KIND_SEAL = 20013` — see item 5b.** Comment-only const; delete or annotate.
- **C. (closed 2026-10, issue 14: the route now answers only the listed pubkey, with one
  identical refusal for everyone else. The text below is the finding as it stood.)
  `GET /list/<pubkey>` is fully unauthenticated.** `handle_blob_list`
  (`src/http/blossom.rs:297-311`) takes no `Authorization` parameter at all, and the route is wired
  with no auth check at `src/http/mod.rs:707-717` (inside the private-subsystem route block, so the
  only precondition is that private repos are enabled). Anyone can enumerate every blob descriptor a
  tenant holds: hashes, sizes, counts, and by extension push cadence. Blob *content* stays
  encrypted, but this is a strictly larger leak than "blob hashes/sizes/timing" observed per push —
  it makes them **queryable per tenant in one request**. The spec now discloses this in its
  normative leak enumeration (`CORD-git-v0-spec.md` §1) and marks the route public in §2.4; the two
  documents agree. BUD-12 marks `/list` unrecommended; consider requiring a 24242 with `t=list` and
  an `a` tag, or dropping the route.
- **D. No `limitation` object in NIP-11.** See item 10.
- **E. Long-lived fixed keys with random 96-bit nonces.** `encrypt_blob_random` is safe by
  construction — fresh key *and* nonce per blob (`crypto.rs:162-174`). But `manifest_key`
  (`crypto.rs:202-207`), `collab_seal_key` (`:105-110`), `guestbook_seal_key` (`:95-100`) and
  `rekey_seal_key` (`rekey.rs:208-216`) are **fixed for the lifetime of the channel key they derive
  from** — an entire epoch at minimum, and spanning multiple epochs when a rotation rekeys only the
  `write` scope (a demote), since `#state`/`#collab` are not rolled then (`repo.rs:1269-1284`:
  `state_key`/`collab_key` are `Option`s applied only when present, while `ks.epoch = p.new_epoch`
  is unconditional). Only `rekey_seal_key` is strictly per-epoch — its HKDF `info` includes
  `epoch_le32` (`rekey.rs:208-215`). Each message gets a random 96-bit
  nonce (`crypto.rs:114-118`). Collision probability is a birthday bound in 2^96 — fine
  at any realistic message volume, but it is an assumption an implementation inherits; XChaCha20-
  Poly1305 (192-bit nonce) would remove the analysis entirely. Now stated in the spec (§3, with the
  nonce width marked **[D]**); still worth deciding before the framing is frozen in a public
  proposal.
- **F. Binding-tag inconsistency between the two sub-streams.** Guestbook Joins bind with a native
  `cgc` tag (`invite.rs:356,460-474`); `#collab` rumors bind with the mandated `a`/`channel`/`epoch`
  tags (`collab.rs:138-144`). The code documents the divergence itself and defers reconciliation
  (`collab.rs:31-35`). Two conventions for the same job is a spec smell; reconcile before
  publication.
- **G. Client/server capability asymmetry on the blob surface.** The server serves BUD-06
  `HEAD /upload` (`src/http/blossom.rs:67`) and DELETE (`:278`); the client implements neither, and
  `exists()` costs a full body download (`cord-core/src/blob.rs:69-71`).

---

## Open questions

> **Resolved since the last revision.** "1059 overload: keep or mint our own kind?" is **shipped —
> MIGRATED to 3359/23359** on both sides (item 12). "Is the NIP-59 relay SHOULD applicable to
> author-addressed wraps?" is moot as a consequence: the migration took our stream wraps out of kind
> 1059 entirely, so no NIP-59 relay rule applies to them and no exemption is needed (item 7b) — with
> the one caveat that the transitional legacy window keeps 1059 admissible on our nodes until an
> operator closes it. The missing tagless admission gate that item 7b demanded has been written
> (`tests/private_repos.rs:4881,4892`). What remains open is upstream kind registration (item 11).

1. **Does GRASP-08 wrap with genuine NIP-59?** Assumed but **not verified against the 08 draft**.
   It is the sole support for item 12's coexistence argument, and it also determines whether an
   08-composed node must AUTH-gate 1059 while serving 3359 anonymously. Verify before the proposal
   cites it.
2. **`server` tag semantics under multi-node replication.** Adding BUD-11 `server` tags (item 1)
   binds an auth event to a host. GRASP-P repos advertise *multiple* nodes (`relays`/`server` tags on
   the 30640, `CORD-git-v0-spec.md:45-47`). Repeated `server` tags covering every node in the repo's
   set is the obvious answer, but it re-widens the replay window to exactly that set — is that the
   intended granularity, or should each upload name a single target host?
3. **Does `/list` survive?** (Decided 2026-10: it stays, behind the listed key's own authorization;
   the watchdog, the only tooling that used it, no longer does.) BUD-12 marks it unrecommended and gap C shows ours is the widest leak on
   the private surface. Removing it is cheapest; the question is whether any operator tooling depends
   on it.
4. **Phase labels.** The `Phase` column assumes `P3` = the GRASP-08-composition phase, where
   discovery (item 6) and client AUTH (item 7) land together. Confirm against the standards-proposal
   plan.
