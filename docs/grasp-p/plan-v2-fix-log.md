# CORD-git + GRASP-P plan — v1→v2 fix log

Method: 3 independent adversarial reviewers on 2026-07-18:

1. **Concord-protocol lens** — reviewed the plan against the actual CORD-01..07 spec text +
   examples.md at pinned commit `23dcea57cc6b419522ed1a217d66ebe5767d52f0`.
2. **Server/ops lens** — reviewed the plan against the as-built `grasp-p` branch in
   `~/ngit-private-impl/ref/ngit-grasp` and the pristine v1.2.0 source at `cbf6f1d`.
3. **Security/privacy lens** — attacked the trust model, crypto, metadata leakage, abuse,
   and legal posture.

Every finding below is **CONFIRMED**; each fix is folded into `~/.claude/plans/keen-growing-bentley.md`
(v3) at the cited section. Nothing invalidated the core architecture (blind write-key gating,
content-addressed blobs, pull-only mirror).

---

## 1. Blockers (3)

### F1 — 30640 had no stream-pk registration vehicle; readers' wraps were inadmissible

**Defect:** Plan §3.2 admitted 1059 wraps by "registered stream pks" but the 30640 tag shape
only carried `w` (write keys) and `aux`. Concord wraps are signed by derived **stream keys**
(control_pk, guestbook_pk, per-channel channel_pk, rekey addresses) — never the write key.
Every reader's guestbook Join (3306) and #collab rumor would have been rejected by
`admit_event`.

**Fix:**
- Add `s`×N stream-pk tags to 30640 covering: control, guestbook, #state, #collab, current
  + precomputed next-epoch rekey addresses, dissolved_pk if used.
- Per-key schnorr proof-of-possession bound to (tenant, alias).
- First-registrant-wins across **w ∪ s ∪ aux** with cross-node deterministic merge
  (lowest `created_at`, tie lowest id; loser tombstoned; conflict alert).
- ~64-key budget per alias (≈6 epochs retained); prune oldest on rotation.
- Old-epoch stream pks deregistered at rotation + grace.

**Rotation sequencing added:** roll root → compute new pks → publish 30640′ with
`s` = old ∪ new ∪ epoch+1 rekey addrs, `w` = old ∪ new → **wait acceptance on BOTH nodes**
→ publish refounding artifacts → 30640″ with s/w = new only. Publishing rekey 3303s before
30640′ acceptance strands the epoch.

**Where in v3 plan:** §3.2, §3.3.

---

### F2 — Cross-tenant blob DELETE was authorized by any registered write key

**Defect:** Blob hashes are public in 30641 `pack` tags. A tenant B could register (open mode),
read tenant A's pack hashes, and send `DELETE /<A's-sha256>` with a 24242 signed by B's own
write key. The plan only required "signed by a registered write key" — attribution, not
authorization.

**Fix (normative):** `DELETE`/`PUT` attribution must verify:
- 24242 signer ∈ the `a`-tag registration's `w`-set.
- Target blob is owned by (uploaded under) or currently referenced by that registration.

Cross-tenant DELETE must return 403; same scoping check applies to quota charging.

**Where in v3 plan:** §5, Verification probe (cross-tenant DELETE 403).

---

### F3 — 30641 coordinate rotation had no resolution semantics

**Defect:** 30641 is NIP-33 addressable on `(kind, pubkey, d)`. After epoch rotation the new
write key produces a NEW coordinate while the old coordinate stays live. No rule said which
one clients, mirror, or GC should treat as current.

**Fix (normative):**
- Current state root = latest (`created_at`, lowest-id tiebreak) 30641 whose signer ∈ the
  **current** 30640 edition's `w`-set.
- All other signer editions are historical.
- Applied by clients, mirror enqueue, and GC claim recompute.
- Rotation window allows two live coordinates; track newest-w signer.
- `created_at` future-drift capped to prevent last-writer-wins gaming.
- Optional server prune of stale-signer editions so naive REQs can't resolve to a frozen fork.
- Per-edition kind-5 deletion of 30641 hooked/rejected to prevent silent state drift.

**Where in v3 plan:** §3.2.

---

## 2. Major design corrections (14)

### M1 — Manifest unified to always-encrypted-blob + #state pointer rumor

The plan had competing manifest designs (inline in a 30618-shaped rumor with >48KB spill, vs
encrypted blob referenced by 30641). Unification:

- Manifest = **always** an encrypted blob under a fresh random key + nonce.
- #state pointer rumor = tiny member-signed `{manifest sha256, manifest key+nonce, prev
  pointer-rumor id, generation, channel/epoch binding}`.
- Fresh random key+nonce per manifest generation stated as the revocation-load-bearing
  invariant — one key-reuse optimization = full revocation failure.
- Manifest records `sha256(plaintext)` per blob because ChaCha20-Poly1305 is not
  key-committing (restores plaintext commitment under partition + malicious writer).
- Fold rules: roster-checked, generation-monotonic, joiner baseline.
- Rotation re-publish = **re-mint** a new pointer under the new epoch, not byte-verbatim
  re-wrap (20013 seals cannot cross epochs).
- Cross-check: `rumor.m == 30641.m` AND pack-set equality; mismatch ⇒ repo treated as forked.

**Where:** §3.1, §3.2.

---

### M2 — `cgc` tag dropped for CORD-03's mandated `channel`/`epoch` tags

**Defect:** Plan proposed a custom `["cgc", channel_id, epoch]` tag. CORD-03 §3 mandates
`["channel", channel_id]` and `["epoch", n]` on every chat-plane rumor; conformant receivers
DROP rumors lacking them.

**Fix:** Use `channel`/`epoch`. Drop `cgc`.

**Where:** §2, §3.2.

---

### M3 — 30643 snapshots must be container rumors, not re-wraps

**Defect:** Plan suggested re-wrapping old #collab rumors into the current epoch. CORD-03's
epoch strict-equality rule would drop them.

**Fix:** 30643 = container rumor with current `channel`/`epoch` binding, embedding old signed
rumors verbatim as payload data. Each embedded rumor is individually signature-verifiable;
rendered as historical quotes. Never republished publicly at flip.

**Where:** §2.

---

### M4 — Write-scope rekey needs dedicated address and demote/promote flows

**Defect:** Plan said "parallel synthetic-scope rekey" but left address derivation,
`prevcommit`, and role-conclusion semantics unspecified. The obvious wrong choice (share the
base rekey address) corrupts CORD-06's chunk-correlation/removal test.

**Fix:**
- `scope_id = sha256("cord-git/write-scope-id/v1" ‖ 0x00 ‖ community_id)` (stable across
  refoundings; community_id replaces the undefined `namespace_id`).
- Dedicated address:
  `group_key("concord/rekey-pseudonym", prior_root, write_scope_id, write_epoch+1)`.
- Write-scope `prevcommit` computed over `(write_secret, write_epoch)` per CORD-02 A.5.
- Push-role conclusions come **only from the roster fold** — write-scope blobs are pure
  secret delivery; missing blob ≠ removal.
- New flows: **demotion** = standalone write-scope rotation (no refounding); **promotion** =
  `write_secret` delivery on grant (3313 whisper or targeted 3303).

**Where:** §2.

---

### M5 — a-coordinate identity rule for flip-public

**Defect:** Collab a-tags used `30617:<tenant>:cg-<community_id>` without specifying that the
`<tenant>` pubkey must equal the eventual public-30617 signer. Choosing a different flip key
would dangling every historical a-coordinate.

**Fix:** Mint collab a-tags with the intended eventual 30617 signer (default = owner/hosting
pseudonym). Document `--fresh-identity` cost same as `--fresh-d`.

**Where:** §2, §7.

---

### M6 — Raw rumor-byte retention for flip-public

**Defect:** "Verbatim republish" only works if the exact NIP-01 serialization is preserved.
Re-serializing parsed events changes whitespace/key order ⇒ new ids ⇒ broken signatures and
broken 1111 threading.

**Fix:** Keystore MUST retain raw rumor JSON bytes; flip republishes those bytes.

**Where:** §2, §7.

---

### M7 — 13302/13303 excluded from git-node admission

**Defect:** Plan had knob-gated admit arms for 13302/13303. These are signed by members' real
npubs (self-encrypted to self). Admitting them on the git nodes would deanonymize members to
the operator/world.

**Fix:** Drop 13302/13303 from admit arms. Normative client rule: these kinds go only to the
member's own NIP-65 relays.

**Where:** §2, §3.2.

---

### M8 — Quota ledger must be charge-retained

**Defect:** Every accepted 30640/30641 edition charged bytes but nothing released on
replacement/ring-trim/deletion. A sybil set could exhaust the 50 GiB global budget at ~0
real storage cost via addressable replacement flooding.

**Fix:** Release superseded-edition bytes on 30640 replacement, state-ring trim, kind-5
targeting the registration, and offboard purge.

**Where:** §5.

---

### M9 — Offboard made functional

**Defect:** Offboard was a stub: tombstone field never set, kind-5 not in sync filters,
NIP-62 vanish claimed to offboard-all (false — vanish is per-author; derived keys are not the
tenant npub).

**Fix:**
- Tombstone+purge worker: set `tombstoned_at`, purge blobs/ring/key claims/ledger after
  retention.
- Kind-5 must be published to both nodes OR added to private sync filters.
- Strike NIP-62 offboard claim.

**Where:** §3.3, §5.

---

### M10 — GC ring time-decay

**Defect:** Alias-scoped state ring retains up to N editions. In a quiescent repo, frozen
editions from old write keys never trim and pin their blob sets forever.

**Fix:** Editions older than GC grace stop protecting blobs unless they are the newest edition
of a current-w-set signer.

**Where:** §5.

---

### M11 — quota-class tag dropped

**Defect:** 30640 included a self-declared `quota-class` tag — either dead weight or a
privilege-escalation vector.

**Fix:** Server computes and records quota class at acceptance; drop the tenant-declared tag.

**Where:** §3.2.

---

### M12 — App bits ≤ 1<<52

**Defect:** Plan claimed bit 48 (`CORDGIT_PUSH`) without noting CORD-04's legacy-number float
trap above 2^53.

**Fix:** All CORD-git app bits must be ≤ 1<<52.

**Where:** §2.

---

### M13 — Guestbook Join outer signer must not be member npub

**Defect:** Plan wording implied a prospective member publishes their guestbook Join before
receiving the bundle. The Join's outer signer would then have to be the member npub.

**Fix:** Joiner receives the bundle (community_root) first, then publishes Join wrapped at the
derived guestbook_pk. Outer signer is the stream key, never the member npub. Kept as a
`doctor` check.

**Where:** §2.

---

### M14 — Rotation sequencing

(See F1.) Refounding artifacts must not publish until 30640′ with new s/w sets is accepted on
both nodes.

**Where:** §3.3.

---

## 3. Threat-model & leak-table honesty (9)

### T1 — Operator ACTIVE misbehavior (split-view / withholding)

Added: forgery is defeated; withholding/partition is **not detectable in-protocol** because
both nodes are one operator. Detection needs member gossip, a third-party mirror, or (v3) an
external watchdog.

### T2 — Coerced operator (future behavior)

Added: compelled logging/selective service cannot be prevented by design; mitigations are
client-side (Tor/SOCKS5) and jurisdictional.

### T3 — Malicious writer

Added as its own adversary class: garbage/rollback 30641s with valid shared-key sigs; detected
client-side via prev-CAS and roster-signed rumors; recovery = honest re-publish.

### T4 — Member-visible roster

Stated explicitly: roster is plaintext to members; membership is hidden from operator/world,
**not** from members.

### T5 — "Cannot locate" → "cannot READ"

Corrected: a removed member can still bulk-fetch new ciphertext from the public-read relay;
only decryption fails.

### T6 — Leak table completed

Added: repo-birth timestamp, revocation-event cadence, push-structure correlation, negentropy
per-stream event counts, pack-size histograms, public-GET popularity.

### T7 — Legal posture

Stated: proactive scanning is structurally impossible; actionable reports must include the blob
key; workflow = verify-then-denylist; ToS language required.

### T8 — Open-mode sybil exhaustion

Stated honestly: unpreventable, only escapable via mode escalation.

### T9 — Removed-member write-spam window

Quantified: spam-only, future-drift-capped, unbounded if tenant stalls.

---

## 4. Server-mechanism corrections from as-built evidence (9)

### S1 — ReplaceableHistoryStore implication struck

The plan originally implied `ReplaceableHistoryStore` retains N editions. Source review showed
it retains latest-per-coordinate payloads only. The actual mechanism is the alias-scoped
`state_ring` in the private meta env — a GC/quota artifact, not servable. Client recovery
rides the #state prev-chain.

### S2 — Out-of-order recovery is net-new code, not reuse

The existing `RejectedEventsIndex` can't key giftwraps (ephemeral outer pubkeys, no d-tag).
The as-built added `PrivateRejectedIndex` + inline reprocess + 5s polling rebuild. Plan now
reflects this and adds hourly `since=None` re-issue for the slow tail.

### S3 — reqwest is a new main dependency

Pristine v1.2.0 had no outbound HTTP client. The mirror needed `reqwest`. Plan now names it.
`self_subscriber.rs` reference dropped.

### S4 — policy_fingerprint is a hard gate

Promoted from "runbook note" to startup/health alarm; fingerprint mismatch should refuse
peering.

### S5 — Dispatch edge

When `NGIT_PRIVATE_REPOS_ENABLE=true`, foreign a-ref'd 30640/30641 are rejected (previously
admittable via orphan catch-all). Documented.

### S6 — Stub knobs stated

`NGIT_PRIVATE_ACCEPT_DIRECT_INVITES`, `NGIT_PRIVATE_PER_TENANT_METRICS` have no call sites;
`RegistrationMode::Paid` is rejected by `Config::validate`.

### S7 — Exact-host URL match

Inherited substring match (`git.sovit.xyz` contained in `git.sovit.xyz.attacker.tld`) fixed to
exact-host parsing.

### S8 — sync/mod.rs submodule extraction

+384 lines of private sync wiring should move to a submodule in Phase 4c to reduce rebase
surface.

### S9 — 30640 replacement-cadence limit

Free addressable replacements re-trigger index rebuilds and history growth. Added to Phase 4b
as the last uncontrolled flooding vector.

---

## 5. Refuted or verified-holding (7)

These were suspected problems that the reviewers confirmed are **not** defects:

1. **Guestbook-join identity leak** — refuted; bundle delivers `community_root` before any Join;
   outer signer is the derived guestbook stream key.
2. **GC permanent-pin** — refuted in stated form; alias-scoped ring trims during continued
   activity; only weakened quiescent-repo form was real (fixed via time-decay).
3. **Manifest-key-reuse revocation failure** — traced; design holds because of per-generation
   fresh keys. The invariant is now normative, not a code change.
4. **Kind-number collisions** — 30640/30641/30642/30643 are clear vs Concord, NIP-34, Blossom,
   Marmot.
5. **Outsider confirmation-of-content** — defeated by random per-blob keys.
6. **Clobber/corruption resistance** — holds (immutable blobs, write-key gating, hash-pins).
7. **1059 p-tags** — Concord wraps use random ephemeral p-tags; non-identifying.

---

## 6. Downstream propagation checklist (Phase 4)

These amendments are in the plan; they must still land in code/spec/tests.

### CORD-git spec draft (`docs/grasp-p/CORD-git-v0-spec.md`)
- [ ] channel/epoch tags (drop `cgc` if present)
- [ ] write-scope dedicated address + `prevcommit` + demote/promote flows
- [ ] manifest always-blob + fresh-key invariant + plaintext hashes
- [ ] pointer fold rules + re-mint rule
- [ ] 30643 container rumors
- [ ] raw-byte retention for flip-public
- [ ] a-coordinate identity rule
- [ ] 30641 resolution rule
- [ ] rotation sequencing
- [ ] 13302/13303 exclusion
- [ ] invite/join signer rules

### Code (`grasp-p` branch)
- [ ] charge-retained ledger
- [ ] tombstone+purge worker
- [ ] kind-5 sync propagation
- [ ] 30641-deletion hook
- [ ] ring time-decay
- [ ] blossom ownership-scoping audit
- [ ] hourly `since=None` re-issue
- [ ] per-write-key token bucket
- [ ] 30640 replacement-cadence limit
- [ ] mirror retry/backoff policy
- [ ] exact-host URL check (if not built)
- [ ] sync/mod.rs submodule extraction
- [ ] external split-view watchdog (Phase 4b)

### Tests
- [ ] ledger-release soak
- [ ] cross-tenant DELETE 403 probe
- [ ] revoke E2E
- [ ] demote/promote E2E
- [ ] rotation-sequencing ordering test
- [ ] split-view drill

---

*This log pairs with `~/.claude/plans/keen-growing-bentley.md` (v3) and the existing
`docs/grasp-p/phase[0-3]-*.md` design/report documents.*
