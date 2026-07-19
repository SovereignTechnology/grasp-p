# GRASP-P Phase 3 — CORD-git client, as-built report (2026-07-18)

New client workspace at `~/ngit-private-impl/cord-git/` (separate cargo repo). Build clean, 0
warnings. cord-core unit tests 4/4. **Live-server end-to-end (`scripts/e2e.sh`) green 3×
consecutively** against the real Phase-1/2 `ngit-grasp` release binary (private repos enabled,
memory backend).

## Delivery constraint (important context)

Partway through Phase 2's verification and all of Phase 3, the multi-agent workflow subagents
became **unavailable — a monthly spend limit on the Opus tier the workflows use**. Phase 3 was
therefore implemented **directly in the main loop by hand** (no subagent fan-out): design,
implementation, live E2E, and a manual security pass. This is slower and less parallel than the
prior phases but the deliverable is real and verified end-to-end.

## What shipped (cord-core lib + cord-git CLI)

- `cord-core::crypto` — self-certifying `community_id`; per-epoch write keypair via
  `HKDF(write_secret, "cord-git/write-auth/v1", epoch)`; **schnorr proof-of-possession matching
  the server's exact rule** (`sha256("grasp-p key-claim:<tenant>:<alias>")`); per-blob **fresh
  random ChaCha20-Poly1305 key + nonce** (no convergent encryption); manifest encrypted under an
  HKDF of the shared `#state` key.
- `keystore` — per-community secrets under `CORD_GIT_HOME` (0600, never logged); read-only
  members hold no `write_secret`.
- `events` — 30640 registration (with PoP w-tag), 30641 state root, kind-24242 Blossom auth
  header — all byte-matching the server contract (verified against `src/private/*`).
- `relay` — minimal blocking WebSocket client (publish + REQ/EOSE fetch, latest-30641 selection).
- `blob` — Blossom PUT (24242-authed) + public GET.
- `git` — system-`git` shell-out for pack/unpack/refs (no native git lib).
- `repo` — create / push / clone orchestration with **client-side CAS** (fork detection via
  `manifest_prev`), operator-tamper detection (GET blob sha256 re-check + AEAD), and
  **git-flag-injection hardening** (refname/oid validation before shelling out).
- `cord-git` CLI: `create`, `push`, `clone`, `status`, `doctor`.

## E2E exit criteria (design §8) — observed

| Scenario | Result |
|---|---|
| 2. create + push (30640 + PoP accepted; pack/manifest blobs PUT; 30641 published) | **PASS** |
| 3. owner clone round-trips (HEAD oid + file contents byte-match the original) | **PASS** |
| 4b. read-only member clones, but push is refused (no `write_secret`) | **PASS** |
| 6. concurrent-push CAS: stale base refused with "remote moved — fetch/merge first" | **PASS** |
| 6. force-push after fork succeeds | **PASS** |

Green 3/3 runs. (The force-push step sleeps 1.1 s so its 30641 strictly supersedes the
owner-advance edition — the server's addressable tie-break rejects an equal-`created_at` loser,
which is correct server behavior, not a client defect.)

## Honest scope — what is NOT in Phase 3

- **Full `invite`/`join` (3313 giftwrap to a contributor's inbox) + a write-contributor
  push-back round-trip** (design scenario 4/5). Phase 3 proves the read-vs-write distinction by
  provisioning a read-only member (keystore without `write_secret`) and showing push refusal.
  The 3313 invite/join flow and multi-writer collaboration overlap heavily with **Phase 4**
  (collaboration + revocation) and land there.
- **`git-remote-cord` helper** (`git clone cord://…`) — the design made it explicitly
  best-effort; the guaranteed deliverable is the `cord-git clone/push` CLI, which works.
- Concord byte-conformance (R1, design §0): the membership/crypto layer is CORD-git-native
  behind clean seams; a Concord backend is a documented TODO.
- The manifest deviates from the design's "random-key manifest + key in a #state rumor": Phase 3
  encrypts the manifest under `HKDF(#state key)` so clone needs no rumor fold. Same security
  (any `#state`-key holder reads it; packs keep fresh random keys); the rumor channel returns in
  Phase 4 for roster/collab.

## Security self-review (manual, since the audit agent was unavailable)

- **No nonce reuse / no convergent encryption**: every blob has an independent random key AND
  nonce (unit-tested). Manifest key is `#state`-scoped, random nonce per push.
- **Operator-tamper detection**: clone re-hashes every fetched blob against its addressed
  sha256 and AEAD-authenticates on decrypt — a malicious operator serving wrong ciphertext is
  detected, not silently accepted.
- **Write authority**: only registered write keys can publish a 30641 (server-enforced); a
  read-only member's PUT/30641 is rejected server-side and its push is refused client-side.
- **git-flag injection**: refnames must start with `refs/` and match a conservative charset;
  oids must be 40/64-hex — validated before any `git` invocation.
- **Secrets**: `hosting_nsec`/`write_secret` live only in the 0600 keystore, never in argv,
  env, or logs.
- **Residual / deferred**: fine-grained roster-authorship verification (which write member
  authored a manifest) is Phase 4 ("authority is rejection"); wss:// TLS read-timeout wiring is
  a follow-up (the 15 s deadline loop bounds it); a full adversarial crypto review by an
  independent reviewer should re-run once model budget allows.
