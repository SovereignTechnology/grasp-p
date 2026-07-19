# GRASP-P post-Phase-4 review addendum (2026-07-18)

Independent adversarial review of the hand-written client (Phase 3/4) plus a re-verification
pass over the server. Triggered by a user request to "look over what we did"; the review agent
(formerly blocked by the Opus spend limit) ran and found real defects. All load-bearing findings
are now **fixed and committed**, with tests.

## Re-verified state (this pass)

- Server suites: phase0_gates 42/42, private_repos 44/44, private_two_node 41/41 — green.
- Client: cord-core unit tests 10/10 (4 crypto + 6 new adversarial selection tests).
- Live E2E (`cord-git/scripts/e2e.sh`): **14/14 scenarios green**, incl. two new adversarial
  pinning-attack scenarios. Run multiple times, no flakes.

## Review findings → resolutions

| # | Sev | Finding | Resolution |
|---|---|---|---|
| 1 | CRITICAL | Read path trusted raw relay results: no signature check, no author-set check, `created_at`-only selection — revocation didn't reliably take effect; a future-dated or forged 30641 pinned every reader | **Fixed (client + server).** `latest_valid_state_root` requires sig-valid + author ∈ current 30640 `w`-set + ≤15 min future slack; server rejects future-dated private events at admission. Unit-tested (forgery/future/rotation lockout/tamper) + E2E pinning scenarios |
| 2 | HIGH | Push CAS: TOCTOU + relay OK=true despite the edition being discarded by addressable replacement → phantom `manifest_prev` | **Fixed.** Post-publish read-back: push fails loudly unless its own event is the served authenticated latest |
| 2b | (found while fixing) | A future-dated 30641 doesn't just pin readers — it **evicts the real latest from the relay DB** (addressable replacement) | **Fixed (server).** Future-dated private events rejected at admission (15-min skew); E2E asserts the real latest survives |
| 3 | MEDIUM | `relay::fetch` returned partial/empty results as success → silent empty/stale clones | **Fixed.** fetch errors unless EOSE arrives; CLOSED/NOTICE surfaced |
| 4 | MEDIUM | No read timeout on TLS sockets (hang-forever) | **Fixed.** native-tls arm sets the socket timeout |
| 5 | MEDIUM | Keystore tmp file world-readable during save | **Fixed.** 0600 at creation (OpenOptions mode), 0700 dirs |
| 6 | MEDIUM | `rotate` republished local stale history with no freshness check | **Fixed.** Rotate now compares the working tree's refs to the remote manifest's refs and refuses on divergence (the keystore anchor is insufficient — another clone can move it) |
| 7 | MEDIUM | Blob client: no timeouts, no size cap (OOM via unbounded body) | **Fixed.** connect/read timeouts + 256 MiB cap |
| 8 | LOW | `community_id` path traversal via `.cord-git` pointer | **Fixed.** Must be exactly 64 lowercase hex before any path join |
| 9 | LOW | Clone into pre-existing repo could run its git hooks / clobber files | **Fixed.** Clone refuses non-empty destinations |
| 10 | LOW/NIT | Blob ids used unvalidated in URL path; dead code; vestigial nonce/epoch; no tests beyond crypto | Partially addressed (hash compare already bounds ids to served ciphertext; nonce field kept for spec clarity; 6 new selection unit tests added). Remaining nits left as-is |

## What this changes in the threat-model story

Before this pass, "the operator is untrusted" held for **blob contents** (sha256 + AEAD) but
NOT for **event metadata** (which 30641 is "latest") — the client took the relay's word.
After this pass, state-root selection is cryptographically anchored: signature verification +
live-registration author-set + freshness bounds, with the server refusing future-dated events
at admission. The remaining operator-level capability is **availability/rollback to an older
VALID edition** (the operator can withhold newer valid events and serve an older signed one).
The `manifest_prev` chain makes this partially detectable client-side but not fully preventable
without monotonic sequencing in the registration — documented as a residual (Phase 4/5
candidate: roster-anchored epoch sequencing).

## Residuals (documented, not blocking)

- Operator availability/rollback to old valid editions (above).
- Push remains O(history) per push (delta packs are a Phase 4/5 efficiency item; correctness is
  unaffected — each pack is self-contained and superseded packs are GC'd).
- `wss://` end-to-end path is code-reviewed but E2E-tested only over `ws://` localhost.
- Full multi-member invite/join (3313) + roster authorship remain Phase 4-full items; the
  read-vs-write distinction is server-enforced and tested via the read-only keystore path.
