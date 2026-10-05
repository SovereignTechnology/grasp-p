# GRASP-P Phase-0 verification gates — results (2026-07-18)

Base: ngit-grasp v1.2.0 @ cbf6f1d, nostr crates 0.45.0-alpha.3, branch `grasp-p`.
Suite: `cargo test --test phase0_gates -- --nocapture` (G1–G5, G7; ~4 s once built,
flake-free across repeated runs) + `bash scripts/phase0/g6_nginx_stream_shape.sh` (G6,
docker nginx:alpine, exit 0 = pass). Every gate was independently adversarially reviewed
for vacuous-pass loopholes before being accepted.

| Gate | Verdict | Headline evidence |
|---|---|---|
| G1 custom kinds traverse admit_event | **PASS** | Bare 30640 → `restricted:` orphan reject (proves traversal to the catch-all); a-ref'd 30640 → accepted + byte-identical REQ round-trip by authors and by `#d` |
| G2 lmdb Custom+GiftWrap by authors/#d + NIP-77 across two instances | **PASS** | Two LMDB relays; negentropy Down from A (SyncSummary.received = both ids) → Up to B (sent = both, pre-Up guard REQ proved B empty) → B serves both. No REQ fallback exists in nostr-sdk sync, so negentropy is genuinely exercised |
| G3 no hidden 1059 serving guard | **PASS** | Signer-less, AUTH-incapable fresh client on a fresh connection fetched another user's stored wrap via `kinds=[1059]` and via bare `ids=[..]` |
| G4 128 KiB event passes | **PASS** | 128 KiB and 1 MiB content events accepted + round-tripped. **No layer enforces any ceiling below tungstenite's 64 MiB frame default ⇒ GRASP-P's 128 KiB check is the only limit (mandatory)** |
| G5 21059 through policy, broadcast, unstored | **PASS** | Policy veto precedes ephemeral branch (bare 21059: OK=false + no broadcast); accepted 21059 broadcast live, absent from any later REQ |
| G6 256 MiB streamed PUT nginx shape | **PASS** | Deploy shape (`client_max_body_size 0; proxy_request_buffering off;` + limit_req zone): first upstream body byte at +0.006 s of a throttled 6.4 s transfer; sha256+bytes verified end-to-end. Negative control (`buffering on`): first byte at +6.4 s — methodology provably discriminates |
| G7 ReplaceableHistoryStore retains N editions of custom addressable kind | **CHARACTERIZED-LIMITATION** | Both backends: metadata rows for all archived editions survive, but the payload store applies addressable replacement — only the LATEST superseded payload exists (`event_by_id(older)` → None). Capture is also only invoked for 30617/30618 (`src/nostr/lifecycle/deletion/service.rs:722-724`); 30641 via the catch-all never triggers it |

## Design amendments adopted (per plan: gate failure ⇒ amendment before Phase 1)

1. **G7 → 30641 edition ring lives in GRASP-P's private meta store** (`state_ring` table,
   `NGIT_GRASP_P_STATE_HISTORY_EDITIONS`, default 16). Do not touch ReplaceableHistoryStore.
   Already reflected in `phase1-design.md` §4.

## Bonus findings to carry forward

- **Phase 2 positive**: with announcements cross-listing both domains, ngit-grasp's
  announcement-driven proactive sync replicated the custom 30640 AND the gift wrap from A
  to B within ~2 s with no bootstrap config — the sync fabric moves our kinds natively once
  filters exist. (The gate pinned announcements to one domain each so the client-driven Up
  leg stayed provable.)
- **Phase 2/3 client gotcha**: nostr-sdk 0.45.0-alpha.3's default client database is an
  id-tracker only — sync flows MUST set an explicit event store
  (`nostr_memory::MemoryDatabase::unbounded()` or LMDB) or Up-reconciliation is vacuous.
- **Feature flags**: this workspace compiles `nostr` WITHOUT nip59/nip44. The server never
  needs them (stores/serves wraps verbatim). The Phase-3 client crates must enable them in
  their own Cargo.toml; never enable them here (feature unification would alter the relay
  binary).
- Bare 30617 publishes are `AcceptPurgatory` (OK=true but not DB-stored) — accepted-repo
  fixtures need the real git-push promotion (`setup_announcement_on_relay` helper).
- Anonymous scrape/NEG-OPEN/COUNT serve everything to everyone (verified) — consistent with
  the threat model's CONCEDED store-now/decrypt-later posture; confidentiality rests solely
  on client-side encryption.
