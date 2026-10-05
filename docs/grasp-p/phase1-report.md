# GRASP-P Phase 1 — as-built report (2026-07-18)

Single-node MVP shipped on branch `grasp-p`. Build: `cargo build --release` clean, 0 warnings.
Tests: **phase0_gates 42/42**, **private_repos 44/44** (exit1–exit8, exit7 extended with
proof-of-possession negatives), lib 533/533. Runtime-smoked both enabled and disabled.

## What shipped
- `src/grasp_p/{mod,meta,registration,state_root,write_keys,quota,blob_store,blossom_auth,gc}.rs`
  — `PrivateService`: heed meta env, blob store, registration/state-root/wrap admission,
  quota ledger, Blossom-subset blob routes, GC, boot reconcile from the relay DB.
- `src/http/blossom.rs` + routes in `src/http/mod.rs`: `HEAD/PUT /upload`, `GET/HEAD /<sha256>`,
  `DELETE /<sha256>`, `GET /list/<pubkey>` — kind-24242 auth, streamed frame-by-frame PUT,
  fsync+rename, denylist 451.
- Config: 22 `NGIT_GRASP_P_*` knobs + derived-path accessors + `validate()` (paid mode →
  hard error) + `for_testing()`. `src/nostr/builder.rs` four admit_event arms (30640/30641/
  1059/21059) gated on `private.is_some()`. NIP-11 `private_repos` advert. Aggregate metrics.
- **enable=false is a strict no-op**: `PrivateService` never constructed; admit arms guard on
  `is_some()`; routes/NIP-11/GC/metrics gated; CORS on OPTIONS + all stock responses reverts to
  upstream `GET, POST` / `Content-Type` (verified: disabled node byte-identical, `/upload` 404).

## Audit fixes applied (2 independent reviewers → 8 must-fix, all resolved)
1. **HIGH** duplicate/replayed 1059 double-charged quota → `check_id` dedup before charge.
2. **HIGH** GC TOCTOU deleting a re-claimed live blob → re-verify unreferenced+grace under the
   write lock; `finish()` evaluates `already_stored` inside its txn (serializes GC vs upload).
3. **HIGH** no global-budget/concurrency enforcement before bytes land → RAII `UploadReservation`
   + `InflightUploads` (MAX_CONCURRENT_UPLOADS=64, global budget checked pre-sink).
4. **MEDIUM** key-namespace squatting → **proof-of-possession**: every non-author w/aux key must
   carry a schnorr sig over `sha256("grasp-p key-claim:<tenant>:<alias>")` (design §2 amended).
5. **MEDIUM** unauthenticated `/list` full cross-tenant table scan → `alias_claims` index,
   O(tenant's claims) lookups.
6. **MEDIUM** 30641 replay older than ring re-charged → DB-coordinate replacement-ordering guard.
7. **MEDIUM** 30641 parsed LAST d/a tag vs DB's FIRST → first-tag-wins alignment.
8. (GC finding counted by both reviewers.)

## Deferred follow-ups (non-blocking; tracked for later phases)
- **P4** event-byte ledger is monotonic — replaced 30640/30641 editions are not refunded (blob
  bytes ARE released by GC). Decide refund-on-replace vs documented drift.
- **P4** NIP-09-deleted registration permanently locks its alias + keys + ledger (offboard
  retention is a P1 stub). Needs the offboard/purge path to free them.
- **P4/P5** open-mode default has no sybil resistance (one actor → 50 pseudonymous tenants fills
  the global budget). Ops guidance: don't deploy open mode on public nodes without pow/whitelist;
  consider changing the shipped default.
- **P4** cross-tenant blob dedup pins bytes to the first uploader's ledger until GC (single-charge
  per design). Revisit with mirroring (P2 widens exposure).
- **hardening** Blossom 24242 auth replayable within its validity window (idempotent ops, low
  impact) — add a nonce/replay cache later. `X-Reason` echoes `Internal` error text — genericize.
- **cosmetic** `GET /list` descriptors report `uploaded: 0` (timestamp not persisted in claims).
- **behavior note** `boot_reconcile` re-runs admission-mode gates for DB 30640s missing from meta;
  a mode change across restart can orphan previously-accepted aliases (logged). Intentional;
  document in ops runbook.

## Interface anchors for Phase 2/3
- `PrivateService::new(&Config, SharedDatabase)`; `handle_registration/handle_state_root`,
  `try_handle_wrap(&Event, ephemeral) -> Option<WritePolicyResult>` (None = fall through),
  `begin_upload -> UploadSink`, `blob_path/is_denylisted/blob_delete/blob_list`,
  `spawn_gc`; `gc::run_pass(&PrivateService)` is pub for deterministic tests. The NIP-11
  advert is built by the free function `private::nip11_private_repos_from_config(&Config)` —
  the single advert constructor (a second, service-bound one existed and was deleted unwired).
- Wiring: `create_relay` builds it when enabled and calls `write_policy.set_private()`;
  `RelayRuntime.private: Option<Arc<PrivateService>>`; threaded into `HttpService`.
- Meta tables: registrations, key_claims, tenant_aliases, ledger, blob_claims, alias_claims,
  state_ring. Blob layout `<blob_root>/<aa>/<bb>/<sha256>`, temp under `<blob_root>/tmp`.
