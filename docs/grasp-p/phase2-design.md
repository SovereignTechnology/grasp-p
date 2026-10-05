# GRASP-P Phase 2 — two-node replication design contract

Status: implementation contract for `grasp-p`. Builds on Phase 1 (committed). Additive and
gated: **when `NGIT_GRASP_P_REPOS_ENABLE=false` the SyncManager and blob layer behave exactly
as upstream** (existing sync tests MUST still pass unchanged). Mirror activity additionally
gated on `NGIT_GRASP_P_MIRROR_ENABLE`.

## 0. The problem Phase 2 solves

Private repos publish NO kind-30617 announcement, so ngit-grasp's announcement-driven
proactive sync never discovers them. Phase 2 adds a parallel, registration-driven private-sync
path plus an HTTP blob mirror, so a push to node A is fully served by node B within ~2 min:
the 30640/30641/1059 event set (via nostr sync) AND the referenced pack/manifest blobs (via
HTTP pull from the peer's existing public GET route).

Two nodes are a fixed pair. Deterministic pairing: each node sets
`NGIT_SYNC_BOOTSTRAP_RELAY_URL` to the other (map gotcha: without it a node only learns its
peer from an announcement, and private repos have none). The private L1 filter rides that
bootstrap connection; peer URLs for derived filters + blob mirror are ALSO learned from
accepted 30640 `relays`/`server` tags (which list both nodes by construction).

## 1. Event replication — additive private-sync in SyncManager

Reuse the battle-tested application path (`process_event_static` → `admit_event` at
loopback:0 → `save_accepted_event` → `notify_event` → rejected-index) — do NOT reimplement
dedup/negentropy/broadcast. Only add filters + a registration-driven index + a reprocess hook.

### 1.1 Filters (src/sync/filters.rs)
- `build_private_registration_filter(since) -> Filter`: `kinds:[30640]` only. Layer-1-style,
  always subscribed on connect when `private_repos_enable`, NOT part of consolidation rebuilds
  (mirror the 30617 L1 treatment at filters.rs:22). Registrations are small and bounded by the
  global budget, so an unscoped 30640 subscription is acceptable (like the unscoped 30617 L1).
- `build_private_derived_filters(regs: &[(alias, w_aux_keys)], since) -> Vec<Filter>`: per
  100-alias chunk `kinds:[30641] #d:[aliases]`; per 100-key chunk `kinds:[1059]
  authors:[keys]`. Chunk exactly like state_event_filters_for_our_repos (filters.rs:73). 21059
  is ephemeral (never stored) — do NOT sync it. Aux keys included (read-only members' 1059s).

### 1.2 PrivateSyncIndex (src/sync/mod.rs or src/sync/private_index.rs)
A small additive index parallel to RepoSyncIndex: `alias -> {w_aux_keys, server_urls,
relay_urls}`. Populated from EVERY accepted 30640 (client push AND synced), removed on 30640
tombstone (NIP-09). Guarded by the same lock discipline as the existing indexes. When it
changes, recompute derived filters and `AddFilters` them to every connected peer (reuse the
existing AddFilters channel + handle_new_sync_filters path; since=None backfill).

### 1.3 Wiring points (all gated on private_repos_enable)
- `SyncManager::run` (mod.rs:1486): on each peer connect, also subscribe the private L1 filter
  (live limit(0) + historic since=None) exactly alongside the normal L1 subscription.
- `process_event_static` Accept branch (mod.rs:2697): after a 30640 Accept, update
  PrivateSyncIndex + trigger derived-filter recompute + run the reprocess hook (1.4). A synced
  30641/1059 Accept needs nothing extra here (blob mirror is triggered inside
  `handle_state_root`, see §2).
- Pre-filter skip (mod.rs:1771-1782): add 30640/30641/1059 to the rejected-skip check so a
  known-rejected event is not reprocessed every pass.

### 1.4 Out-of-order reprocess (rejected-index; recipe from the sync map §3)
A 1059 or 30641 can arrive at B BEFORE the 30640 that authorizes it → Phase-1 handler rejects
(`unregistered key` / `alias not live`) → lands in RejectedEventsIndex. On 30640 Accept,
invalidate + reprocess held events keyed by that alias.
- Extend `EventType` (rejected_index.rs:97) with `PrivateState` and `PrivateWrap`.
- Registration of these rejections (mod.rs:2933 reject branch): 1059 wraps have an ephemeral
  outer pubkey and no `d` tag, so the existing (pubkey, d) key does NOT apply. Derive the
  invalidation key = the **alias** the event targets: for 30641 it is the `#d`/`a` alias; for
  1059 the server cannot read the target alias (encrypted) — so key 1059 rejections by the
  **outer author pubkey** and, on 30640 Accept, invalidate every held 1059 whose author ∈ the
  newly-registered key set. Implement a dedicated small `PrivateRejectedIndex` (author->events
  and alias->events) rather than overloading the (pubkey,identifier) map, to avoid the d-tag
  assumption landmines. 120s hot-cache TTL applies (raise `rejected_hot_cache_duration_secs`
  in ops if 30640/dependent ordering is slow; document).
- Reprocess = `process_event_static(ev, SaveContext::HotCacheReprocess)` (safe recursion — the
  map confirms events are removed from hot cache first).

## 2. Blob mirror (src/grasp_p/mirror.rs, pull-only)

On ANY 30641 Accept (client or synced), the referenced blobs must exist locally. On A (client
push) they already do (client PUT them first). On B (synced 30641) they are missing → pull.

- `BlobMirror`: an mpsc job queue + a worker task spawned like `spawn_gc`. Job = {tenant_hex,
  alias, want: Vec<sha256>, peer_servers: Vec<url>}. `handle_state_root` Accept enqueues a job
  with want = {m} ∪ {pack} and peer_servers = registration.servers minus this node's domain.
- Worker: for each want hash NOT already local and NOT denylisted, `GET https://<peer>/<hash>`
  (reqwest, streamed to a temp file, sha256 verified against the hash — reject on mismatch),
  then store via the Phase-1 blob store path (fsync+rename) + claim for (tenant, alias) +
  charge the replicated tenant's ledger. Over quota / global budget → skip + increment
  `mirror_lag`. Pull-only: uses the EXISTING public `GET /<sha256>` route — no new inbound
  surface. 24242-gated GET is a Phase-5 knob (with a peer carve-out); v1 GET stays public
  because the mirror depends on it.
- Idempotent + GC-safe: mirroring claims the blob (unreferenced_since=None) exactly as an
  upload finish would, so GC won't reap a mirrored-and-referenced blob. Re-running a job is a
  no-op once the blob is local.
- Metrics: gauge `ngit_private_mirror_lag_blobs` (jobs' outstanding want count), counters
  `ngit_private_mirror_fetched_total` / `ngit_private_mirror_failed_total{reason}`. **Alert on
  sustained mirror_lag_blobs > 0** (silent-desync lesson F1) — expose via metrics; ops alert.
- Config: reuse `NGIT_GRASP_P_MIRROR_ENABLE` (default false). Add `NGIT_GRASP_P_MIRROR_PEER_URLS`
  (Option<CSV>, default None → derive from 30640 server tags + bootstrap). Add
  `NGIT_GRASP_P_MIRROR_MAX_CONCURRENCY` (u32, default 4) and
  `NGIT_GRASP_P_MIRROR_FETCH_TIMEOUT_SECS` (u64, default 120). HTTP client must cap per-blob
  bytes at max_blob_bytes (413-equivalent abort mid-stream) — a hostile/misconfigured peer
  must not stream unbounded.

## 3. GC on both nodes

Per-node GC already exists (Phase 1 spawn_gc). No node-specific change — each node reaps its
own unreferenced-after-grace blobs. Correctness note: the mirror claims blobs on B, so B's GC
only reaps them after B's own retained 30641 ring stops referencing them (same as A). The GC
TOCTOU fix from Phase 1 covers the mirror-vs-GC race (mirror store+claim and GC decide+unlink
serialize on the same meta write lock).

## 4. Config parity (R6) — divergence silently breaks replication

If A accepts a 30640 (e.g. open mode) that B would reject (e.g. whitelist mode, or a different
domain-listing requirement), B never stores it and never mirrors — a per-repo silent desync.
Mitigations (all additive):
- **Doctor/parity advert**: extend NIP-11 `private_repos` with a `policy_fingerprint` =
  short hash of the admission-affecting config (registration_mode, pow_bits, the sorted tenant
  whitelist, max_event_bytes, quota tuple, both node domains). Ops (and a `doctor --two-node`
  check) compare fingerprints across the pair; mismatch = warn. Do NOT leak raw whitelist.
- **Startup log**: on boot, log the fingerprint + the configured peer so an operator can eyeball
  parity.
- Synced 30640s re-run the SAME admission policy (no relaxation) — this is correct and
  deterministic ONLY under equivalent config (pow is on event.id, whitelist on tenant npub,
  domain-listing on the registration's tags which list both nodes). Parity is therefore an ops
  invariant, enforced by the fingerprint check, not code.

## 5. Exit tests (tests/private_two_node.rs, TestRelay pair)

Use two TestRelays A and B, LMDB backend, private enabled + mirror enabled, each bootstrapped
to the other (extend tests/common RelayOptions with private-peer + mirror knobs — test infra,
allowed). Reuse tests/private_repos.rs helpers (registration, blob PUT, 24242 auth, 30641).

1. **Replication E2E**: register a 30640 (listing both domains) + PUT 2 blobs to A + publish a
   30641 to A. Within a bounded poll (≤120 s, but should be seconds with NGIT_TEST=1 fast
   timers): assert B serves the 30640 (REQ), the 30641 (REQ), any 1059 (REQ by author), AND
   `GET https://B/<hash>` returns each blob with a matching sha256. Byte-compare at least one
   pack against the original.
2. **Out-of-order**: publish the 30641 + a 1059 to B FIRST (before B knows the 30640), then the
   30640 to A. Assert B eventually accepts and serves the 30641 + 1059 (reprocess hook fired).
3. **Kill-one-node backfill**: stop B; push a fresh 30641 + new blob to A; restart B (same
   LMDB paths); assert B backfills the new event + mirrors the new blob within the bound.
4. **Disabled no-op**: with `private_repos_enable=false` on both, confirm the existing sync
   behavior is unchanged (a normal 30617 repo still replicates A→B) and no private filters are
   emitted. (Rely primarily on the existing sync test-suite staying green.)
5. **Mirror bounds**: a 30641 referencing a blob that does NOT exist on the peer → B logs a
   mirror failure, `mirror_lag` > 0, and B's `GET` for that hash is 404 (no partial/poisoned
   blob stored); the 30641 itself is still accepted (event replication independent of blobs).

## 6. Non-goals for Phase 2 (deferred)
- 24242-gated blob GET with peer carve-out → Phase 5 knob.
- Refunding event-byte ledger on edition replacement → Phase 4.
- Offboard/tombstone freeing alias+keys+ledger → Phase 4.
- Mirroring is best-effort with alerting; no guaranteed-delivery queue persistence across
  restart beyond re-deriving want sets from retained 30641s on boot (a boot repair pass MAY
  re-enqueue missing blobs for all live 30641s — include a lightweight version of this).
