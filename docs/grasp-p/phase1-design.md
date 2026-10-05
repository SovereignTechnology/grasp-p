# GRASP-P Phase 1 — single-node MVP design contract

Status: implementation contract for the `grasp-p` branch. Derived from the CORD-git plan
(`~/.claude/plans/keen-growing-bentley.md`) + the verified internals map. Where this doc
fixes an interface, implement exactly this interface; where silent, follow repo idiom.

Hard invariants (from the plan):
- **Zero behavior change when `NGIT_GRASP_P_REPOS_ENABLE=false`** (default). Every new code
  path is gated on it; all four private kinds fall through to existing handling when off.
- Public `:7334` NIP-34/git path untouched. Private repos NEVER touch git-smart-HTTP; no bare
  repo is ever created for them.
- Server is content-blind: it verifies outer signatures against registered opaque pubkeys and
  moves ciphertext. It never inspects wrap contents.
- Phase 1 scope: registration (open/whitelist/pow modes), write-key index, quota ledger, blob
  store + Blossom-subset routes, admit_event arms, NIP-11 advert, 30641 edition ring
  (G7 amendment). NOT in Phase 1: sync/mirror (P2), denylist/1984/offboard hardening beyond
  stubs (P4), paid mode (P5 — selecting it must fail `Config::validate()` with a clear error).

## 1. Config knobs (src/config.rs, clap pattern like existing fields)

All fields on `Config`, `#[arg(long, env = "...", default_value...)]`. Update
`Config::for_testing()` too. Booleans default false unless stated.

| env | type | default | meaning |
|---|---|---|---|
| NGIT_GRASP_P_REPOS_ENABLE | bool | false | master switch |
| NGIT_GRASP_P_REGISTRATION_MODE | enum open\|whitelist\|pow\|paid | whitelist (WP-E; was open in Phase 1–4b) | admission mode for NEW aliases |
| NGIT_GRASP_P_POW_BITS | u8 | 20 | NIP-13 bits required on 30640 when mode=pow |
| NGIT_GRASP_P_TENANT_WHITELIST | String CSV npubs | "" | tenants allowed when mode=whitelist |
| NGIT_GRASP_P_MAX_BLOB_BYTES | u64 | 268435456 (256 MiB) | per-blob cap, enforced pre- and mid-stream |
| NGIT_GRASP_P_MAX_EVENT_BYTES | u64 | 131072 (128 KiB) | serialized-JSON cap for 30640/30641/1059/21059 |
| NGIT_GRASP_P_QUOTA_TENANT_BYTES | u64 | 1073741824 (1 GiB) | per hosting-npub total (events+blobs) |
| NGIT_GRASP_P_QUOTA_REPO_BYTES | u64 | 536870912 (512 MiB) | per alias total |
| NGIT_GRASP_P_GLOBAL_BUDGET_BYTES | u64 | 53687091200 (50 GiB) | whole private subsystem cap |
| NGIT_GRASP_P_MAX_ALIASES_PER_TENANT | u32 | 64 | registrations per hosting npub |
| NGIT_GRASP_P_MAX_WRITE_KEYS_PER_ALIAS | u32 | 64 | `w` + `aux` tags cap |
| NGIT_GRASP_P_STATE_HISTORY_EDITIONS | u32 | 16 | 30641 edition ring depth (G7 amendment) |
| NGIT_GRASP_P_GC_GRACE_SECS | u64 | 86400 | unreferenced blob grace before delete |
| NGIT_GRASP_P_GC_INTERVAL_SECS | u64 | 3600 | GC pass cadence |
| NGIT_GRASP_P_OFFBOARD_RETENTION_SECS | u64 | 2592000 (30 d) | tombstoned-alias purge delay (stub in P1) |
| NGIT_GRASP_P_BLOB_DATA_PATH | Option<String> | None → `<relay_data_path>/blobs` | blob store root (accessor `effective_private_blob_path()`) |
| NGIT_GRASP_P_META_DATA_PATH | Option<String> | None → `<relay_data_path>/private-meta` | heed env root (accessor `effective_private_meta_path()`) — derived defaults keep TestRelay tempdir isolation without new env vars |
| NGIT_GRASP_P_DENYLIST_PATH | Option<String> | None | sha256-per-line file; GET→451 (loaded at boot) |
| NGIT_GRASP_P_MIRROR_ENABLE | bool | false | P2; knob exists, unused in P1 |
| NGIT_GRASP_P_ACCEPT_DIRECT_INVITES | bool | false | 3313 storage opt-in; P1 only honors =false (reject) |
| NGIT_GRASP_P_PER_TENANT_METRICS | bool | false | per-tenant metric labels opt-in |

`Config::validate()` additions (only when enable=true): mode=paid → Err("paid registration
mode is not yet available"); pow_bits 1..=40; history editions ≥1; quotas nonzero; repo quota
≤ tenant quota ≤ global budget; blob/meta paths non-empty.

## 2. Kinds and event shapes (server-visible plaintext only)

- **30640 registration** (addressable, signed by tenant hosting npub):
  `d` = alias, exactly 32 lowercase-hex chars. `w` tag ×N = 64-hex x-only pubkeys (write
  keys). Optional `aux` tag ×N = 64-hex pubkeys (stream/publish keys; read-only members'
  event publishing). **Proof-of-possession (audit amendment):** each claimed w/aux key that
  is not the event author must carry, as the tag's third value, a 128-hex schnorr signature
  by that key over sha256(`grasp-p key-claim:<tenant-hex>:<alias>`); keys without a valid
  proof are rejected `invalid:`. This stops key-namespace squatting (denial of registration
  for a victim's known pubkey and 1059 wrap attribution/quota hijack). `relays` tag(s) and `server` tag(s): at least one of EACH must contain
  this node's domain (same substring/trailing-slash normalization as
  `events.rs::has_clone_url/has_relay` — reuse those helpers' logic against `config.domain`).
  Optional `quota-class` tag (opaque string, recorded, unused in P1).
- **30641 state root** (addressable, signed by a registered write key of the alias):
  `d` = alias. `a` = `30640:<tenant-hex>:<alias>` and must match the live registration.
  `m` = `["m", <64-hex sha256>, <bytes-u64>]` manifest blob. `pack` ×N =
  `["pack", <64-hex>, <bytes-u64>]`. All hashes lowercase hex; all sizes parse as u64 and are
  each ≤ max_blob_bytes.
- **1059** (regular) / **21059** (ephemeral): admitted iff outer pubkey ∈ (live w-keys ∪ live
  aux keys) of ANY registration. Contents never inspected. 21059 accepted → library
  broadcasts, never stores (verified: WritePolicy runs before the ephemeral branch).
- All four kinds: serialized event JSON (`event.as_json().len()`) ≤ max_event_bytes else
  reject `restricted: event exceeds private repo size limit`.

## 3. Module layout — `src/grasp_p/`

New `pub mod private;` in lib.rs. Files:

```
src/grasp_p/mod.rs          PrivateService: construction, Arc handles, boot reconcile
src/grasp_p/meta.rs         heed env + typed tables (see §4)
src/grasp_p/registration.rs 30640 validation + apply (modes, alias/key claims)
src/grasp_p/state_root.rs   30641 validation + edition ring append
src/grasp_p/write_keys.rs   write/aux-key index queries
src/grasp_p/quota.rs        ledger: check_and_charge / release, per tenant+alias+global
src/grasp_p/blob_store.rs   disk store: streamed write, read, exists, remove, sharded paths
src/grasp_p/blossom_auth.rs kind-24242 verification (see §6)
src/grasp_p/gc.rs           background pass: grace-expired unreferenced blobs
```

`PrivateService` (all methods take `&self`; internal sync via `parking_lot::Mutex` around
heed write txns — writes are small):

```rust
pub struct PrivateService { /* config: PrivateConfig (extracted subset), meta: MetaEnv,
    blobs: BlobStore, database: SharedDatabase (relay DB handle for liveness checks) */ }

impl PrivateService {
    pub async fn new(config: &Config, database: SharedDatabase) -> anyhow::Result<Arc<Self>>;
    /// admit_event arms call these; return the existing WritePolicyResult vocabulary
    pub async fn handle_registration(&self, event: &Event) -> WritePolicyResult;   // 30640
    pub async fn handle_state_root(&self, event: &Event) -> WritePolicyResult;     // 30641
    pub async fn handle_wrap(&self, event: &Event, ephemeral: bool) -> WritePolicyResult; // 1059/21059
    /// blob routes
    pub async fn blob_upload_preflight(&self, auth: &BlossomAuth, sha256: &str, len: u64) -> Result<(), BlobError>;
    /// Streaming upload: HTTP layer feeds hyper Incoming frames into an UploadSink.
    /// begin_upload validates auth+quota (like preflight) and opens <blob_root>/tmp/<rand>;
    /// sink.write_chunk(&[u8]) hashes+counts+aborts 413 on overrun of min(declared_len, max);
    /// sink.finish() verifies hash==auth.x, fsyncs, renames into <aa>/<bb>/<sha256>, claims
    /// + charges; Drop without finish removes the temp file.
    pub async fn begin_upload(&self, auth: &BlossomAuth, declared_len: u64) -> Result<UploadSink, BlobError>;
    pub fn blob_path(&self, sha256: &str) -> Option<PathBuf>;   // None if absent or denylisted(451 handled by caller via is_denylisted)
    pub fn is_denylisted(&self, sha256: &str) -> bool;
    pub async fn blob_delete(&self, auth: &BlossomAuth, sha256: &str) -> Result<(), BlobError>;
    pub async fn blob_list(&self, tenant: &PublicKey) -> Vec<BlobDescriptor>;
    pub fn spawn_gc(self: &Arc<Self>) -> JoinHandle<()>;
}
```

Rejections reuse the `restricted:` / `invalid:` / `blocked:` prefix vocabulary of
`src/nostr/policy/result.rs`. Quota rejections: `restricted: quota exceeded` (events) /
HTTP 507 (blobs). Unregistered-key wraps: `restricted: unregistered key`.

## 4. Meta store (heed at NGIT_GRASP_P_META_DATA_PATH)

Add direct dep `heed` matching the transitively-pinned version in Cargo.lock (0.20.x — same
one nostr-lmdb uses) + `parking_lot`. Tables (Str/SerdeBincode or manual bytes):

- `registrations`: alias → RegistrationRecord { tenant_hex, event_id, w_keys: Vec<[u8;32]>,
  aux_keys, relays, servers, quota_class, created_at, tombstoned_at: Option<u64> }
- `key_claims`: pubkey_hex → alias (covers w AND aux keys; first-registrant-wins)
- `tenant_aliases`: tenant_hex → Vec<alias>
- `ledger`: key `t:<tenant>` / `r:<alias>` / `g:` → LedgerEntry { event_bytes, blob_bytes }
- `blob_claims`: sha256 → BlobClaim { size, aliases: Vec<alias>, unreferenced_since: Option<u64> }
- `state_ring`: `<alias>:<created_at:020>:<event_id>` → 30641 event JSON; append trims to
  NGIT_GRASP_P_STATE_HISTORY_EDITIONS per alias (G7 amendment: the relay DB keeps only the
  latest addressable edition — this ring is the lost-update recovery net)

Boot reconcile (`PrivateService::new`): query relay DB for all kind-30640 events, rebuild
registrations/key_claims/tenant_aliases if meta env is empty or inconsistent (log diffs).
Ledger and blob_claims are authoritative in meta (never recomputed from disk at boot; a
doctor-style consistency scan can come later).

### 4b. Replay/replacement ordering (correctness-critical)

`admit_event` runs BEFORE the library's `save_event`, which may still reject the event as
`Replaced` (older than stored edition; equal created_at → lowest id wins) or `Duplicate`.
Meta mutations must therefore mirror nostr-lmdb's replacement semantics: `handle_registration`
applies index/ledger changes ONLY if the event is strictly newer than the stored
RegistrationRecord (or equal created_at with lower id); otherwise Accept without meta changes
(the DB will discard it). 30641 ring appends are idempotent by event id and ordered by
(created_at, id). This keeps meta and relay DB convergent under replays and out-of-order sync.

## 5. Admission semantics

**30640** (`handle_registration`): size cap → shape checks (§2) → tenant-liveness rules:
  - alias registered to a DIFFERENT tenant → `restricted: alias already registered`.
  - any claimed w/aux key held by a DIFFERENT alias → `restricted: write key already registered`.
  - NEW alias: apply registration_mode — open: accept; whitelist: tenant npub (bech32) ∈
    whitelist CSV else `restricted:`; pow: `event.id.check_pow(pow_bits)` else `restricted:`.
    Cap aliases-per-tenant.
  - SAME alias + same tenant (rotation/update): always allowed regardless of mode (mode
    gates only NEW aliases). Diff the key sets: released keys freed in key_claims, new keys
    claimed (subject to the different-alias conflict rule). Relay DB replacement of the old
    30640 edition is native (addressable). Update meta atomically in one write txn.
  - Charge event bytes to tenant ledger (30640s are small; still counted).
**30641** (`handle_state_root`): size cap → shape (§2) → alias registration live (query meta
  + verify the 30640 coordinate still exists in relay DB — self-healing vs missed deletes) →
  outer pubkey ∈ that alias's w set (NOT aux) → every m/pack size ≤ max_blob_bytes → quota
  check event bytes → accept; then: append to state_ring (trim to N), update blob_claims
  (claim hashes for alias; hashes no longer referenced by ANY retained ring edition of this
  alias → mark unreferenced_since=now), charge event bytes.
**1059/21059** (`handle_wrap`): size cap → outer pubkey ∈ key_claims (w or aux) → alias
  live → quota (charge only stored 1059, not ephemeral 21059) → Accept. Else FALL THROUGH:
  return None-equivalent so builder.rs continues to `handle_related_event` (public path
  unchanged). Implement arms as: if private enabled and handler returns a definitive
  result use it; for wraps from unregistered keys, fall through to the existing catch-all.

admit_event integration (src/nostr/builder.rs, in the match before `_ =>`):
```rust
k if private.is_some() && k.as_u16() == 30640 => private.handle_registration(...)
k if ... == 30641 => private.handle_state_root(...)
k if ... == 1059  => match private.try_handle_wrap(...) { Some(r) => r, None => self.handle_related_event(...) }
k if ... == 21059 => same as 1059 with ephemeral=true
```
(Exact style: give `Nip34WritePolicy` an `Option<Arc<PrivateService>>` field set in
`create_relay`; kinds compared via `as_u16()` — never pattern-match `Custom(_)`.)

## 6. Blossom auth (kind 24242, `blossom_auth.rs`)

`Authorization: Nostr <base64(event-json)>` header. Verify: kind 24242; valid sig+id;
`t` tag ∈ {upload, delete} matching the operation; `expiration` tag in the future;
`x` tag = the exact sha256 being operated on (REQUIRED for both upload and delete);
MANDATORY `a` tag = `30640:<tenant-hex>:<alias>` (attribution — resolves to a live
registration); signing pubkey ∈ that alias's **w** set (aux keys cannot PUT/DELETE).
created_at within ±24 h. Errors → 401 (malformed/expired) or 403 (key not authorized).

## 7. HTTP routes (src/http/mod.rs)

Insertion point: after the git-URL block, BEFORE the NIP-11 Accept check (between current
lines ~637-640) — verified: 1-2 segment paths can't collide with `parse_git_url` (≥3 seg)
or the npub landing route. Gate all routes on `private_repos_enable`. Extend CORS consts:
methods += `PUT, DELETE, HEAD`; headers += `Authorization, X-SHA-256, X-Content-Length`.
Existing universal OPTIONS→204 covers preflight.

- `HEAD /upload` — BUD-06 preflight: headers `X-SHA-256` (64-hex) + `X-Content-Length`
  (u64) + Authorization. 200 OK / 400 / 401 / 403 / 413 (blob too big) / 507 (quota).
  Reason in `X-Reason` header.
- `PUT /upload` — same auth; `Content-Length` REQUIRED (411 if absent; also preflight-check
  it against quota/max before reading body). Stream `hyper::body::Incoming` frame-by-frame
  to `<blob_root>/tmp/<uuid>` while feeding sha256 + byte counter; abort 413 mid-stream on
  overrun (and if actual bytes exceed Content-Length); final hash must equal the auth `x`
  tag else 400 + delete temp; fsync + rename to `<blob_root>/<aa>/<bb>/<sha256>`; claim +
  charge. Blob already present: still verify auth, add claim if new, 200 (idempotent, no
  double-charge). Response JSON (BUD-01 blob descriptor): url, sha256, size, uploaded.
- `GET|HEAD /<64-lowercase-hex>` — public, unauthenticated (v1 by design: mirroring depends
  on it). 451 if denylisted; 404 if absent; else stream file via the existing
  mpsc/StreamBody response pattern (8 KiB chunks), `content-type: application/octet-stream`,
  `cache-control: public, max-age=31536000, immutable`, `content-length` set.
- `DELETE /<64-hex>` — Blossom auth t=delete; removes THIS alias's claim; file removal is
  GC's job after grace. 200 even if claim absent (idempotent).
- `GET /list/<pubkey-hex-or-npub>` — JSON array of blob descriptors for that tenant's
  aliases. (Aggregate only; no per-blob alias mapping in the response beyond hashes/sizes.)

Threading: `Option<Arc<PrivateService>>` field on `HttpService`, threaded through
`run_server` / `run_server_on_listener` / `RelayServer::run_until` (all already
`too_many_arguments`). Constructed in `RelayServer::start` after `create_relay` (needs
SharedDatabase), passed to both the write policy and HTTP. `spawn_gc` handle pushed to
`background_tasks`.

## 8. NIP-11 (src/http/nip11.rs)

When enabled, add field `private_repos` (serde `skip_serializing_if = "Option::is_none"`):
`{ "kinds": [30640, 30641, 1059, 21059], "registration_mode": "...", "pow_bits": n?,
"max_blob_bytes": n, "max_event_bytes": n, "quota_tenant_bytes": n, "quota_repo_bytes": n,
"blob_endpoints": ["https://<domain>"] }`. Note in supported_nips: add 24242-relevant BUDs
are HTTP-side, not NIPs — do NOT add fake NIP numbers.

## 9. Metrics

Aggregate only (default): counters `ngit_private_registrations_total{mode}`,
`ngit_private_events_{accepted,rejected}_total{kind}`, `ngit_private_blob_bytes_stored`,
`ngit_private_blob_{uploads,downloads}_total`, gauges `ngit_private_ledger_bytes{scope="global"}`,
`ngit_private_aliases_total`. Per-tenant labels ONLY when NGIT_GRASP_P_PER_TENANT_METRICS=true.
Follow the lazy_static free-function style (metrics/mod.rs) — do NOT construct a second
`Metrics` instance (global REGISTRY panics on duplicate registration).

## 10. Phase-1 exit tests (tests/private_repos.rs, TestRelay-based)

1. enable=false: 30640 → `restricted:` orphan (unchanged behavior); /upload → 404.
2. open mode E2E: 30640 accepted (REQ round-trip) → preflight 200 → PUT 2 blobs (few KiB)
   → GET both (hash-verified) → 30641 accepted → state_ring visible via second 30641
   (relay serves only latest; both blob sets still GET-able).
3. foreign-key wrap: 1059 signed by unregistered key → `restricted:`; registered w-key 1059
   → accepted + served to anonymous REQ; 21059 → OK, broadcast to live sub, not stored.
4. quota: tiny NGIT_GRASP_P_QUOTA_REPO_BYTES → PUT #2 → 507; oversize single blob → 413 at
   preflight AND mid-stream (chunked PUT with lying preflight).
5. auth failures: bad sig 401; wrong-alias key 403; x-mismatch 400; expired 401.
6. whitelist mode: non-listed tenant rejected, listed accepted. pow mode: low-pow rejected,
   sufficient-pow accepted (use small bits, e.g. 8, for test speed).
7. write-key conflict: second tenant claiming same w key → rejected; alias collision across
   tenants → rejected; rotation w={old,new}→w={new} frees old key.
8. registration deleted (NIP-09 a-tag) → subsequent 30641/1059 rejected (liveness check).
```
