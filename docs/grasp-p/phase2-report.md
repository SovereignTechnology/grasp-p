# GRASP-P Phase 2 — as-built report (2026-07-18)

Two-node replication shipped on branch `grasp-p`. Build clean, 0 warnings. Tests:
**private_two_node 41/41** (5 exit scenarios + fixture units), **sync 64/64** (regression guard,
2 pre-existing ignores), **phase0 42/42**, **private_repos 44/44**, lib 536+3/… green. Observed
A→B replication latency under NGIT_TEST=1: **~0.73 s** for the full event+blob set (design bound
was 120 s).

## What shipped
- **Private-sync filters** (`src/sync/filters.rs`): `build_private_registration_filter`
  (kinds:[30640], L1-sibling, always-on, excluded from consolidation) +
  `build_private_derived_filters` (per-100-alias 30641 `#d` chunks, per-100-key 1059 `authors`
  chunks; 21059 never synced).
- **PrivateSyncIndex** (`src/sync/private_index.rs`): alias→{keys, relay/server urls}, rebuilt
  from the relay DB's 30640s by a 5 s (200 ms in tests) timer; on change it connects newly
  listed peer relays and re-issues derived filters to every connected peer. NIP-09-deleted
  30640s fall out on the next rebuild.
- **PrivateRejectedIndex** (out-of-order): a dedicated hot cache (author-keyed for 1059,
  alias-keyed for 30641; 4096-event cap, TTL = rejected-hot-cache-duration) draining via two
  reprocess hooks — inline on synced-30640 Accept and in the registration timer for
  client-pushed 30640s. The reject-and-hold now also fires on the **WS admission path** (a real
  bug the test author caught: exit-2 failed until WS-path 30641/1059 rejections were held, not
  just sync-path ones).
- **Blob mirror** (`src/private/mirror.rs`): pull-only over the peer's existing public
  `GET /<sha256>`. handle_state_root Accept enqueues a job; a worker (semaphore-bounded,
  in-flight-deduped) + periodic repair scan streams each missing blob through the Phase-1
  UploadSink (reservation → sha256 verify → fsync+rename → claim+charge). Boot repair re-derives
  want-sets from retained 30641 claims. Metrics: `ngit_private_mirror_lag_blobs` gauge +
  fetched/failed counters. Best-effort with alerting (lag>0).
- **Parity fingerprint (R6)**: NIP-11 `private_repos.policy_fingerprint` (16-hex over the
  admission-affecting config incl. the sorted {A,B} domain set) + startup log. Raw whitelist
  never exposed. Equal across a correctly-paired A/B; changes on config divergence.
- All gated on `private_repos_enable` (+ mirror on `private_mirror_enable`). Disabled path is
  byte-identical to upstream — proven by the full existing `tests/sync` suite staying green.

## Security: SSRF finding caught + fixed post-workflow

The workflow's automated adversarial **correctness and security review agents did not run** —
both aborted on an Opus monthly-spend limit. A manual security pass over the highest-risk new
surface (the blob mirror's outbound HTTP) found a real **SSRF**:

- **Finding**: `peer_servers_for` derived mirror fetch targets from tenant-controlled 30640
  `server` tags. Phase-1 validation requires only that *one* server tag contains the node's own
  domain; any *other* tag (e.g. `http://169.254.169.254/…`, an internal host/port) was kept as a
  peer, and the reqwest client followed redirects and did not block private IPs. Content-exfil
  was already blocked by the sha256 verify, but blind request forgery, internal port-scanning via
  metric/timing oracles, and redirect-bouncing were live in the zero-config default.
- **Fix** (committed): new `NGIT_PRIVATE_MIRROR_ALLOW_PRIVATE_IPS` (default **false**; tests set
  true for the 127.0.0.1 pair). In production the mirror now requires **https**, resolves each
  peer host, and drops it if any resolved address is loopback/private/CGNAT/link-local/
  unspecified/multicast/ULA or an IPv4-mapped form thereof; **redirect-following disabled**
  (`redirect::Policy::none()`). Unit-tested (`is_disallowed_ip`, `peer_allowed`). Recommended
  production posture also documented: set `NGIT_PRIVATE_MIRROR_PEER_URLS` to the known peer.
- **Residual (documented)**: DNS-rebinding at connection time (host re-resolved by reqwest after
  the pre-check) is not fully closed; the explicit peer-URL override is the belt-and-braces
  mitigation. Track for Phase 4/5 hardening (pin the resolved IP, or a connect-time guard).

## Follow-ups deferred to Phase 4/5
- DNS-rebinding residual on the mirror (above).
- Re-run the full automated adversarial correctness + security review once model budget allows,
  as a second pass over the sync/mirror diff (the manual pass prioritized SSRF).
- 24242-gated blob GET with peer carve-out (Phase 5).
- PrivateRejectedIndex has no cold tier — a dependent rejected >TTL before its 30640 arrives is
  refetched on the next sync pass rather than reprocessed from cache. Acceptable; documented.

## Deviations from the design contract
- PrivateSyncIndex is DB-poll driven (timer), not inline in process_event_static — client-WS
  30640s never traverse that path and the DB is the single source of truth for both push paths +
  NIP-09 deletes. Converges within one interval (200 ms in tests).
- `NGIT_PRIVATE_MIRROR_PEER_URLS`, when set, REPLACES the tenant-derived peer list (override
  semantics; also the safe production posture).
- `check_disconnects` skips relays listed in accepted registrations when private is enabled
  (private peers carry no public repos; the empty-relay heuristic would flap them). Empty set /
  unchanged when disabled.
- policy_fingerprint domain set = {own domain} ∪ {bootstrap host} (a node cannot know the literal
  peer domain otherwise; under mandated pairing both nodes hash the identical {A,B} set).
