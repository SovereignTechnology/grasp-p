# GRASP-P split-view watchdog (`ngit-private-watchdog`)

External observer for two-node GRASP-P deployments. It anonymously probes
**both** nodes and alerts when their views of private-repo state diverge —
the canonical case being one node withholding a kind-30641 state-root
manifest that the other node serves (a *split-view* attack or a replication
break).

The watchdog holds **no keys**, signs nothing, and publishes nothing. Every
input it compares is anonymously readable by design:

- NIP-11 `private_repos.policy_fingerprint` / `registration_mode`
  (`GET /` with `Accept: application/nostr+json`)
- kind-30640 registrations and kind-30641 state roots (anonymous websocket
  REQ; if a relay demands NIP-42 auth for these reads, that is reported as
  an operational error — GRASP-P anonymous reads must stay open)
- Blob existence: `HEAD /<sha256>` (or `GET` with body verification) on each
  node's blob base URL

It does not compare `GET /list/<pubkey>`: that route answers only the listed
key, and the watchdog holds none. Stored blobs that no currently served state
root names (uploads not yet referenced, and blobs only superseded editions
name) are therefore outside its view. No reader fetches such a blob, so no
split view of repository content can hide there. The `--tenant` flag went with
the check: a unit that still passes it exits 2 on a usage error.

## Build

```bash
cargo build --release --bin ngit-private-watchdog
# binary: target/release/ngit-private-watchdog
```

## Run

```
ngit-private-watchdog --relay-a wss://A --relay-b wss://B \
  [--alias ALIAS]... \
  [--blob-base-a URL] [--blob-base-b URL] \
  [--blob-probe head|get|none] \
  [--timeout-secs 30] [--max-skew-secs 300] [--json]
```

- **Discovery**: with no `--alias`, all kind-30640s are fetched from both
  relays and the alias set is their union. With `--alias`, only those
  aliases are watched.
- **Blob base URLs**: default derived from registrations' `server` tags —
  the value whose scheme, host, AND effective port match the node's relay
  endpoint (`https` for `wss` relays, `http` for `ws`; default ports
  normalized, so `https://host` and `https://host:443` are equivalent). The
  host match is the SSRF guard: a tenant-controlled `server` tag can never
  point the watchdog anywhere but the node's own host, and the scheme/port
  match stops derivation latching onto the wrong scheme or an arbitrary
  port on that host. When the relay URL given to the watchdog has a path
  (a node under `NGIT_BASE_PATH`, e.g. `wss://host/grasp`), only the values
  with that same path are candidates, because that node's blob routes are
  under it; the rest of this paragraph is about a relay URL at the root of
  its host. Multiple matching values that differ ONLY by path
  (e.g. `https://host` and `https://host/x` — the common nginx path-vhost
  shape) are NOT ambiguous: the path-empty value wins deterministically.
  Genuine ambiguity — one endpoint spelled two ways (e.g. `https://host`
  vs `https://host:443`), or a path-only tie with no unique path-empty
  candidate — still errors; pass `--blob-base-a`/`--blob-base-b` explicitly
  (the blob-dependent check errors out with that guidance rather than
  guessing — checks 1–3 are unaffected).
- **kind-30641 author filters** are derived from each alias's `w` tag union
  across both nodes (aux keys cannot author state roots).

### Exit codes

| Code | Meaning | stderr |
| ---- | ------- | ------ |
| 0 | all checks pass | empty |
| 1 | divergence alert | every FAIL line + `WATCHDOG ALERT` summary (plus any operational-error lines) |
| 2 | operational error, no divergence (node unreachable, timeout, unexpected HTTP status, underivable/ambiguous blob base, incomplete probe coverage) | `WATCHDOG OPERATIONAL ERROR: ...` |

A node that is down is **never** reported as divergence: partial failure is
exit 2, so connection problems cannot be mistaken for a split view.

**Completed check results are never suppressed.** Checks 1–3 (fingerprint,
registration, manifest parity) are computed and printed even when the
blob-dependent check 4 fails operationally; it then emits its
own per-check `ERROR` lines (e.g. `ERROR blob-existence ... -- blob base
unresolved: ...; pass --blob-base-a/--blob-base-b explicitly`) instead of
aborting the run. Divergence dominates: the exit code is **1** whenever any
check FAILs, even if operational errors also occurred; **2** only when
operational errors occurred with no divergence. In `--json` mode the
accumulated operational errors are in `operational_errors` and the summary
carries an `error` count. A genuine blob-base ambiguity (host-matching
`server` tags with no unique path-empty candidate) therefore wedges ONLY
check 4, never the run.

### Checks

1. **fingerprint-parity** — NIP-11 `private_repos.policy_fingerprint` must
   be present and equal on both nodes (a correctly paired setup hashes the
   same sorted `{own domain} ∪ {bootstrap peer}` set on both sides).
   `registration_mode` and `policy_version` are reported for each side. On a
   mismatch the detail names which case it is: a **VERSION SKEW** (the
   `grasp-p-policy-vN` labels differ — a label bump moves every node's
   digest, so a rolling upgrade fails this check for the whole window) or a
   **SAME-VERSION knob split** (a real acceptance divergence).
1b. **kinds-parity** — NIP-11 `private_repos.kinds` must be the same SET on
   both nodes; the line names the kinds only one side admits (`only-a=` /
   `only-b=`). Its own check because the fingerprint digest folds a dozen
   knobs into 16 opaque hex chars: a stream-wrap kind split (1059/21059 vs
   3359/23359) means events one node stores are refused by the other and
   never replicate. SKIP when neither node advertises `private_repos`
   (private repos disabled — check 1 reports that).
   **Scope:** this compares what the nodes SAY they accept. No check
   compares stream-wrap SETS; wrap divergence is not covered by any
   data-parity check here.
2. **registration-parity** — per alias, the latest kind-30640 (highest
   `created_at`; ties broken by **lowest** event id, matching the relay's
   addressable tie-break) must be the same event id with the same
   `w`/`aux`/`relays`/`server` tag sets on both nodes.
3. **manifest-parity** — *the split-view check.* Per (alias, author), the
   latest kind-30641's `m` tag (hash, size) and sorted `pack` set must be
   identical on both nodes.
   - Present on one node, absent on the other: FAIL
     `reason=withheld-30641` once the edition's `created_at` is older than
     `now - --max-skew-secs` (default 300). The boundary is **exclusive**:
     age exactly equal to the window is still within grace; future-dated
     editions (author clock ahead) are always within grace. Inside the
     window the line is PASS with a "replication in flight?" note.
   - Both nodes have a latest edition but content differs: FAIL
     `reason=diverged` under the same grace rule applied to the newest
     involved `created_at`.
4. **blob-existence** — every manifest/pack sha referenced by the compared
   latest manifests must answer `200` on **both** blob bases. `404` is
   reported as missing, `451` distinctly as denylisted. `--blob-probe get`
   additionally streams the body and verifies its sha256 and declared size
   (early-abort just past the largest declared size). Any other HTTP status
   or a transport failure is an operational error (exit 2), never a data
   verdict.

### Output

Human mode prints one line per check to stdout:

```
PASS fingerprint-parity fingerprint=f9d937ac1a5851d8 policy-a=grasp-p-policy-v3 policy-b=grasp-p-policy-v3 mode-a=open mode-b=open
PASS kinds-parity kinds=1059,3359,21059,23359,30640,30641
PASS registration-parity alias=0123… event=ab12cd34
FAIL manifest-parity alias=0123… author=deadbeef reason=withheld-30641 -- kind-30641 present on A but absent on B; created_at=1785000000 age=912s exceeds --max-skew-secs=300
FAIL blob-existence probe=head probed=3 failed=1 -- sha=d24eb189 A=404 B=200
```

With `--json`, stdout is a single machine report instead (FAIL lines still
go to stderr):

```json
{
  "tool": "ngit-private-watchdog",
  "report_version": 1,
  "ok": false,
  "exit_code": 1,
  "now": 1785131227,
  "nodes": {
    "a": { "relay": "wss://node-a.example.com", "blob_base": "https://node-a.example.com",
           "nip11_policy_fingerprint": "f9d937ac1a5851d8", "nip11_registration_mode": "open",
           "malformed_30640_ignored": 0, "malformed_30641_ignored": 0 },
    "b": { "relay": "wss://node-b.example.com", "blob_base": "https://node-b.example.com",
           "nip11_policy_fingerprint": "f9d937ac1a5851d8", "nip11_registration_mode": "open",
           "malformed_30640_ignored": 0, "malformed_30641_ignored": 0 }
  },
  "params": { "timeout_secs": 30, "max_skew_secs": 300, "blob_probe": "head",
              "aliases": ["0123…"] },
  "checks": [
    { "check": "manifest-parity", "status": "FAIL",
      "scope": { "alias": "0123…", "author": "deadbeef", "reason": "withheld-30641" },
      "detail": "kind-30641 present on A but absent on B; created_at=1785000000 age=912s exceeds --max-skew-secs=300" }
  ],
  "summary": { "total": 6, "pass": 4, "fail": 2, "skip": 0 }
}
```

## systemd (timer-driven, every 5 minutes)

`/etc/systemd/system/ngit-private-watchdog.service`:

```ini
[Unit]
Description=GRASP-P split-view watchdog (one-shot)

[Service]
Type=oneshot
ExecStart=/usr/local/bin/ngit-private-watchdog \
  --relay-a wss://node-a.example.com \
  --relay-b wss://node-b.example.com \
  --json --timeout-secs 30 --max-skew-secs 300
# Exit 1 = divergence alert, 2 = operational error; both land in the journal.
```

`/etc/systemd/system/ngit-private-watchdog.timer`:

```ini
[Unit]
Description=Run the GRASP-P split-view watchdog every 5 minutes

[Timer]
OnCalendar=*:0/5
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
systemctl daemon-reload
systemctl enable --now ngit-private-watchdog.timer
```

### Consuming alerts

- **Journal**: `journalctl -u ngit-private-watchdog.service --since "10 min ago"`.
  FAIL lines are on stderr in all modes, so
  `journalctl ... -p warning` style filters and journal-based alerting
  (e.g. `systemd-journal-gatewayd`, log shippers) see them directly.
- **Cron-style mail**: run the binary without `--json`; stderr non-empty
  means "act". Exit code distinguishes divergence (1) from "the watchdog
  itself couldn't tell" (2) — page on 1, investigate on 2.
- **Machine pipelines**: `--json` stdout; `jq '.summary.fail > 0'`, or
  `jq -r '.checks[] | select(.status=="FAIL")'`.

## Tuning notes

- **Resource bounds (fixed caps, not knobs).** The watchdog is an
  internet-facing client of both nodes; every unbounded input is capped so a
  hostile or broken node cannot turn it into a memory/connection amplifier:
  - Blob probes run with at most **32 probe tasks in flight** (one HEAD/GET
    per node per task).
  - At most **10 000 distinct blob shas** are probed per run; excess targets
    are skipped loudly: the check reports `ERROR` with `skipped=N` plus a
    "NOT probed this run" note and the run exits **2** — partial coverage
    never reads as a clean PASS (exit 0).
  - A NIP-11 response body is read with a **4 MiB cap**; a larger body is
    an operational error, not something to buffer.
  - A single REQ batch returning more than **100 000 events** is refused as
    an operational error (ingress within the window is already bounded by
    `--timeout-secs`; this bounds what is retained and compared).
- **Malformed events are counted, not compared.** kind-30640/30641 events
  that fail shape validation are excluded from comparison and counted per
  node (`malformed_30640_ignored` / `malformed_30641_ignored` in `--json`).
  In human mode a `NOTE malformed-events node=X ignored-30640=N
  ignored-30641=M` line prints whenever either count is non-zero — a
  sustained non-zero count means a broken writer or a probing attacker, not
  a split view.
- `--max-skew-secs` must comfortably exceed the pair's normal replication
  lag (observed seconds on healthy pairs). Too small = false withheld
  alerts during ordinary propagation; too large = slower detection of a
  real split view. The 300s default is deliberately conservative.
- `--timeout-secs` applies per request (relay connect, each REQ, each HTTP
  call), not globally.
- **Withholding invisibility window.** A withheld kind-30641 stays
  invisible to the watchdog for up to `--max-skew-secs` **plus** the
  server's future-dating bound: nodes admit events dated up to 900s ahead
  (`MAX_FUTURE_SKEW_SECS`, src/grasp_p/mod.rs:307), and the grace clock runs
  from the edition's `created_at`, so an author who maximally future-dates
  keeps a withheld edition unaccusable for skew + 900s — **1200s at the
  300s default**. Detection latency claims should use the sum, not the skew
  alone.
- **Active-refresh suppression.** The grace rule compares the NEWEST
  involved `created_at`, so a malicious author who republishes the withheld
  edition (same content, fresh `created_at`) more often than every
  `--max-skew-secs` keeps the divergence in grace indefinitely — each run
  reports a PASS "replication in flight?" note instead of FAIL. Tells: the
  same (alias, author) showing within-grace notes across consecutive runs,
  or visible edition churn in the relay DB. Mitigations: tighten
  `--max-skew-secs` toward the pair's real replication lag, and alert on
  manifest churn (an alias republishing state roots far more often than the
  tenant's push cadence).
- **`now` is captured once per run.** All grace comparisons in a run use
  the same timestamp, so a long run delays true alerts by at most the run
  duration — negligible at the recommended 5-minute timer cadence.
- `--blob-probe get` downloads every referenced blob from both nodes per
  run; on large repos prefer a longer timer interval or `head`.
- The E2E semantics are pinned by `tests/private_watchdog.rs` (healthy pair
  → exit 0; partitioned pair → exit 1 with `reason=withheld-30641` /
  `reason=diverged`; grace window suppresses both).
