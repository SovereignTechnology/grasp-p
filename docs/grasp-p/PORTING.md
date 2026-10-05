# Porting GRASP-P onto ngit-grasp v3

Working notes for the port from the v1.2.0-based line (`legacy/v1.2-grasp-p`) to
upstream v3.0.7. Delete this file when the port is merged.

## State

The port is complete and builds. `cargo fmt --check` and
`cargo clippy --workspace --all-targets --locked -D warnings` are clean under the pinned
Rust 1.96.0. The four GRASP-P suites pass: `phase0_gates` 60, `private_repos` 93,
`private_two_node` 68, `private_watchdog` 59. See "Gate results" below for upstream's suite.

## How the port is laid out

GRASP-P code lives in `src/grasp_p/`, `src/http/blossom.rs`, `src/sync/private_index.rs`,
`src/sync/grasp_p_sync.rs` and `src/bin/ngit-private-watchdog.rs`. Upstream's files carry
thin seams only:

| Upstream file | Seam |
|---|---|
| `src/nostr/builder.rs` | `Nip34WritePolicy` holds the service (`set_grasp_p` / `grasp_p()`); `admit_event` calls `grasp_p::admission::admit` after the blacklist and deletion gates, frees key claims after an honored kind 5 / 62, logs NIP-56 reports; `create_relay` builds the service; `RelayRuntime.grasp_p` |
| `src/server.rs` | spawns GC, mirror and denylist reload (`grasp_p::spawn_background_tasks`); passes the service to HTTP |
| `src/http/mod.rs` | `HttpService.grasp_p`; widened CORS on OPTIONS; blob routes matched on the base-path-stripped path (`blossom::match_route`) just before NIP-11 |
| `src/config.rs` | `NGIT_GRASP_P_*` settings and their validation, including the GRASP-08 exclusion |
| `src/sync/mod.rs` | `grasp_p` state field; GRASP-P filters added to `sync_generic_filters`, `sync_generic_history` and `complete_live_filters`; timer spawn; previously-rejected skip; after-saved / after-rejected hooks in `process_event_static_inner`; peers kept in `check_disconnects` |
| `src/sync/history.rs` | negentropy also skips known-rejected GRASP-P ids |
| `src/sync/relay_connection.rs` | forwards SDK-deduplicated events, only when GRASP-P is enabled |
| `src/sync/filters.rs`, `src/metrics/mod.rs`, `src/http/nip11.rs`, `src/nostr/lifecycle/deletion/service.rs`, `src/lib.rs` | additive helpers, carried by three-way apply |

Every seam is inert with `NGIT_GRASP_P_REPOS_ENABLE` unset: no service is built, the admission
arms, blob routes, sync filters, timers and duplicate forwarding are all gated on it, and the
GRASP-P metrics register lazily on first use.

## Decisions made during the port

- **Names.** `HttpService.private` and the write-policy field are `grasp_p`;
  `TestRelay::start_with_private_repos` / `start_private_pair_node` are `start_with_grasp_p` /
  `start_grasp_p_pair_node`. The `Config` field names (`private_repos_enable`,
  `private_mirror_enable`, ...) are unchanged; only their environment variables were renamed.
  Their clap long flags (`--private-repos-enable`) therefore still say "private". They do not
  collide with upstream's GRASP-08 fields; renaming them is a possible follow-up.
- **GRASP-08 exclusion.** `NGIT_GRASP_P_REPOS_ENABLE=true` with `NGIT_PRIVATE_MODE=true` is a
  fatal config error. Documented in all four config sources; unit test in `src/config.rs`.
- **Consolidation.** Upstream's consolidation replaces a relay's whole live subscription set with
  `complete_live_filters`. The GRASP-P filters are part of that set, so a consolidation keeps
  them; the legacy `maybe_consolidate` call is replaced by upstream's minimal live extension,
  with the same fallback to a deferred consolidation that `handle_new_sync_filters` uses.
- **Outbound policy.** The mirror's SSRF guards (`peer_allowed`, `relay_peer_allowed`) now go
  through `crate::outbound::OutboundTargetPolicy::authorize_resolved`, then re-check every vetted
  address with our `is_disallowed_ip`, which also decodes NAT64 / 6to4 / IPv4-compatible forms
  that upstream's `is_globally_reachable` does not. Production still requires https / wss. GRASP-P
  peers register as event-directed targets, so upstream's dial-time policy applies to them too.
  Addresses are not pinned yet (DNS rebinding, M3 #3).
- **Duplicate forwarding.** Legacy made `RelayConnection` forward events nostr-sdk reports as
  already seen, unconditionally. It is now behind `with_duplicate_event_forwarding`, set only
  when GRASP-P is enabled, so a public node's sync is unchanged.
- **Hold expiry.** Legacy expired held GRASP-P events inside upstream's rejected-index cleanup
  and shortened that cleanup's interval under `NGIT_TEST=1`. The expiry now runs on GRASP-P's own
  registration timer and upstream's cleanup is untouched.
- **Log lines** keep their legacy wording ("Private ..."): tests and ops docs match on them.

## Behaviour that changed with upstream

- **Kind 1059 needs exactly one `p` tag.** nostr-sdk 0.45's local relay refuses a kind-1059
  event without exactly one `p` tag before any write policy runs. The tagless 1059 stream wraps
  of the legacy window can therefore no longer reach the GRASP-P arm; 21059 is unaffected, and a
  1059 with one `p` tag still is. The client moved to 3359 already and M4 drops the window.
  `exit3`, `exit36` and `exit38` were adapted: the cases meant to reach the GRASP-P arm carry one
  `p` tag, and `exit36` pins the SDK refusal of the tagless form.
- **Relay event-size ceiling.** v3 added `NGIT_RELAY_MAX_EVENT_SIZE_BYTES` (default 192 KiB),
  enforced ahead of the write policy. Phase-0 gate G4 now asserts that 128 KiB passes and 1 MiB
  is refused there (it asserted 1 MiB passed on v1.2). Config validation warns when
  `NGIT_GRASP_P_MAX_EVENT_BYTES` exceeds the relay ceiling.
- **nostr 0.45.5 API.** Types are no longer re-exported at the crate root (`nostr::prelude::*`),
  `nostr::hashes` is gone (`bitcoin_hashes`), `nostr::secp256k1` / `SECP256K1` are gone
  (`secp256k1` 0.30, already in the tree, is now a direct dependency for the proof-of-possession
  check; schnorr signing and verification take the 32-byte digest directly),
  `SingleLetterTag::lowercase(Alphabet::X)` is `SingleLetterTag::LOWERCASE_X`, and
  `EventBuilder::text_note` is gone.

`Cargo.lock` gained only dependency edges (`heed` serde features, `parking_lot`, `secp256k1`,
`url`, `uuid` on `ngit-grasp`); no new packages.

## Gate results

Cloud sandbox, 2026-10-05, Rust 1.96.0, git 2.43.0, running as root:

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | clean |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | clean |
| `cargo test --locked` | 4034 passed, 0 failed, 11 ignored (all upstream's own `ignore`s), 56 binaries; lib 1086 |
| `cargo test -p grasp-audit --locked` | 95 passed, 0 failed, 5 ignored |
| `phase0_gates` / `private_repos` / `private_two_node` / `private_watchdog` | 60 / 93 / 68 / 59 passed, none ignored |

Upstream's tests are unmodified; `tests/common/relay.rs` only gained the two GRASP-P constructors
and the `extra_env` option.

**Git version.** Upstream v3.0.7 needs git 2.42 or newer. `complete_in_family` in
`src/git/staging.rs` passes `--glob=refs/grasp/retained/*` on the stdin of `git rev-list --stdin`,
and git before 2.42 refuses that ("fatal: options not supported in --stdin mode"), so promotion of
pushed history fails. With a git 2.39.5 built from kernel.org source, the three
`git::staging::tests` that failed on the CI runner fail here identically; with 2.43.0 all 19 pass.
This is production code, not only tests: the CI image and the production image need git >= 2.42
(Debian bookworm ships 2.39.5).

## What is left

- The cord-git end-to-end suite against this build (see the handoff).
- M3 items that the port touched but did not do: address pinning in the mirror (#3),
  `GET /list/<pubkey>` authorization (#14), and an adversarial re-review of the ported sync and
  mirror (#10). One point for that review: as on the legacy line, the GRASP-P filters (including
  the derived alias set) go to every connected sync relay, not only to configured peers.
