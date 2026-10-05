# GRASP-P on upstream ngit-grasp: seams and differences

GRASP-P is an overlay on upstream ngit-grasp, v3.0.7 today. This page records where the
overlay touches upstream's files, the decisions taken when it was ported from the v1.2.0
line (`legacy/v1.2-grasp-p`), and what behaves differently from that line. Read it before
an upstream sync: every seam listed here has to survive the merge.

## Layout

GRASP-P code lives in `src/grasp_p/`, `src/http/blossom.rs`, `src/sync/private_index.rs`,
`src/sync/grasp_p_sync.rs` and `src/bin/ngit-private-watchdog.rs`. Upstream's files carry
thin seams only:

| Upstream file | Seam |
|---|---|
| `src/nostr/builder.rs` | `Nip34WritePolicy` holds the service (`set_grasp_p` / `grasp_p()`); `admit_event` calls `grasp_p::admission::admit` after the blacklist and deletion gates, frees key claims after an honored kind 5 / 62, logs NIP-56 reports; `create_relay` builds the service; `RelayRuntime.grasp_p` |
| `src/server.rs` | spawns GC, mirror and denylist reload (`grasp_p::spawn_background_tasks`); passes the service to HTTP |
| `src/http/mod.rs` | `HttpService.grasp_p`; widened CORS on OPTIONS; blob routes matched on the base-path-stripped path (`blossom::match_route`) just before NIP-11 |
| `src/config.rs` | `NGIT_GRASP_P_*` settings and their validation, including the GRASP-08 exclusion |
| `src/sync/mod.rs` | declares `grasp_p_sync` and `private_index`; `grasp_p` state field; GRASP-P filters added to `sync_generic_filters`, `sync_generic_history` and `complete_live_filters`; `register_relay` builds each connection with `with_duplicate_event_forwarding`; timer spawn; previously-rejected skip; after-saved / after-rejected hooks in `process_event_static_inner`; peers kept in `check_disconnects` and counted as desired in `retry_disconnected_relays`; the service handed to both `HistoryJob`s (`historic_sync_with_options`, `spawn_history_queries`); the id and signature check in `process_event_static_inner` (see below) |
| `src/sync/history.rs` | negentropy also skips known-rejected GRASP-P ids |
| `src/sync/relay_connection.rs` | forwards SDK-deduplicated events, only when GRASP-P is enabled, after checking their id and signature and skipping the SDK's second copy of a new event; `fetch_events` drops fetched events whose id or signature does not verify |
| `src/sync/filters.rs`, `src/metrics/mod.rs`, `src/http/nip11.rs`, `src/nostr/lifecycle/deletion/service.rs`, `src/lib.rs` | additive helpers |
| `Cargo.toml` | direct dependencies `heed` (with its `serde` features), `parking_lot`, `uuid`, `url`, `secp256k1`; the `ngit-private-watchdog` binary target; for the TLS test, the dev-dependencies `openssl` and `tokio-rustls` |
| `tests/common/relay.rs` | the `extra_env` option and the constructors `start_with_grasp_p` / `start_grasp_p_pair_node` |
| `.env.example`, `docs/reference/configuration.md`, `nix/module.nix` | the `NGIT_GRASP_P_*` settings (the other three config sources) |
| `.gitignore`, `docs/how-to/prometheus-setup.md` | ignores for key files; a pointer to the GRASP-P alert rules |

With `NGIT_GRASP_P_REPOS_ENABLE` unset no service is built, and the admission arms, blob
routes, sync filters, timers and duplicate forwarding are all gated on it; the GRASP-P
metrics register lazily on first use. One seam is deliberately not gated: the id and
signature check on synced and fetched events, which fixes a flaw in upstream itself.

## Synced events are verified here

nostr-sdk 0.45.4 caches verified events by the id they claim (`verify_and_cache`). After a
relay has delivered one genuine event, it can send other content under that id, with any
author and any signature, and the SDK passes it on unchecked. Upstream's sync trusted the
SDK and never verified: `process_event_static_inner` went from the duplicate lookup to the
write policy, which trusts the author. A forged event reaches that function three ways:
through upstream's own `fetch_events` (missing-event recovery, dependency fetch, mailbox
and NIP-65 fetches); through any ordinary subscription once the SDK's list of seen ids
(35,000 per connection) has dropped an id that its verification cache (128,000) still
holds, at which point the SDK reports the forged copy as a new event; and, on a GRASP-P
node, through the duplicate-forwarding arm.

`process_event_static_inner` therefore verifies id and signature itself, after the
duplicate lookup. A failure is `Rejected(Other)`, not `Invalid`: `Invalid` is a final
verdict on the id, and a forged copy says nothing about the genuine event. `fetch_events`
drops what does not verify before its callers pick one event per id, so a forged copy
cannot stand in for the genuine one there, and the forwarding arm verifies too. Unit
tests: `synced_event_that_does_not_verify_is_refused_without_settling_its_id` and
`duplicate_forwarding_skips_the_paired_copy_and_drops_a_forged_redelivery`.

A node that synced before this check may hold a forged event under a genuine id; such an
id answers `Duplicate` from then on. No GRASP-P node has run in production, so there is
nothing of ours to scan.

The flaw is in unmodified upstream v3.0.7 and in nostr-sdk. Reporting it to both is the
maintainer's call. When upstream verifies on its own, drop this seam in the sync that
brings the fix.

## Decisions made during the port

- **Names.** `HttpService.private` and the write-policy field are `grasp_p`;
  `TestRelay::start_with_private_repos` / `start_private_pair_node` are `start_with_grasp_p` /
  `start_grasp_p_pair_node`. The `Config` field names (`private_repos_enable`,
  `private_mirror_enable`, ...) are unchanged; only their environment variables were renamed.
  Their clap long flags (`--private-repos-enable`) and the nix options therefore still say
  "private". They do not collide with upstream's GRASP-08 fields; renaming them is a
  possible follow-up.
- **GRASP-08 exclusion.** `NGIT_GRASP_P_REPOS_ENABLE=true` with `NGIT_PRIVATE_MODE=true` is a
  fatal config error. Documented in all four config sources; unit test in `src/config.rs`.
- **Consolidation.** Upstream's consolidation replaces a relay's whole live subscription set
  with `complete_live_filters`. The GRASP-P filters are part of that set, so a consolidation
  keeps them; the legacy `maybe_consolidate` call is replaced by upstream's minimal live
  extension, with the same fallback to a deferred consolidation that
  `handle_new_sync_filters` uses.
- **Outbound policy.** The mirror's SSRF guards (`peer_allowed`, `relay_peer_allowed`) go
  through `crate::outbound::OutboundTargetPolicy::authorize_resolved`, then re-check every
  vetted address with our `is_disallowed_ip`, which also decodes the NAT64 and 6to4 forms
  that upstream's `is_globally_reachable` lets through (upstream already refuses every
  IPv4-compatible address). Production still
  requires https / wss. GRASP-P peers register as event-directed targets, so upstream's
  dial-time policy applies to them too. Addresses are not pinned yet (DNS rebinding, M3 #3).
- **Duplicate forwarding.** Legacy made `RelayConnection` forward events nostr-sdk reports
  as already seen, unconditionally. It is now behind `with_duplicate_event_forwarding`, set
  only when GRASP-P is enabled, so a public node's sync is unchanged. The SDK sends a new
  event twice (as `Event`, then inside `Message`); only the copy it did not also deliver as
  `Event` is forwarded. One consequence: a new GRASP-P event that is rejected and held is
  no longer accounted for by its second copy, so a negentropy batch that contains one does
  one extra retry round and logs "Negentropy sync incomplete".
- **Hold expiry.** Legacy expired held GRASP-P events inside upstream's rejected-index
  cleanup and shortened that cleanup's interval under `NGIT_TEST=1`. The expiry now runs on
  GRASP-P's own registration timer and upstream's cleanup is untouched.
- **Peers.** A configured peer is dialled when it is missing from the sync index, redialled
  by upstream's reconnect loop after a failed connection, and retried once a minute (and
  reported once) while it cannot be registered at all.
- **Advertised URLs.** NIP-11 `blob_endpoints` and the blob descriptors are built from
  `Config::service_address()`, so they carry `NGIT_BASE_PATH`. The check that a
  registration names this node still compares host and port only.
- **Log lines** keep their legacy wording ("Private ..."): tests and ops docs match on them.

## Behaviour that changed with upstream

- **Kind 1059 needs exactly one `p` tag.** nostr-sdk 0.45's local relay refuses a kind-1059
  event from a client without exactly one `p` tag before any write policy runs. The tagless
  1059 stream wraps of the legacy window can therefore no longer reach the GRASP-P arm from
  a client; 21059 is unaffected, and a 1059 with exactly one `p` tag still reaches it. The
  client emits 3359 only, and M4 drops the window. The setting
  `NGIT_GRASP_P_ACCEPT_LEGACY_WRAP_KIND` and its documentation still describe the tagless
  form.
- **Relay event-size ceiling.** v3 added `NGIT_RELAY_MAX_EVENT_SIZE_BYTES` (default 192 KiB),
  enforced ahead of the write policy for events from clients. Phase-0 gate G4 asserts that
  128 KiB passes and 1 MiB is refused there. Config validation warns when
  `NGIT_GRASP_P_MAX_EVENT_BYTES` exceeds the relay ceiling. Synced events do not pass that
  ceiling: only the SDK's 5 MB message limit bounds them.
- **Relay filter limits.** `NGIT_RELAY_FILTER_LIMIT` and `NGIT_RELAY_MAX_SUBSCRIPTIONS` (500
  each) are new in v3. The watchdog's discovery filter does not page, so its view of a node
  is cut short after 500 events per filter (M3 #10). The GRASP-P sync filters are sent
  through upstream's historic sync, which pages on REQ + EOSE and reconciles in full under
  negentropy; only their live subscriptions stop at the peer's limit.
- **nostr 0.45.5 API.** Types are no longer re-exported at the crate root
  (`nostr::prelude::*`), `nostr::hashes` is gone (`bitcoin_hashes`), `nostr::secp256k1` /
  `SECP256K1` are gone (`secp256k1` 0.30 is a direct dependency for the proof-of-possession
  check; schnorr signing and verification take the 32-byte digest directly),
  `SingleLetterTag::lowercase(Alphabet::X)` is `SingleLetterTag::LOWERCASE_X`, and
  `EventBuilder::text_note` is gone.

`Cargo.lock` differs from upstream's only by dependency edges: on the `ngit-grasp` package
(`heed`, `parking_lot`, `secp256k1`, `url`, `uuid`, and for the TLS test `openssl` and
`tokio-rustls`), and `serde` / `serde_json` on `heed` and `heed-types` from heed's serde
features. No package was added.

## What the server needs at run time

- **git 2.42 or newer on `PATH`.** Upstream v3.0.6 and later pass `--not` and `--glob=` on
  the stdin of `git rev-list --stdin` (`complete_in_family`, `src/git/staging.rs`), which git
  accepts from 2.42, and rely on the capabilities line `upload-pack` advertises for an empty
  repository, which git has from 2.41. With an older git nothing fails loudly: promotion of
  pushed history reports "promoted history is incomplete in the family" and staged pushes
  stay unpromoted. Debian 12 ships 2.39.5 and has no backport; Debian 13 ships 2.47.3. The
  server does not check the version at startup.
- **`libssl.so.3` and CA certificates.** The blob mirror and upstream's NIP-11 probe use
  reqwest with native-tls (OpenSSL). Relay connections use rustls with ring and the
  compiled-in web PKI roots, so a relay peer behind a private CA can be mirrored from but
  not synced with. Do not switch reqwest to rustls: that links a second crypto provider and
  every `wss://` dial panics.
- **The release binary** is built by CI on Debian 12 (glibc 2.36, OpenSSL 3.0) so that it
  runs in a Debian 12 or a Debian 13 guest; `ci-out/BUILD-INFO` repeats these needs.

## Tests

- `private_repos`, `private_two_node`, `private_watchdog`: the GRASP-P suites, on the
  fixture constructors `TestRelay::start_with_grasp_p` and `start_grasp_p_pair_node` in
  `tests/common/relay.rs` (upstream's file, with those two constructors and the `extra_env`
  option added). `phase0_gates` runs the stock relay (`TestRelay::start`, `start_with_lmdb`)
  with GRASP-P off: it checks what GRASP-P needs from upstream. In the pair tests the peer
  is also the bootstrap relay, except `exit14` in `private_two_node`, and both SSRF guards
  are switched off (`NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS=true` and upstream's
  `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS=true`), because the nodes are on loopback. No test
  runs a peer with the guards on.
- `grasp_p_tls`: the one test with real TLS. A CA made at run time, two TLS fronts before a
  plain node, and a second node that mirrors a blob through `https://` (must succeed, with
  the CA passed in `SSL_CERT_FILE`) and dials a `wss://` peer (must reach certificate
  verification and be refused there, since the relay client trusts the web PKI roots only).
  It would fail on a binary that links two rustls crypto providers.
- Upstream's own test files are unmodified, apart from `tests/common/relay.rs` above, one
  `grasp_p: None` field in the `HistoryJob` that the unit tests in `src/sync/history.rs`
  build, the two unit tests named under "Synced events are verified here", and fixed commit
  dates in the git helper of `src/git/staging/tests.rs`: one upstream test there builds the
  same commit twice and compares the ids, which only match within one wall-clock second.
