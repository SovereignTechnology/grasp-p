# GRASP-P on upstream ngit-grasp: seams and differences

GRASP-P is an overlay on upstream ngit-grasp, v3.0.7 today. This page records where the
overlay touches upstream's files, the decisions taken when it was ported from the v1.2.0
line (`legacy/v1.2-grasp-p`), and what behaves differently from that line. Read it before
an upstream sync: every seam listed here has to survive the merge.

## Layout

GRASP-P code lives in `src/grasp_p/`, `src/http/blossom.rs`, `src/sync/private_index.rs`,
`src/sync/grasp_p_sync.rs` and `src/bin/ngit-private-watchdog.rs`. `src/git/version.rs` is
ours as well: the startup check of the git version, which is not specific to GRASP-P.
Upstream's files carry thin seams only:

| Upstream file | Seam |
|---|---|
| `src/nostr/builder.rs` | `Nip34WritePolicy` holds the service (`set_grasp_p` / `grasp_p()`); `admit_event` calls `grasp_p::admission::admit` after the blacklist and deletion gates, frees key claims after an honored kind 5 / 62, logs NIP-56 reports; `create_relay` builds the service; `RelayRuntime.grasp_p` |
| `src/server.rs` | spawns GC, mirror and denylist reload (`grasp_p::spawn_background_tasks`); passes the service to HTTP; one call to `git::version::ensure_supported` before the storage migration, fatal only when GRASP-P is enabled; one call to `grasp_p::metrics_endpoint::start` ahead of every other background task, whose error stops startup (see below) |
| `src/git/mod.rs` | declares `version` |
| `src/main.rs` | the `version` attribute of `Cli` and of its `Serve` variant, both `grasp_p::build_info::version()` (`Config` sets upstream's version on that subcommand, and a subcommand's own version wins over the propagated one) |
| `src/http/mod.rs` | `HttpService.grasp_p`; widened CORS on OPTIONS; blob routes matched on the base-path-stripped path (`blossom::match_route`) just before NIP-11; one condition on the `/metrics` route, which a node with GRASP-P enabled does not serve (see below) |
| `src/config.rs` | `NGIT_GRASP_P_*` settings and their validation, including the GRASP-08 exclusion |
| `src/sync/mod.rs` | declares `grasp_p_sync` and `private_index`; `grasp_p` state field; GRASP-P filters added to `sync_generic_filters`, `sync_generic_history` and `complete_live_filters`; `register_relay` builds each connection with `with_duplicate_event_forwarding`; timer spawn; previously-rejected skip; after-saved / after-rejected hooks in `process_event_static_inner`; peers kept in `check_disconnects` and counted as desired in `retry_disconnected_relays`; the service handed to both `HistoryJob`s (`historic_sync_with_options`, `spawn_history_queries`); the id and signature check in `process_event_static_inner` (see below) |
| `src/sync/history.rs` | negentropy also skips known-rejected GRASP-P ids |
| `src/sync/relay_connection.rs` | forwards SDK-deduplicated events, only when GRASP-P is enabled, after checking their id and signature and skipping the SDK's second copy of a new event; `fetch_events` drops fetched events whose id or signature does not verify; the NIP-11 probe (`fetch_limit_hints`, `preflight_limit_hints`, and the helpers `vet_nip11_target`, `VettedAddresses`, `nip11_client`, `read_limited_body`, `fetch_nip11_document`) follows no redirect, uses no proxy, reads at most 256 KiB and, for an event-directed target, is vetted on every call and connects only to the vetted addresses (see below) |
| `src/sync/filters.rs`, `src/metrics/mod.rs`, `src/http/nip11.rs`, `src/nostr/lifecycle/deletion/service.rs`, `src/lib.rs` | additive helpers |
| `Cargo.toml` | direct dependencies `heed` (with its `serde` features), `parking_lot`, `uuid`, `url`, `secp256k1`; the `ngit-private-watchdog` binary target; for the TLS test, the dev-dependencies `openssl` and `tokio-rustls` |
| `tests/common/relay.rs` | the `extra_env` option and the constructors `start_with_grasp_p` / `start_grasp_p_pair_node`, which both set `NGIT_GRASP_P_METRICS_BIND=127.0.0.1:0` ahead of `extra_env`; the accessors `grasp_p_metrics` and `grasp_p_metrics_address` |
| `.env.example`, `docs/reference/configuration.md`, `nix/module.nix` | the `NGIT_GRASP_P_*` settings (the other three config sources) |
| `.gitignore`, `docs/how-to/prometheus-setup.md` | ignores for key files; a pointer to the GRASP-P alert rules and to the address a GRASP-P node is scraped on |

With `NGIT_GRASP_P_REPOS_ENABLE` unset no service is built, and the admission arms, blob
routes, sync filters, timers, duplicate forwarding and the metrics endpoint are all gated
on it, and `/metrics` is upstream's public route; the GRASP-P metrics register lazily on
first use. Two seams are deliberately not gated, because each
fixes a flaw in upstream itself: the id and signature check on synced and fetched events,
and the hardened NIP-11 probe. Both have a section below. Two more things differ from
upstream with the switch unset, and neither changes what the server does: `--version`
names the GRASP-P build, and a git older than 2.42, or no git, draws one warning at
startup.

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

## The NIP-11 probe is vetted, pinned and bounded here

Sync fetches a relay's NIP-11 document over HTTP up to twice per connection attempt
(`RelayConnection::fetch_limit_hints`): before the dial, unless the instance runs in
GRASP-08 private mode, to recognise a GRASP-08 private service, and on the connected
session for the page size, the subscription budget and the owner. Every relay that is not
registered as the bootstrap relay is event-directed. Most of those URLs come from events
anyone can publish; the index relays (`NGIT_USER_INDEX_RELAYS`), the Sync+ fallback
relays (`NGIT_SYNC_PLUS_FALLBACK_RELAYS`) and the GRASP-P sync peers an operator
configures are registered the same way.

Upstream v3.0.7 makes that request with `reqwest::Client::new()`. It follows up to ten
redirects, to plain `http` as well, honours the proxy variables of the environment, and
reads the whole body, limited only by a 3 second timeout. Only the call before the dial
(`preflight_limit_hints`) checks an event-directed target against the outbound target
policy; the call on the connected session does not. Neither holds the HTTP connection to
the addresses the policy vetted: reqwest resolves the name again. So a relay that passes
the policy can redirect the probe to an internal address, a name can resolve to a public
address for the check and to an internal one for the request, and a relay can send as
much body as fits in 3 seconds, on eight attempts in parallel.

The fork changes four things, all in `src/sync/relay_connection.rs`:

- The probe's HTTP client follows no redirect and uses no proxy. It is built per probe.
- The body is read up to 256 KiB, the figure upstream's own audit probe uses
  (`grasp-audit/src/probe.rs`). A larger `Content-Length` is refused before any of the
  body is read; a chunked body, or one that ends with the connection, is cut off when it
  passes the limit.
- An event-directed target is checked inside `fetch_limit_hints`, so on both calls. A
  refusal returns default hints without any request. `preflight_limit_hints` keeps its
  name and its caller and is now the same call.
- Where the policy vetted addresses, the client's resolver (`VettedAddresses`) answers
  every lookup with exactly those and never asks DNS, so there is no second answer to
  follow. A host that is an IP literal is connected to as written, and it is the literal
  the policy checked. Under `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS=true` the policy vets no
  address, so nothing is pinned; that is how the test suites reach their loopback relays.

An operator-configured target (the bootstrap relay) is still not vetted, as in upstream,
and gets the first two changes. The 3 second budget now covers the check with its DNS
lookup, the request and the body together. Anything that fails is default hints, as
before. One case is new: a client that cannot be built is default hints too, where
upstream's `Client::new()` panicked.

None of this is behind `NGIT_GRASP_P_REPOS_ENABLE`. For an operator, with or without
GRASP-P: a relay whose NIP-11 document is reachable only through a redirect, or is larger
than 256 KiB, now gets default hints (upstream's fallback paging and subscription
budget, no owner and no GRASP-08 flag: a public instance does not recognise a GRASP-08
private service before the dial and syncs with it as with any relay, and a GRASP-08
private instance derives no membership from that relay's owner and sends no credential
with Git fetches from its host), and `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` no
longer apply to the probe.

Unit tests, in the same file: `nip11_probe_does_not_follow_redirects`,
`nip11_probe_refuses_a_document_over_the_size_limit`,
`event_directed_nip11_probe_never_contacts_a_refused_target` (these three fail on
upstream's probe), `nip11_probe_reads_a_document_up_to_the_size_limit`,
`nip11_probe_is_held_to_the_addresses_a_strict_policy_vetted`,
`vetted_nip11_request_connects_to_the_vetted_address` and
`vetted_nip11_request_never_falls_back_to_a_dns_lookup`. They connect to loopback
listeners only; the one that names a public address checks it and connects to nothing.
No test covers a pinned request over TLS, the 3 second budget, that a proxy variable is
ignored, or one probe from vetting to connection: a target the production policy accepts
cannot be a loopback listener, so the choice of addresses is tested on `vet_nip11_target`
and the pinned client through `fetch_nip11_document`, each alone.

The relay dial itself is unchanged: vetted before every attempt and not pinned, which
upstream documents (`docs/explanation/defensive-measures.md`).

The address check is upstream's too (`src/outbound.rs`), unchanged. It counts the NAT64
prefixes (`64:ff9b::/96`, `64:ff9b:1::/48`) and 6to4 (`2002::/16`) as globally reachable,
so an address there that wraps an internal IPv4 address passes it, for the probe as for
the dial. The blob mirror decodes `64:ff9b::/96` and `2002::/16` and refuses such an
address (`is_disallowed_ip` in `src/grasp_p/mirror.rs`). Aligning upstream's ranges is to
be offered upstream, not carried here.

The change and its tests need no other file, so they can be offered upstream as they
are; offering them is the maintainer's call. When upstream hardens the probe itself, drop
this seam in the sync that brings the fix.

## Metrics leave a GRASP-P node on loopback only

Upstream serves `/metrics` on the public listener: to any client, for any method, with
`Access-Control-Allow-Origin: *`. On a node that hosts private repositories the scrape
counts those repositories, the bytes they hold, and the takedowns and reports received.
That is not public, so a node with GRASP-P enabled does two things differently.

- **The public listener has no `/metrics` route.** One condition in `src/http/mod.rs`:
  with `private_repos_enable` set the request falls through to the 404 page of any
  unknown path. The test is on the path with `NGIT_BASE_PATH` already stripped, so it
  holds under any base path, and for every method that reaches it: `OPTIONS` is answered
  earlier, with the 204 every path gets, as in upstream. The public repositories of such
  a node are served by the same process, so their `/metrics` is closed with it.
- **The scrape has a listener of its own**, `src/grasp_p/metrics_endpoint.rs`, and only
  when `NGIT_GRASP_P_METRICS_BIND` names its address. The value must be an IP address on
  loopback; a host name, any other address, or the setting together with
  `NGIT_METRICS_ENABLED=false` is a startup error (`Config::validate`, inside the GRASP-P
  block). The listener answers `GET /metrics` with the render upstream's route uses and
  everything else with an empty 404, sends no CORS header, and closes a connection whose
  peer is not loopback. `NGIT_BASE_PATH` does not apply to it. It answers the scrape only
  when the `Host` header is a loopback address or `localhost`, or is absent: a page from
  another site that points its own name at 127.0.0.1 is same-origin for a browser on the
  host and needs no CORS header, and its requests carry that name. A connection that
  sends no request head for 30 seconds is closed; there is no limit on how many
  connections are open at once. Its startup line is `Private metrics endpoint listening
  on <address>`.

`RelayServer` calls `metrics_endpoint::start` once, as the first entry of its background
tasks. The socket is bound inside that call, so an address already in use makes startup
fail, and it fails before any other background task is spawned: nothing is left half
started. That is why the call sits at the head of the list and not beside
`spawn_background_tasks`. The task is aborted with the others at shutdown, and aborting
it closes the listener and every open connection.

Collection is untouched: the `Metrics` object is built where and how upstream builds it,
because the server uses it for more than the scrape (the warning about one address
holding too many connections is logged from it). A GRASP-P node with metrics on and no
bind address collects in memory and serves nowhere; one line at startup says so and names
the setting. Upstream's own line, "Metrics enabled on /metrics endpoint", is still
printed on a GRASP-P node and is wrong there. The setting is node-local and not part of
`policy_fingerprint`.

For an operator: loopback is not authentication, any local process can read the scrape;
and upstream's `scripts/verify-deployment.sh` requests `/metrics` on the public listener,
so it needs `VERIFY_METRICS=false` against a GRASP-P node. Upstream's
`docs/reference/deployment-contract.md` says to set that variable only when metrics are
disabled; on a GRASP-P node it is needed with metrics on.

Still open, as the second part of issue 24: six metric families of upstream's sync code
carry the URL of each relay the node dials as a label value, and they are in this scrape
unchanged.

Tests: `metrics_are_not_served_on_the_public_listener` in `private_repos` fails when a
sync drops either seam (the public half needs the condition in `src/http/mod.rs`, the
endpoint half the call in `src/server.rs`), `metrics_are_off_without_a_bind` covers the
node with no endpoint, and `grasp_p_node_refuses_to_start_when_its_metrics_address_is_taken`
the failed bind. The first of them also sends the endpoint a `Host` that is not local.
The rules of the address, the routing and the `Host` header have unit tests in
`src/grasp_p/metrics_endpoint.rs` and `src/config.rs`. No test puts the node under a base
path, none reaches the listener from an address that is not loopback, and none waits out
the timeout.

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
  server checks at startup, before the storage migration (`src/git/version.rs`). With
  GRASP-P enabled a git older than 2.42 is a fatal error that names the version found, the
  minimum and the symptom, and so is a git that cannot be run. With GRASP-P off the same
  finding is one warning and the server starts wherever upstream starts. Output of
  `git --version` that it cannot read a version from only ever warns. The check is not
  specific to GRASP-P and could be offered upstream in unconditional form; that is the
  maintainer's call, and the seam in `src/server.rs` goes when upstream checks for itself.
- **`libssl.so.3` and CA certificates.** The blob mirror and upstream's NIP-11 probe use
  reqwest with native-tls (OpenSSL). Relay connections use rustls with ring and the
  compiled-in web PKI roots, so a relay peer behind a private CA can be mirrored from but
  not synced with. Do not switch reqwest to rustls: that links a second crypto provider and
  every `wss://` dial panics.
- **The release binary** is built by CI on Debian 12 (glibc 2.36, OpenSSL 3.0) so that it
  runs in a Debian 12 or a Debian 13 guest; `ci-out/BUILD-INFO` repeats these needs. Besides
  libc it links `libssl.so.3`, `libcrypto.so.3`, `libz.so.1` and `libzstd.so.1` dynamically
  (checked with `ldd` on the first release, which starts in a `debian:trixie-slim` image with
  git and ca-certificates added).
- **A build names itself.** `--version` on `ngit-grasp` and on `ngit-private-watchdog` prints
  upstream's version, the GRASP-P release and the commit, for example
  `3.0.7 (grasp-p sovtech-v1.0.0, commit 83b63ac0d1e2)` (`src/grasp_p/build_info.rs`). The
  release is the tag the release job built, passed in the build-time variable
  `GRASP_P_BUILD_RELEASE`; any other build says `grasp-p unreleased`. That variable is read by
  the compiler, not by the server, so it is not one of the settings and is in none of the four
  config sources. The commit is the `GIT_COMMIT` that upstream's `build.rs` already exports
  (`commit unknown` when a build has neither `.git` nor `NGIT_BUILD_REVISION`). The startup log
  line "GRASP-P private repositories enabled" carries the same text in its `build` field.
  NIP-11 `version` is untouched: upstream's `3.0.7-<commit8>`. The release job ships both
  binaries with their sha256 sums, appends both version lines to `ci-out/BUILD-INFO`, and
  fails when the server's line lacks the first 12 characters of the commit or, on a tag
  pipeline, the tag. Upstream's `scripts/verify-published-container.sh` expects `--version`
  to print exactly `ngit-grasp <version>` and would refuse this binary; it belongs to
  upstream's own release workflow (`.ngit/act/`), which this fork does not run. Because the
  release job runs only after a merge, `tests/private_watchdog.rs` checks the line on both
  binaries first.

## Tests

- `src/grasp_p/config_sources.rs` (lib tests) holds the four config sources together. It
  takes every `NGIT_GRASP_P_*` setting from clap and requires a section in
  `docs/reference/configuration.md`, a `NAME=value` line in `.env.example` and an entry in
  the environment map of `nix/module.nix`; it refuses a name in those files that the code
  does not have; and it compares defaults where a file states one it can read. A setting
  added to, renamed in or removed from fewer than four sources fails there.
- `private_repos`, `private_two_node`, `private_watchdog`: the GRASP-P suites, on the fixture
  constructors `TestRelay::start_with_grasp_p` and `start_grasp_p_pair_node` in
  `tests/common/relay.rs` (upstream's file, with those two constructors, the `extra_env` option
  and the two metrics accessors added). Both constructors set
  `NGIT_GRASP_P_METRICS_BIND=127.0.0.1:0`, so a node they start has a metrics endpoint on a
  port the kernel picks unless the test overrides the setting or switches GRASP-P off, and the
  suites read metrics through `TestRelay::grasp_p_metrics`, which finds the port in the node's
  log and panics unless the answer is a 200. Upstream's `fetch_metrics` returns the body of any
  status, and several assertions read a missing series as 0, so on the public port of a GRASP-P
  node they would pass on a 404 page. One use of it is left, in `exit4_disabled_is_noop` of
  `private_two_node`: that node runs with GRASP-P off and serves upstream's `/metrics`.
  `phase0_gates` runs the stock relay (`TestRelay::start`, `start_with_lmdb`) with GRASP-P off:
  it checks what GRASP-P needs from upstream. In the pair tests the peer is also the bootstrap
  relay, except `exit14` in `private_two_node`, and both SSRF guards are switched off
  (`NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS=true` and upstream's
  `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS=true`), because the nodes are on loopback. No test runs a
  peer with the guards on.
- `grasp_p_node_refuses_to_start_on_git_older_than_2_42` in `private_repos` is the only test
  of the call to the git check in `src/server.rs`. It starts a GRASP-P node with a fake `git`
  that reports 2.39.5 first on `PATH` and requires the refusal, so it fails when a sync
  drops that seam. The rules of the check have unit tests in `src/git/version.rs`.
- `grasp_p_tls`: the one test with real TLS. A CA made at run time, two TLS fronts before a
  plain node, and a second node that mirrors a blob through `https://` (must succeed, with
  the CA passed in `SSL_CERT_FILE`) and dials a `wss://` peer (must reach certificate
  verification and be refused there, since the relay client trusts the web PKI roots only).
  It would fail on a binary that links two rustls crypto providers.
- Upstream's own test files are unmodified, apart from `tests/common/relay.rs` above, one
  `grasp_p: None` field in the `HistoryJob` that the unit tests in `src/sync/history.rs`
  build, the two unit tests named under "Synced events are verified here", the seven named
  under "The NIP-11 probe is vetted, pinned and bounded here", and fixed commit dates in
  the git helper of `src/git/staging/tests.rs`: one upstream test there builds the same
  commit twice and compares the ids, which only match within one wall-clock second.
