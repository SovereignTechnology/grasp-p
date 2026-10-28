# GRASP-P on upstream ngit-grasp: seams and differences

GRASP-P is an overlay on upstream ngit-grasp, v3.0.8 today. This page records where the
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
| `src/nostr/builder.rs` | `Nip34WritePolicy` holds the service (`set_grasp_p` / `grasp_p()`); `admit_event` passes over upstream's deletion gate for state roots and stream wraps (`grasp_p::offboard::deletion_gate_exempt`, see "Who may delete" below), calls `grasp_p::admission::admit` after the blacklist and the deletion gate and before its own dispatch, for every kind (GRASP-P's own kinds, and every other kind that references their content, which it refuses: see "Nothing attaches to private-repository events" below), frees key claims after an honored kind 5 / 62; `create_relay` builds the service; `RelayRuntime.grasp_p`. The GRASP-P arm for NIP-56 reports is gone: a report `admit` lets through takes upstream's generic arm and its words |
| `src/server.rs` | spawns GC, mirror and denylist reload (`grasp_p::spawn_background_tasks`); passes the service to HTTP; one call to `git::version::ensure_supported` before the storage migration, fatal only when GRASP-P is enabled; one call to `grasp_p::metrics_endpoint::start` ahead of every other background task, whose error stops startup; where `Metrics` is built, the builder call `with_relay_labels(RelayLabels::from_config(..))`, which passes `None` unless GRASP-P is enabled (see below) |
| `src/git/mod.rs` | declares `version` |
| `src/main.rs` | the `version` attribute of `Cli` and of its `Serve` variant, both `grasp_p::build_info::version()` (`Config` sets upstream's version on that subcommand, and a subcommand's own version wins over the propagated one) |
| `src/http/mod.rs` | `HttpService.grasp_p`; widened CORS on OPTIONS; blob routes matched on the base-path-stripped path (`blossom::match_route`) just before NIP-11; one condition on the `/metrics` route, which a node with GRASP-P enabled does not serve (see below) |
| `src/config.rs` | `NGIT_GRASP_P_*` settings and their validation, including the GRASP-08 exclusion; two GRASP-P lines in the help text of upstream's `NGIT_EVENT_BLACKLIST` (see "Policy fingerprint v4 and the event blacklist") |
| `src/sync/mod.rs` | declares `grasp_p_sync` and `private_index`; `grasp_p` state field; GRASP-P filters added to `sync_generic_filters`, `sync_generic_history` and `complete_live_filters`, for a configured peer only (`grasp_p_filters_for`); `register_relay` builds each connection with the GRASP-P node's address check (`with_grasp_p_address_check`) and with duplicate forwarding on a configured peer's connection only (`with_duplicate_event_forwarding`), and takes its outbound policy from `grasp_p_peer_policy` when that gives one; timer spawn; previously-rejected skip; after-saved / after-rejected hooks in `process_event_static_inner`; configured peers kept in `check_disconnects`, counted as desired in `retry_disconnected_relays`, kept by `handle_disconnect` (`grasp_p_peer_needs`) and not muted by the naughty list in `schedule_connect_relay` (`grasp_p_naughty_mute_applies`); the source gate in `process_event_static_inner` (`grasp_p_gate`), directly after the id and signature check (see below); the GRASP-P ids counted as delivered in the negentropy completion check of `handle_eose` (`grasp_p_settled_ids`); see "Configured peers" below for these; the service handed to both `HistoryJob`s (`historic_sync_with_options`, `spawn_history_queries`) |
| `src/sync/history.rs` | negentropy also skips known-rejected GRASP-P ids |
| `src/sync/relay_connection.rs` | forwards SDK-deduplicated events, only on a connection built with that flag (a configured peer's), after checking their id and signature and skipping the SDK's second copy of a new event; the flag `grasp_p_node` and its builder, and one call of `grasp_p::mirror::vet_relay_dial` on it each in `connect` and `vet_nip11_target`, on the outbound policy's answer, which on a GRASP-P node also refuses a NAT64 or 6to4 address that wraps an internal one (see "Configured peers"); `fetch_events` drops fetched events whose id or signature does not verify; the NIP-11 probe (`fetch_limit_hints`, `preflight_limit_hints`, and the helpers `vet_nip11_target`, `VettedAddresses`, `nip11_client`, `read_limited_body`, `fetch_nip11_document`) follows no redirect, uses no proxy, reads at most 256 KiB and, for an event-directed target, is vetted on every call and connects only to the vetted addresses (see below) |
| `src/sync/filters.rs`, `src/http/nip11.rs`, `src/nostr/lifecycle/deletion/service.rs`, `src/lib.rs` | additive helpers |
| `src/nostr/lifecycle/deletion/cascade.rs` | the announcement cascade's plan leaves registrations, state roots and stream wraps out of the events it deletes on a GRASP-P node (`grasp_p::offboard::cascade_exempt`; one more argument to `plan_deleted_announcement_cascade`; see "Who may delete" below) |
| `src/nostr/lifecycle/deletion/archival.rs` | `archive_and_delete_filter` leaves state roots and stream wraps in place on a GRASP-P node (`grasp_p::offboard::removal_exempt`; see "Who may delete" below) |
| `src/metrics/mod.rs` | additive helpers (the `ngit_private_*` series and their recorders); the field `Metrics::relay_labels`, its builder `with_relay_labels`, and one statement in `render` between `REGISTRY.gather()` and the encoder, which rewrites the relay labels when the field is set (see below) |
| `Cargo.toml` | direct dependencies `heed` (with its `serde` features), `parking_lot`, `uuid`, `url`, `secp256k1`; the `ngit-private-watchdog` binary target; for the TLS test, the dev-dependencies `openssl` and `tokio-rustls` |
| `tests/common/relay.rs` | the `extra_env` option and the constructors `start_with_grasp_p`, `start_with_grasp_p_at_base_path`, `start_grasp_p_pair_node` and `start_grasp_p_pair_node_with_upstream_guard` (the pair node without `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS`), which all set `NGIT_GRASP_P_METRICS_BIND=127.0.0.1:0` ahead of `extra_env`; the two pair constructors also name their bootstrap peer in `NGIT_GRASP_P_SYNC_PEER_URLS` and, through `TestRelay::blob_peer_url`, in `NGIT_GRASP_P_MIRROR_PEER_URLS`; the accessors `grasp_p_metrics` and `grasp_p_metrics_address` |
| `.env.example`, `docs/reference/configuration.md`, `nix/module.nix` | the `NGIT_GRASP_P_*` settings (the other three config sources), and a GRASP-P paragraph on upstream's `NGIT_EVENT_BLACKLIST` in each, at the end of upstream's text; in the configuration reference also one on upstream's `NGIT_DELETION_REQUEST_DISRESPECTOR`, at the end of its section |
| `.gitignore`, `docs/how-to/prometheus-setup.md` | ignores for key files; a pointer to the GRASP-P alert rules and to the address a GRASP-P node is scraped on |

With `NGIT_GRASP_P_REPOS_ENABLE` unset no service is built, and the admission arms, the
deletion gate, cascade and removal exemptions, blob routes, sync filters, timers, duplicate forwarding, the handling of configured peers (there
are none, and no connection carries the flag the dial check goes by), the metrics endpoint
and the rewrite of relay labels are all gated on it, and `/metrics` is upstream's public route with upstream's
labels; the GRASP-P metrics register lazily on first use. Two seams are deliberately not
gated, because each fixes a flaw in upstream itself: the id and signature check on synced
and fetched events, and the hardened NIP-11 probe. Both have a section below. Two more
things differ from upstream with the switch unset, and neither changes what the server
does: `--version` names the GRASP-P build, and a git older than 2.42, or no git, draws one
warning at startup.

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
node, through the duplicate-forwarding arm of a configured peer's connection.

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

The flaw is in unmodified upstream v3.0.7 and v3.0.8 (re-checked at the v3.0.8 sync: still
no verification in `src/sync/`, nostr-sdk still 0.45.4) and in nostr-sdk. Reporting it to both is the
maintainer's call. When upstream verifies on its own, drop this seam in the sync that
brings the fix.

## The NIP-11 probe is vetted, pinned and bounded here

Sync fetches a relay's NIP-11 document over HTTP up to twice per connection attempt
(`RelayConnection::fetch_limit_hints`): before the dial, unless the instance runs in
GRASP-08 private mode, to recognise a GRASP-08 private service, and on the connected
session for the page size, the subscription budget and the owner. Every relay that is not
registered as the bootstrap relay is event-directed. Most of those URLs come from events
anyone can publish; the index relays (`NGIT_USER_INDEX_RELAYS`), the Sync+ fallback
relays (`NGIT_SYNC_PLUS_FALLBACK_RELAYS`) and the GRASP-P sync peers an operator lists
are registered the same way.

Upstream v3.0.7 makes that request with `reqwest::Client::new()`, and v3.0.8 still does
(re-checked at the v3.0.8 sync, along with `src/outbound.rs`'s ranges). It follows up to ten
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
  The same holds for the one connection that has a permissive policy of its own: a
  configured peer when `NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS=true` ("Configured peers").
  That is right for it: the operator named the target and said it may be internal, which
  is what upstream assumes of its bootstrap relay, and the probe still follows no
  redirect, uses no proxy and reads a bounded body.

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
address, and the local-use prefix whatever it carries (`wraps_non_global` in
`src/grasp_p/mirror.rs`). On a node with GRASP-P enabled
the relay dial and the probe now pass the mirror's check as well ("Configured peers",
the last point); a node without it keeps upstream's check alone. Aligning upstream's
ranges is still to be offered upstream, and that seam goes when upstream decodes them.

The change and its tests need no other file, so they can be offered upstream as they
are; offering them is the maintainer's call. When upstream hardens the probe itself, drop
this seam in the sync that brings the fix.

## Metrics leave a GRASP-P node on loopback only

Upstream serves `/metrics` on the public listener: to any client, for any method, with
`Access-Control-Allow-Origin: *`. On a node that hosts private repositories the scrape
counts those repositories, the bytes they hold, and the takedowns and reports received.
That is not public, so a node with GRASP-P enabled serves it elsewhere, in the two ways
below, and names no relay by its URL in it, which the second half of this section covers.

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

Collection is untouched: the `Metrics` object is built where upstream builds it and
records what upstream records, because the server uses it for more than the scrape (the
warning about one address holding too many connections is logged from it). A GRASP-P node
with metrics on and no bind address collects in memory and serves nowhere; one line at
startup says so and names the setting. Upstream's own line, "Metrics enabled on /metrics
endpoint", is still printed on a GRASP-P node and is wrong there. The setting is
node-local and not part of `policy_fingerprint`.

For an operator: loopback is not authentication, any local process can read the scrape;
and upstream's `scripts/verify-deployment.sh` requests `/metrics` on the public listener,
so it needs `VERIFY_METRICS=false` against a GRASP-P node. Upstream's
`docs/reference/deployment-contract.md` says to set that variable only when metrics are
disabled; on a GRASP-P node it is needed with metrics on.

**No relay is named by its URL in that scrape.** Six metric families of upstream's sync
code label each series with the URL of the relay it is about, and do so for every relay
the node dials: `ngit_sync_relay_connected`, `ngit_sync_connection_attempts_total`,
`ngit_sync_relay_status`, `ngit_sync_relay_failures`, `ngit_sync_policy_refusals_total`
and `ngit_sync_hydration_events_total`. Most of those relays are named by customers'
events, and a scrape is shipped off the host into a monitoring system. Upstream's
`src/sync/metrics.rs` is left as it is, byte for byte; `src/grasp_p/relay_labels.rs`
rewrites the gathered families before they are encoded.

- **The seam** is in `Metrics::render` (`src/metrics/mod.rs`): one optional field,
  `relay_labels`, set through the builder `with_relay_labels`, and one statement between
  `REGISTRY.gather()` and the encoder. `src/server.rs` passes
  `RelayLabels::from_config(&config)` where it builds `Metrics`. That is `None` unless
  GRASP-P is enabled, and with `None` the render is upstream's. The registry and
  upstream's recorders are untouched: the URLs stay in the process, as they do in
  upstream, and are not written out.
- **It goes by the name of the label**, `relay`, in whatever family that occurs, so a
  family upstream labels with `relay` later is covered without a new seam. A label of
  another name that held a relay URL would not be; the integration test below fails on
  `ws://` or `wss://` anywhere in the scrape of a pair.
- **A configured peer is renamed, every other relay is dropped.** A sample whose `relay`
  is one of this node's peers gets an alias, `peer-1`, `peer-2` and so on; any other
  sample that has the label is removed. The aggregate series have no relay label and
  are untouched. The same process serves the node's public repositories, so the relays
  those bring in lose their per-relay series as well.
- **The peers** are the entries of `NGIT_GRASP_P_SYNC_PEER_URLS`, numbered in their
  order: the one set the sync code treats as peers ("Configured peers"). The setting is
  the operator's, so an alias tells nothing a customer chose. The relay in
  `NGIT_SYNC_BOOTSTRAP_RELAY_URL` has an alias only when the list names it, and then the
  number of its entry; one the list leaves out carries public sync alone and is dropped
  with the other relays. So are relays configured for another purpose (the user index,
  the Sync+ fallbacks), which keeps the peer alert about the pair. On a pair the one peer
  is `peer-1` on both nodes.
- **The list is read by the function the service builds its peer set with**,
  `configured_peer_relay_keys` (`src/sync/private_index.rs`): `normalize_relay_url`, the
  own-address exclusion and `canonical_relay_key`, each key once, in list order. The label
  upstream writes is that key, and it is compared as it stands. A key has one alias, so
  two series of one family cannot end up with the same labels; a label in any other
  spelling is dropped, never folded in. The unit test
  `aliases_exist_for_exactly_the_relays_sync_treats_as_peers` holds the aliases to the
  service's set.
- **A family left with no sample is removed.** The registry prunes empty families before
  it hands them over, and the text encoder answers one with an error, which `render`
  unwraps.

At an upstream sync: upstream rewrote `Metrics::render` once before, so check that the
statement still sits between gather and encode. If `register_relay` or the bootstrap
registration in `src/sync/mod.rs` changes how a relay's key is formed, the labels stop
matching and the peers' series drop out of the scrape: the integration test fails and
nothing is disclosed.

Check the label names as well: the rewrite knows `relay` and no other. In v3.0.7 no other
label that reaches a scrape holds a relay, an address, a key or a repository; every other
value the server sets is a fixed word, a build constant or an event kind number. Two
things would change that, and each needs a decision before the sync is merged: a caller
for `BandwidthTracker::record_transfer`, which would put up to ten repository identifiers
in `ngit_git_top_repos_bytes{repo}` (it has none today), and a caller for a recorder that
takes free text and has none today (`record_message_received`, `record_message_sent`,
`record_event_rejected`). The pair test looks for `ws://`, `wss://` and the addresses of
the relays it started, so it would not notice either.

For an operator, the alias mapping and what can no longer be read per relay are in
`docs/grasp-p/ops/runbook.md`, "Relays in the scrape", and the peer alert in
`docs/grasp-p/ops/prometheus-alerts.yaml` selects the alias and also fires when `peer-1`
has no series. One of the six families never reaches a scrape in the first place: upstream
registers `ngit_sync_relay_failures` and nothing calls `record_failure_count`. The alert
rule that read it is removed; upstream's `docs/explanation/monitoring.md` still lists
the series.

Tests: `metrics_are_not_served_on_the_public_listener` in `private_repos` fails when a
sync drops either seam (the public half needs the condition in `src/http/mod.rs`, the
endpoint half the call in `src/server.rs`), `metrics_are_off_without_a_bind` covers the
node with no endpoint, and `grasp_p_node_refuses_to_start_when_its_metrics_address_is_taken`
the failed bind. The first of them also sends the endpoint a `Host` that is not local.
The rules of the address, the routing and the `Host` header have unit tests in
`src/grasp_p/metrics_endpoint.rs` and `src/config.rs`. No test puts the node under a base
path, none reaches the listener from an address that is not loopback, and none waits out
the timeout.

`scrape_never_names_a_relay` in `private_two_node` fails when a sync drops the relay-label
seam in `src/metrics/mod.rs` or in `src/server.rs`: on both nodes of a replicating pair
the scrape must show the peer as `relay="peer-1"`, connected, with a successful dial
counted and a health state, and must hold neither the peer's address nor `ws://` nor
`wss://`. One node also holds a public repository whose announcement names a third relay:
that relay must be counted among the tracked relays and have neither a series nor its
address in the scrape. It is the only test that puts a public repository on a node with
GRASP-P enabled. The rules of the rewrite have unit tests in
`src/grasp_p/relay_labels.rs`, on a registry of their own and never the global one. One
of them reads upstream's `src/sync/metrics.rs` as text and fails when the number of
families labelled with a relay, or of methods that take one, changes, because the lists
the other tests drive are kept by hand. `the_bootstrap_relay_is_a_peer_only_when_listed`
covers the bootstrap relay, and `exit18_bootstrap_relay_that_is_not_a_peer_carries_no_grasp_p_sync`
in `private_two_node` reads the scrape of a node whose bootstrap relay is not listed: it
counts the relay and names none.

## What the blob routes answer

All of this is in GRASP-P's own files (`src/http/blossom.rs`, `src/grasp_p/`); it adds no
seam to a file upstream owns, no setting, and nothing to `policy_fingerprint`.

- **Headers on every response.** `X-Content-Type-Options: nosniff`. A blob is whatever
  bytes a client uploaded, and a browser must not guess a type for them. The CORS
  expose list of these routes names `X-Reason` and `Retry-After` beside upstream's
  `WWW-Authenticate`, so a browser client can read why a request failed and when to
  retry. The public routes keep upstream's list on their own responses. The `OPTIONS`
  preflight is the exception: `src/http/mod.rs` answers it for every path of a GRASP-P
  node from the blob routes' CORS function, so on public paths too it names the three
  headers and says `nosniff`. Both are without effect there (a preflight has no body and
  its expose list is not read).
- **A served blob** (`GET` and `HEAD /<sha256>`, same headers) also carries
  `Content-Security-Policy: default-src 'none'; sandbox`, `Cache-Control: no-cache` and a
  strong `ETag` that is the sha256 in quotes. It used to say `public, max-age=31536000,
  immutable`, which let every cache serve a taken-down blob for a year. Now a cache may
  keep the bytes but asks the node before each reuse.
- **Conditional requests.** `If-None-Match` (one tag, a list, a weak tag or `*`) is
  answered `304`, with the same `ETag` and `Cache-Control` and no body, only after the
  denylist check and the existence check. A cache that revalidates a blob that has been
  taken down gets the `451`, and one that revalidates a removed blob gets the `404`. The
  order lives in one function, `decide_blob_read`, apart from the code that reads the
  facts and builds the responses, and a unit test walks every combination.
- **Errors and 404s** say `Cache-Control: no-store`: a `404` and a `451` are cacheable by
  default and a cached one would outlive its cause.
- **`WWW-Authenticate: Nostr`** on every `401` and on no other status.
- **`X-Reason` never carries internal detail.** An internal failure reads `internal error`
  to the client, and a body that could not be read reads `request body error`;
  `BlobError::public_reason()` is what the HTTP layer sends, and it logs the detail once
  (`blob route internal error: ...`). `BlobError::reason()` is unchanged, and the mirror's
  retry classes and log lines still read it.
- **`uploaded` is real.** `BlobClaim.stored_at` records when this node first stored a
  blob, by upload or by mirroring. `GET /list` and the `PUT /upload` descriptor report it,
  and a repeat upload reports the first time, not the time of the repeat. It is per node:
  the two nodes of a pair report different times for one blob. Claims are stored as JSON
  (`heed`'s `SerdeJson`), so the field is optional with a default: a claim written by an
  older build reads as "time unknown" and is listed with `uploaded: 0` until the blob is
  uploaded again, which records the time of that upload; an older build reading a newer
  claim ignores the field, and drops it from any claim it rewrites, so after a roll-back
  the time is unknown again until the next upload. The time belongs to the claim: when GC
  or a takedown deletes the claim and the blob is stored again, that is a new first time.
  No migration.
- **Authorization events (kind 24242)** are accepted only with `created_at` between one
  hour before and fifteen minutes after the node's clock (it was 24 hours either way),
  whatever their `expiration`. A BUD-11 `server` tag is checked: an event that carries
  such tags is refused unless one names this node, a `list` authorization must carry
  one, and `upload` and `delete` do not need one until the client sends it (M4). "Names
  this node" is the configured domain (`NGIT_DOMAIN`), compared by `host::url_denotes_domain`:
  the host without regard to case or a trailing dot, and the port when the domain has one.
  The tag is a bare domain, so the mount path of a node under `NGIT_BASE_PATH` is not
  compared here. The tags of a registration are URLs and are compared with the path (see
  "Under a base path the node is its host and its path"). A refused `GET /list` is still
  the one identical `401`, whichever check failed.
- **No record of used authorizations**, on purpose. What a captured authorization can
  still do inside its window (75 minutes at most): a list authorization returns that
  key's inventory to whoever presents it; an upload authorization, with the bytes, stores
  the blob again if its owner deleted it meanwhile; a delete authorization removes the
  claim again if its owner uploaded the blob again meanwhile. Nothing else: no other
  blob, no other alias, and where the event carries a `server` tag no other server. A
  record of used ids would close these three only on one node and only until its next
  restart, because a table in one process is neither shared with the peer node nor kept
  over a restart, so the node does not promise it. The window and the tag are stateless and the same on both nodes. They are not
  in `policy_fingerprint` because authorization events are never replicated: no setting
  is involved, both nodes run the same build, and a difference could not make two nodes
  hold different data.
- **Denylist reload starts from the boot load.** `denylist::load_boot` returns what it
  read from each file, the service keeps it, and the reload task takes it as its starting
  state. It used to start from nothing, so a file that could not be read or parsed again
  after boot had no entries to keep, and the next change to any other file swapped in a
  set without them. Now the first reload after boot changes nothing unless a file changed,
  and such a file keeps what it had. What a **missing** file means is not changed: it
  counts as empty, at boot and on reload. That is an open decision (`PLAN.md`).
- **Upload temp files are swept at startup.** `BlobStore::open` unlinks every regular
  file and symlink directly in `<blob root>/tmp`, judged with `symlink_metadata`, so a
  link is removed and not followed, and a directory is neither removed nor entered. A
  `tmp` that is itself a link is not swept at all, with a warning. It
  logs the number of entries and bytes, and an error is a warning, not a failed start.
  This is safe because nothing can be uploading yet: the store is opened inside
  `PrivateService::new`, which `create_relay` awaits before the mirror task is spawned
  (`spawn_background_tasks`) and before the HTTP listener serves its first request, and
  one process owns a data directory.

What changes for clients: the client sends no `server` tag and never lists or deletes, so
nothing breaks for it; its tokens already expire after an hour; a client whose clock runs
more than fifteen minutes fast is refused on the blob routes, as its events already are.
A third-party Blossom client that lists without a `server` tag gets the `401`. Anything in
front of a node that caches must honour the origin's cache headers on blob paths
(`ops/runbook.md`, takedown procedure).

## Upload slots and the body timeout

In GRASP-P's own files (`src/grasp_p/mod.rs`, `src/http/blossom.rs`, one line in
`src/grasp_p/mirror.rs`), plus two settings and one warning in `src/config.rs` and one
counter in `src/metrics/mod.rs`. `src/http/mod.rs` is not touched. Nothing joins
`policy_fingerprint`.

- **What was wrong.** 64 upload slots served the whole node, shared by every client and
  by the blob mirror. One account that opened 64 uploads and stopped sending took all of
  them: no other account could upload and the mirror could not replicate. Running out of
  slots answered `507 quota exceeded`, which tells a client its storage is full. And the
  body of an upload was read with no time limit, so a stalled upload kept its slot, its
  temp file and its reserved bytes for as long as the connection stayed open.
- **Slots per account.** A client upload is counted against the tenant key of the alias
  its authorization names (the registration's tenant, which `verify_blossom_auth` has
  already matched to the `a` tag). At most `NGIT_GRASP_P_MAX_UPLOADS_PER_TENANT` (default
  8, `0` = no cap) are in flight for one account; one more is answered `429`, `X-Reason:
  too many uploads in progress for this account; retry later`, `Retry-After: 5`.
- **Slots of the node.** The cap of 64 client uploads stays, and is not a setting. A full
  node answers `503`, `X-Reason: all upload slots are in use; retry later`,
  `Retry-After: 30`. `507` is now only ever about bytes.
- **Order of the checks.** Account cap, node cap, byte budget, under one lock
  (`reserve_inflight`). An account at its own cap is told so even when the node is full,
  because waiting for the node would not help it. A refusal takes nothing.
- **The two `Retry-After` values are hints.** 5 seconds for the account: its slot comes
  back when one of its own uploads ends, and an upload of ordinary size ends within
  seconds. 30 seconds for the node: a full node usually means stalled uploads, and 30
  seconds is when a stalled upload is cut.
- **The mirror is outside both caps.** `reserve_upload` takes an origin. A mirror fetch
  reserves the bytes it expects to read (the peer's announced length, otherwise
  the declared size) against `NGIT_GRASP_P_GLOBAL_BUDGET_BYTES`, and
  takes no slot: `NGIT_GRASP_P_MIRROR_MAX_CONCURRENCY` already bounds how many run. So
  clients that fill or stall the slots no longer make replication wait for a slot, and
  the transient number of temp files is now at most 64 plus the mirror's concurrency.
  This is about slots only. The bytes that client uploads have reserved still count
  against the global budget the mirror reserves from: up to 64 uploads of the largest
  blob, 16 GiB at the defaults (8 per account, 2 GiB), for as long as they are in
  flight. A node closer than that to `NGIT_GRASP_P_GLOBAL_BUDGET_BYTES` can still have
  mirror fetches refused with `quota`, and client uploads with `507`, while stalled
  uploads hold their reservations.
- **Release.** Everything a reservation took (the bytes, the node slot, the account's
  count) is given back by `UploadReservation::drop` and nowhere else. The reservation is
  a field of the upload sink, and the sink is a local of the request handler, so every
  way an upload can end drops it: success and every error return of the handler, the
  timeout, a client that disconnects (the body read fails, or hyper drops the handler's
  future), and a panic unwinding through the handler. The sink's own `Drop` removes the
  temp file first. An account's entry in the map is removed when its count reaches zero,
  so the map is never larger than the number of uploads in flight.
- **Body timeout.** `next_frame` in `src/http/blossom.rs` waits for each piece of the
  body under two clocks. Idle: 30 seconds between two pieces (a constant). Total: 30
  seconds plus the declared `Content-Length` divided by
  `NGIT_GRASP_P_UPLOAD_MIN_BYTES_PER_SEC` (default 16384; `0` = no total deadline),
  counted from the moment the body starts being read. The total is also checked before
  each read, so a body that always has a few bytes ready cannot outrun it. Either expiry
  answers `408`, `X-Reason: upload timed out waiting for the request body`, and
  `Connection: close`. Writing a piece to disk and the final rename and ledger update
  are not under these clocks; they do not depend on the client.
- **What hyper does with the rest of the body** (read from hyper 1.11.1,
  `proto/h1/dispatch.rs` and `conn.rs`; the node serves HTTP/1.1 only). When the handler
  answers before the body has been read to its end, hyper does not drain it. It makes one
  attempt to read what has already arrived; if that completes the body (a small upload
  whose bytes came with the head) the connection stays usable, otherwise hyper closes its
  reading side, switches keep-alive off, sends the response and shuts the connection
  down. That holds for every early answer of `PUT /upload` (`413`, `429`, `503`, `507`,
  `408`), and was already so before this change. A client that is still sending when the
  connection closes can get a reset from the operating system and lose the response it
  had not read yet; a client that had stopped sending, which is the case the idle
  cut-off is for, reads the `408` and then the end of the connection. The `408` says
  `Connection: close` itself, so a client or a proxy that reads it knows not to reuse
  the connection.
- **Under `NGIT_TEST=1`** the idle time is 5 seconds, so an integration test can wait
  for it. The unit tests pass the times in and run under paused time.
- **Counter.** `ngit_private_upload_refused_total{reason}` with `account_slots`,
  `node_slots`, `idle_timeout` and `deadline`. No label carries a tenant, an alias or a
  key. The alert `NgitPrivateUploadSlotsExhausted` is on `node_slots`. A stall that
  begins within the idle time of the deadline is cut at the deadline and counted as
  `deadline`. That includes every stalled upload smaller than one second's worth at
  the minimum rate (under 16 KiB at the default), whose deadline is the idle time
  itself.
- **Both settings are node-local.** They decide when a client is told to wait or is cut
  off, never which blob or event a node accepts, so the two nodes of a pair may differ
  and the fingerprint has nothing to cover. Every value is valid; a cap per account
  of 64 or more draws a warning at start.
- **What a client sees.** The client today uploads with a fixed 300 second timeout of
  its own and does not retry a `429`, a `503` or a `408`: the push fails with the status
  and the reason, and running it again is the retry. Retrying on `Retry-After` belongs
  to a later client milestone. With one hosting key for a whole team, the team shares
  the account's 8 concurrent uploads. At the default rate the node's deadline is longer
  than the client's own 300 seconds for any blob above about 4.2 MiB (4,423,680 bytes),
  so for those the client gives up first.
- **Still open.** The total deadline is one point in time, not a rate that is checked
  as the body arrives. An upload that declares the largest blob (256 MiB by default)
  and sends one byte inside every idle period keeps its slot until that deadline, about
  4 hours 33 minutes at the default rate, having sent a few hundred bytes. Eight
  accounts doing so fill the 64 slots for that long. The cap per account makes that
  cost eight registered accounts where it cost one, and the mirror takes no slot.
  Checking the bytes received against the rate as the body arrives would close it and
  is not done here. The bytes such uploads reserve are held for as long (see "The
  mirror is outside both caps").

## The blob mirror: one queue per account, an attempt budget, every failure gated

In GRASP-P's own files (`src/grasp_p/mirror.rs`, and the quota half of the upload
preflight cut out as `blob_quota_preflight` in `src/grasp_p/mod.rs`), plus one setting in
`src/config.rs`. No other upstream file is touched and nothing joins
`policy_fingerprint`: none of this changes what a node accepts, only when it fetches.

- **What was wrong.** The worker waited for a fetch slot inside its job loop, and the
  slots (4 by default) served the whole node. One account whose blobs came slowly, or
  never, held every slot: no other account's blob was mirrored and the repair scan was
  not served. Some failure classes cleared the retry gate, so the 60-second scan queued
  them again for ever, some after downloading the whole blob. A scan walked the claim
  table and the file system on the async runtime. A blob claimed by several accounts
  went to whichever alias came first. And the reason recorded for a blob was the last
  peer's.
- **One queue per account.** `FairQueue` holds a backlog per account (the tenant key),
  serves the accounts in turn, and lets one account have at most
  `max(1, NGIT_GRASP_P_MIRROR_MAX_CONCURRENCY / 2)` fetches running. The share is derived
  and has no setting. A backlog holds 1024 blobs; one more is dropped, and the next scan
  derives it again from the claim table, which is why dropping is safe. A hash is queued
  or running at most once, whoever asked for it. A node with a single busy account
  mirrors at half the configured concurrency: the share is not lent out, because a slot
  lent to a slow account is not there when another account's blob arrives. With the
  default of four, one slow account leaves two slots for everyone else; two slow accounts
  hold all four, and a third account then waits for fetches of theirs to end, served in
  its turn. One account is also held to 1024 blobs per repair scan: its backlog holds
  1024 and the next scan refills it, so no setting takes one account past about 17 blobs
  a second.
- **The loop never waits for a slot.** `run_worker` waits for a job, the repair tick, a
  finished scan or a finished fetch, and after each starts every fetch that may start.
  The slots are a count the loop keeps, not a semaphore: the only thing that frees one
  is the report of the fetch that held it, and that report is also what wakes the loop,
  so a free slot and a sleeping loop cannot coexist. A fetch reports from a drop guard,
  so one that panics or is cancelled reports too.
- **Attempt budget.** A token bucket over all accounts, taken when a fetch starts:
  `NGIT_GRASP_P_MIRROR_MAX_ATTEMPTS_PER_MIN` (default 600, `0` = unlimited), a burst of
  one minute's worth and then that rate. When the budget is what holds a fetch back, the
  loop arms a timer for the next token. One attempt is one blob tried against its peers,
  so with several peers the number of requests is a multiple.
- **Every failure backs off.** The class table is in the module documentation of
  `mirror.rs` and in the runbook. Classes that may heal by themselves or by a change on
  this node back off exponentially; `404` from every peer, `blocked`, `verify` and
  `too_large` wait the maximum interval. The metric labels are unchanged. A peer name
  that does not resolve is `network`, not `blocked`: the address check connects to
  neither, but a resolver that fails for a moment must not park every blob tried
  meanwhile for the maximum interval. A lookup through the client's resolver that
  fails, or answers no address, is `network` for the same reason. The two are told apart by how the outbound
  policy's error begins (`POLICY_DNS_ERROR_PREFIX`); a unit test fails if upstream
  rewords it. The cost of gating every class is slower recovery: a blob refused with
  `quota` used to be fetched within a minute of space being freed and now waits out its
  backoff, about `NGIT_GRASP_P_MIRROR_RETRY_MAX_SECS` at most. A restart clears every
  gate.
- **Which reason is recorded.** A failure from this node's own state (`quota`, `reserve`,
  `sink`, `write`, `store`) ends the peer loop. Otherwise every peer is tried and the
  class that retries soonest wins, whatever the order of the peers.
- **Order within one fetch.** Address check, quota preflight against local state,
  request (its connection vetted by the client's resolver), status, length, byte
  reservation, temp file, body. A blob the account has no
  room for costs no request, and a wrong length costs no body.
- **Whose length is believed.** The peer's, up to `NGIT_GRASP_P_MAX_BLOB_BYTES`, so a
  blob declared with the wrong size is now mirrored and charged at its real size, where
  it used to fail for ever: the replica matches the origin. With no announced length the
  declared size bounds the read. A peer is always one the operator listed ("The blob
  mirror fetches from the operator's peers only"); while a registration's `server` tag
  could name one, such a peer had to announce exactly the declared size, and that rule
  went with the tags.
- **Time limits.** The client has no total timeout any more. The peer must answer, and
  may not go silent mid-body, within `NGIT_GRASP_P_MIRROR_FETCH_TIMEOUT_SECS`; the whole
  request gets that plus the length divided by 256 KiB/s, so a 256 MiB blob on a slow
  link can finish (about 19 minutes at the defaults) where it used to be cut at 120
  seconds every time.
- **The scan.** Runs under `spawn_blocking`, one at a time, asks the file system once
  per claim and looks each alias up once. A blob claimed by several accounts is fetched
  for the live claimant whose account has the fewest missing blobs; within one account,
  for the alias the blob's speculative charge is booked to, since the quota forecast
  nets that charge for no other alias. Up to three more accounts are kept as fallbacks:
  when this node's own state refuses the blob for one account, the same attempt goes on
  for the next, and a peer that already gave an answer of its own is not asked again.
  Without the fallbacks an account with a short queue and no room left would be chosen
  every time and keep the blob from the account that can take it. A job from an event
  knows its own account only; while its blob still waits, the scan's choice replaces it
  (`FairQueue::push_or_move`). The scan derives at most a backlog's worth per account.
  `ngit_private_mirror_lag_blobs` is set by the scan and nowhere else, so it is up to
  one scan interval old; a scan that cannot read the claim table leaves the gauge as it
  was.
- **Still open.** Without `NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS`, each attempt looks the
  peer's name up twice: in the early check, and in the client's resolver, whose answer is
  the one connected to. There is no metric for fetches held back
  by the budget or dropped from a full backlog. Nothing clears an account's gates when
  its quota is raised. A state root whose declared size differs from the stored blob is
  still accepted. A state root is accepted before its blobs are uploaded, so a replica
  can ask during the upload; that one `404` gates the blob for the maximum interval
  (unchanged by this change), which is late for a client that declares first and
  uploads after. A full backlog is refilled only by the next scan tick, not as soon as
  it empties. A shared blob still waits in the lane of the account it is attributed to:
  an account with few missing blobs and slow peers holds it for as long as its fetches
  last. No slot is kept back for an account with nothing running when two slow accounts
  hold them all.

## The blob mirror fetches from the operator's peers only, at the address it vetted

In GRASP-P's own files (`src/grasp_p/mirror.rs`, `src/grasp_p/vetted_dns.rs`, one warning
in `src/grasp_p/mod.rs`), plus the text of two settings in the four config sources and the
pair constructors of `tests/common/relay.rs` (seam table). No setting is added, and nothing
joins `policy_fingerprint`: the list is node-local, it decides where a node fetches blobs and
never what it accepts.

- **What was wrong.** With `NGIT_GRASP_P_MIRROR_PEER_URLS` unset the mirror took its peers
  from the `server` tags of each registration, so an account chose the hosts this node sent
  requests to, with a path largely of the account's choosing, on every repair pass. And a
  fetch was vetted on one DNS answer and connected on another: the address check resolved
  the peer's name, then reqwest resolved it again with the system resolver, and honoured the
  proxy variables of the environment. A name could answer a public address to the check and
  an internal one to the connection.
- **The peers are the operator's list alone**, the maintainer's decision that GRASP-P events
  and blobs replicate only between operator-configured peers, with no setting to widen it.
  `peer_servers_for` returns the entries of `NGIT_GRASP_P_MIRROR_PEER_URLS` as base URLs, each
  once, less the ones that name this node (`is_own_server`, mount path included, as for the
  sync list), so both nodes of a pair can be given one list; the list used to be taken as
  written, this node included. A registration's `server` tags are advisory: they tell clients
  where to go and choose no host to fetch from. With no list, or one that names only this
  node, there is no peer and every missing blob fails as `no_peer`.
- **One warning at startup** when the mirror is on and has no peer:
  `NGIT_GRASP_P_MIRROR_ENABLE is true and NGIT_GRASP_P_MIRROR_PEER_URLS names no peer of this
  node: the blob mirror has no peers, so no blob will replicate to this node`. It replaces the
  warning about `NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS` without a list, which was about the
  tag path. The private-link setting needs no warning of its own any more: each of its readers
  (the mirror's early check and its resolver, `relay_peer_allowed`, `grasp_p_peer_policy`)
  applies it to a listed peer only, so it no longer widens what an account can reach.
- **Every peer's length is believed**, up to the maximum blob size (`expected_len`), since
  every peer is the operator's. The flag `peers_configured` on jobs and routes, and the rule
  that held a peer named only by a registration to the declared size, are gone.
- **The address vetted is the address connected to.** The mirror's one long-lived client
  (`mirror::http_client`) has a resolver of its own, `vetted_dns::VettedResolver`, and
  `no_proxy()`. The resolver looks the name up (`tokio::net::lookup_host`; a test passes a
  lookup of its own), refuses an empty answer, and, unless
  `NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS=true`, refuses the whole answer when any address in
  it fails `outbound::is_globally_reachable` or `mirror::wraps_non_global` (the relay dial's
  check: the mirror's list, a NAT64 or 6to4 form held to both lists by the address it wraps,
  and the local-use NAT64 prefix), as the early check does. hyper-util connects to exactly
  the addresses it returns, so the connection makes no lookup of its own and nothing falls
  through to the system resolver. The lookup's socket addresses go on as they came, so a
  link-local answer keeps its scope. `connect_timeout` covers the lookup and the connection
  together.
- **Its refusal is `blocked`.** reqwest keeps a resolver's error as a source: its own DNS
  error wraps it, hyper-util's connect error wraps that, and the client error wraps the
  connect error (read in reqwest 0.13.5 and hyper-util 0.1.21). `vetted_dns::blocked_target`
  finds it there, and `fetch_from_peer` records `blocked: <host> resolved to <address>, which
  the blob mirror does not connect to`: the class that waits the maximum interval, with the
  metric label `blocked`. A lookup that fails or answers nothing is `network`, as in the
  early check.
- **The early check stays** (`peer_allowed`): scheme, credentials, local names, and the
  address of a host that is an IP literal, which hyper-util connects to without asking a
  resolver. For a name it still makes its own lookup; only the resolver's answer is connected
  to.
- **Why a resolver.** `ClientBuilder::resolve_to_addrs` fixes one name per client and hands
  every other lookup to the system resolver, so it would mean a client per blob, or a cache.
  The NIP-11 probe's `VettedAddresses` (`src/sync/relay_connection.rs`) does the other thing,
  answering with addresses vetted before its per-probe client was built, and is left as it is.
- **A connection is used again.** The client keeps its pool, so a connection opened to a
  vetted address serves later fetches without a lookup for as long as the peer keeps it open.

For an operator: set `NGIT_GRASP_P_MIRROR_PEER_URLS` on both nodes, to the other node's blob
base, which is the host, port and path of its relay over `https`; without it no blob
replicates. `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` no longer apply to the mirror: a pair
that reached its peer through a proxy loses the mirror until the proxy is out of the path. A
peer whose name answers an internal address next to its public one is refused whole, unless
the link is declared private.

Tests. In `src/grasp_p/vetted_dns.rs`, with injected lookups and no network:
`resolver_hands_on_an_all_global_answer`, `resolver_refuses_an_empty_answer` (also on a
private link, and not as a refusal of an address), `resolver_refuses_a_mixed_answer_whole`
(with a row that only upstream's list refuses, 198.18.0.1, rows that only the mirror's
refuses, a NAT64 and a 6to4 form, the same forms around 198.18.0.1 and 240.0.0.1, and the
local-use NAT64 prefix), `resolver_on_a_private_link_passes_every_answer`,
`resolver_keeps_the_scope_of_a_link_local_answer`, `resolver_refuses_a_rebound_answer` (a
public answer, then loopback) and
`resolver_asks_for_the_name_and_passes_a_failed_lookup_on`. In `src/grasp_p/mirror.rs`, on
the real client against a loopback listener, with a name under `.test` that no resolver
answers: `mirror_client_refuses_a_name_that_resolves_to_an_internal_address` (no connection,
the failure is `blocked` with the host and the address; it fails when the client loses its
resolver, because the system resolver finds no address and the failure is `network`),
`mirror_client_connects_to_the_address_its_resolver_vetted` (its control: the same request,
the answer allowed, one connection with the name in `Host`) and
`mirror_client_reports_a_failed_lookup_as_network`;
`fetch_from_peer_records_the_resolvers_refusal_as_blocked` takes the same refusal through
`fetch_from_peer` itself; `peer_allowed_refuses_internal_literals_the_resolver_never_sees`
covers the early check on the hosts no resolver is asked about. The rule of the peers:
`peer_servers_are_the_list_less_this_node` and `server_tags_never_name_a_blob_peer` (a
repair scan and the job a state root enqueues, on a real service, a registration whose
`server` tags name another host: no peer without the list, the list's peers with it).
`expected_len_believes_the_peer_up_to_the_maximum` replaces the test of the two length
rules. In `private_two_node`, every pair node started with a bootstrap peer has it as its
blob peer; `exit16`, which starts its pair without one, lists each node's blob peer by hand,
and `exit18` empties the list beside the sync list and asserts the warning, which `exit1`
asserts is absent with a peer. `exit20_mirror_ignores_the_proxy_variables` runs B with every
proxy variable set (a node is its own process, so its environment races with no other test).
Not tested: a TLS connection through the resolver (`grasp_p_tls` names its blob peer by an
IP literal), and a pooled connection outliving a change of the peer's DNS.

Still open: a name is looked up twice per attempt off a private link (above); the relay dial
is vetted and not pinned (seams 4 to 6; a pinned WebSocket dial is offered upstream); and a
pair sets two lists, `NGIT_GRASP_P_SYNC_PEER_URLS` and `NGIT_GRASP_P_MIRROR_PEER_URLS`, that
the node does not compare.

## Registration: cheap checks first, and a node named with its mount path

Both changes are in GRASP-P's own files (`src/grasp_p/registration.rs`, `host.rs`,
`mirror.rs`, `relay_labels.rs`, `src/sync/private_index.rs`, the watchdog). No upstream
source file is touched. Two of upstream's other files are: `tests/common/relay.rs` gains
the constructor `start_with_grasp_p_at_base_path` (seam table above), and
`docs/reference/configuration.md` gains one bullet under `NGIT_BASE_PATH`.

### The order of checks

A registration (kind 30640) used to have every proof of possession verified, up to 64
signature checks, before the number of its keys was counted and before the node asked
whether the sender may register at all. Anyone could make a node do that work for
registrations it was going to refuse. The admission mode was asked after the conflict
checks, so a sender the mode refuses could still raise the conflict alert and have a
coordinate pruned.

The order now, for a registration from a client or from a peer (`handle`):

| # | Step | Where | Refusal |
|---|---|---|---|
| 1 | date | `check_not_future_dated` | `invalid: event created_at is too far in the future` |
| 2 | size | `handle_inner` | `restricted: event exceeds private repo size limit` |
| 3 | shape, no signature verified | `parse_shape` | in this order: `registration must carry a d tag`, `registration d tag must be exactly 32 lowercase hex chars`, `registration must carry at least one w (write key) tag`, `registration exceeds the N key limit`, `w/aux keys must be 64 lowercase hex chars`, `registration lists the same key more than once`, `w/aux keys must carry a proof-of-possession signature`, `registration relays tag must list this node`, `registration server tag must list this node` (all `invalid:`) |
| 4 | admission, read only | `pre_admission` | the mode's message (below), or `error: private meta store failure` when the store cannot be read |
| 5 | proofs | `verify_proofs` | `w/aux key is not a valid x-only pubkey`, `w/aux key proof-of-possession signature is malformed`, `w/aux key proof-of-possession signature is invalid` (all `invalid:`) |
| 6 | write transaction | `apply` | admission again, first; then `alias already registered`, `write key already registered`, `tenant has reached the alias limit`, `quota exceeded`, `replacement rate-limited; retry later` (all `restricted:`) |

- **Admission is one function.** `new_seat_admission(cfg, event)` is the whole decision
  for a new seat: nothing in `open` mode, `tenant is not on the registration whitelist`
  in `whitelist` mode, `registration requires N bits of NIP-13 proof of work` in `pow`
  mode. `seat_admission` wraps it with the one exemption: an account that already holds
  the alias passes whatever the mode says, because the mode gates new seats only and an
  account taken off the list must keep control of the repositories it has. Steps 4 and
  6 both call `seat_admission`, each with the stored record read in its own
  transaction, so they can only differ when the record changed in between. Step 6 is
  the authority; step 4 exists to refuse early. A later change that makes the list
  reloadable replaces `new_seat_admission` and nothing else.
- **A sender the mode refuses** gets the mode's message and nothing more happens: no
  proof is verified, no write lock is taken (step 4 reads a snapshot), no conflict is
  evaluated, `ngit_private_registration_conflicts_total` does not move and nothing is
  pruned. Such a refusal still counts in `ngit_private_events_rejected_total`.
- **No message text changed.** What changed is which message a registration with more
  than one fault receives:
  - over the key cap, with a malformed key or a missing, malformed or invalid proof:
    the key limit, where it used to be the key's or the proof's message;
  - a malformed key anywhere, with a missing or bad proof on an earlier key: `w/aux keys
    must be 64 lowercase hex chars`, where it used to be the earlier key's message;
  - a key listed twice, with a missing or bad proof: `registration lists the same key
    more than once`, where it used to be the proof's message;
  - a missing proof on one key and a bad proof (or a key that is not a valid curve
    point) on an earlier one: `w/aux keys must carry a proof-of-possession signature`,
    where it used to be the earlier key's message;
  - a bad proof and a `relays` or `server` tag that does not name this node: the tag's
    message, where it used to be the proof's;
  - a bad proof from a sender the mode refuses: the mode's message, where it used to be
    the proof's;
  - a sender the mode refuses whose registration also loses a conflict over the alias
    or over a key: the mode's message, where it used to be `alias already registered`
    or `write key already registered` (and, before, the alert and the prune that go
    with a lost conflict).

  A registration with one fault gets the message it always got.
- **What a node accepts did not change.** Every check is still made; a registration is
  accepted exactly when it was accepted before. That is why the policy fingerprint has
  the same inputs and the same version label: the two nodes of a pair run the same
  build, they are given the same whitelist (which is in the fingerprint), and they
  reach the same verdict on the same registration. The admission decision reads the
  configuration and the event only, never a counter that could differ between nodes;
  the exemption reads the stored record, as the old code did when it asked the mode
  only for an alias that was new to the node.
- **Peers.** A registration that arrives from the peer goes through `handle` like one
  from a client, as before. The peer admitted it under the same policy, so the early
  check passes here too. The one case where it does not is the one that existed
  before: the account was taken off the list on both nodes and this node never stored
  the alias, so here it is a new seat.
- **Boot replay keeps the old position.** At start-up the node replays the
  registrations in its own relay database that the meta store does not have
  (`handle_replay`). There the mode is still asked after the conflict checks, and step
  4 is skipped. The early position sheds load from senders, and these events are the
  node's own; and a stored registration that lost a conflict, left behind by a failed
  prune, is then still recognised as the loser and pruned, even when its author is no
  longer admitted. With the mode asked first it would be refused by the mode at every
  start and never removed. A replay that would create a seat is still subject to the
  mode, as before: rebuilding a wiped meta store under a stricter mode needs the
  accounts listed, or `open`, for that one start. A replay judges a seat the meta store
  held before it began by its age, and a seat it creates by the order alone ("A settled
  seat is not displaced", below).
- **What is left.** An admitted account can still send registrations with 64 keys and
  cost 64 signature checks each time; that is bounded by the cap and attributable to
  the account. In `open` mode nobody is refused at step 4, so only the cap and the
  shape checks come before the proofs. In `pow` mode the work is checked before the
  proofs, but it is paid once per event and not once per send: a registration refused
  for a bad proof is not stored, so the same mined event can be sent again and cost its
  proof checks again. Only the relay's limit on events per connection bounds that.

### Under a base path the node is its host and its path

A node can be served under a path (`NGIT_BASE_PATH`, for example `/grasp`). Its relay
is then `wss://host/grasp` and its blob routes are under `https://host/grasp`, and
`host` alone is somebody else's service or nothing. The comparison that asked "does
this URL name this node" looked at the host and the port only.

`host::url_denotes_service(value, service_address)` is the comparison now. The service
address is `Config::service_address()`: the domain, followed by the mount path if there
is one. The host and the port are compared as before (`url_denotes_domain`). When the
service address has a path, the URL's path, with trailing slashes removed, has to equal
it; a query is not compared. When it has none, the path of the URL is not looked at, so
**a node at the root of its domain behaves exactly as before**, and so does every
existing test.

Every caller of the old comparison, and what it does now:

| Caller | Now | Why |
|---|---|---|
| `registration::parse_shape`, the `relays` and the `server` tag | service | A registration names where clients go. Naming the bare host of a mounted node would send them to the wrong URL. |
| `mirror::is_own_server` (entries of `NGIT_GRASP_P_MIRROR_PEER_URLS`; it judged `server` tags until the mirror took its peers from the list alone) | service | Another service on the same host is a peer, not this node. |
| `private_index::configured_peer_relay_keys` (the sync peer list) | service | The same, for relays. Its callers pass the service address. |
| `relay_labels::RelayLabels::from_config` | service | It must leave out exactly the entries the sync code leaves out, or a peer would be scraped without an alias. A test holds the two together. |
| `ngit-private-watchdog`, `derive_blob_base` | path-aware (own code, same rule) | When the relay URL it was given has a path, only `server` values with that path are candidates for the blob base. |
| `blossom_auth::names_this_node` (the BUD-11 `server` tag of an authorization) | host only, unchanged | BUD-11 puts a bare domain in that tag, with no path. Requiring a path would refuse every conforming client. |

A registration for a pair names both nodes in its `relays` and in its `server` tags.
Each node looks for itself among the values and does not judge the others.

**What changes for a node under a base path** (nothing changes at the root). A domain
setting that itself carries a path counts as mounted at that path: put the path in
`NGIT_BASE_PATH` and keep `NGIT_DOMAIN` to host and port.

- A registration whose `relays` or `server` tags name the bare host, or another path on
  the host, is refused with `registration relays tag must list this node` or
  `registration server tag must list this node`. It has to name `wss://host/path` and
  `https://host/path`. Registrations already stored are not looked at again, except by
  a boot replay into an empty meta store, which refuses the ones that name the bare
  host.
- An entry of `NGIT_GRASP_P_SYNC_PEER_URLS` that names this node's host without its
  path, or with another path, is no longer taken for the node itself. It is dialled as
  a peer, and gets an alias in the scrape. A list shared by both nodes must spell each
  node with its path.
- An entry of `NGIT_GRASP_P_MIRROR_PEER_URLS` that names this node's host without its
  path, or with another path, is a peer the mirror asks for blobs; one with the path
  is this node and is left out. Spell each node with its path there as well.
- The watchdog, given `--relay-a wss://host/path`, takes the blob base from the
  `server` values with that path only.

No setting is added. The fingerprint's `domains` input already was the service address
plus the bootstrap relay, so its inputs and its label stay as they are: both nodes of a
pair run the same build, and at the root nothing a node accepts has changed. (v4 later
replaced the bootstrap relay with the peer list; the service address keeps its path.) Upstream
has its own matcher for its own tags (`outbound::relay_url_matches_service`); it parses
more leniently and is not used for the GRASP-P checks, which stay strict about the URL.

## A settled seat is not displaced

All of it is in `src/grasp_p/registration.rs` (`SEAT_SETTLE_SECS`, `seat_is_settled`,
`challenge`, the two conflict checks in `apply`). No upstream file is touched, no setting
is added, and the fingerprint keeps its inputs and its label: the two nodes of a pair run
the same build, and no node runs the old rule. The label `grasp-p-policy-v4`, two changes
later, marks this rule as well ("Policy fingerprint v4 and the event blacklist").

### Why

Two accounts that claim the same alias, or the same key under different aliases, are
merged by the order of their registrations: the lower `created_at` of the incoming
registration and the holder's first edition wins, ties to the lower event id. That order
is what makes the two nodes of a pair agree whatever order they saw the claims in. But the
signer chooses `created_at`, and it has no lower bound, so any admitted account could
evict any repository by dating a registration before it: by its alias, or by one of its
keys, which takes the holder's whole registration. Every writer of a repository holds its
write key and every member its shared aux key, so the key form was open to every member.
The evicted repository's blob claims are dropped and its blobs collected after the grace
period.

### The rule

The maintainer's decision (2026-10-27): a seat whose first edition is more than an hour
older than the node's clock (`SEAT_SETTLE_SECS`, 3600 seconds) is never the loser of a
conflict with another account for its alias, nor with any other alias, the same account's
included, for any of its keys. An hour old exactly, a seat is still young; it settles the
next second. Younger seats merge by the order as before, so two nodes that saw a fresh
conflict in different orders still agree.

- **The age is the anchor's.** It is counted from the `created_at` of the seat's first
  edition, the same anchor the order compares against, never from `registered_at`, the
  time this node first stored the seat. Two nodes that hold the same anchor therefore judge
  a seat settled at the same moment. A node rebuilt from its relay database, or a peer that
  joined late, holds only each seat's newest edition (the relay database replaces older
  ones) and anchors there: it protects a seat once that edition is an hour old, at once for
  a seat with no edition in the last hour. Until then a claim dated before that edition
  takes the seat on that node only: the other node, which kept the older anchor, refuses
  it, by the order if it is dated after the seat's first edition and as settled if before,
  and the pair splits. A registration of the holder's own that lowers the anchor makes the
  seat older, never younger.
- **A constant, not a setting.** Both nodes must use the same value, and none of the four
  configuration sources changes.
- **The answer is the one a lost conflict always got:** `restricted: alias already
  registered` or `restricted: write key already registered`. The challenger's own
  coordinate is pruned and the conflict alert is raised as for any lost conflict. The
  warning `private registration conflict: incoming registration lost the deterministic
  merge (§3.2) and was rejected` keeps its text and gains the field `incumbent_settled`:
  `true` when the order alone would have let the challenger win and only the seat's age
  refused it, `false` for an ordinary merge loss. `loser_tenant` in the same line is the
  challenger's key.
- **The rule only ever refuses.** It turns what the order would have made a win into a
  refusal, and never the reverse, so it never evicts anyone and never puts an event into
  the relay database.

### Where the clock is read, and where it is not

The node's clock now enters a merge decision, against the rule the anchor was built on
(see `RegistrationRecord::anchor` in `src/grasp_p/meta.rs`, which names this exception). It
is read for every live decision (`handle`): a client's registration, one a peer delivers,
and a held registration retried later. The one live exception is an edition of the
sender's own seat that is no newer than the stored one: it changes no claim (it is
accepted as a no-op, and whatever it would evict stays), so a settled seat has nothing to
lose to it, and the order alone judges it, as before. Judged by the clock, an old edition
that anyone sends again, once a key it lists has passed to another account after a
rotation and that account's seat has settled, would be refused with a settled-seat warning
that names the repository's own account, and it could no longer lower the anchor on a node
that never saw it. When the node replays its own relay database at start-up
(`handle_replay`, called by `boot_reconcile`), the clock judges only the seats the meta store
held before the replay began (`registered_at` before the replay's start, passed in as
`reconcile_started`); a seat the replay itself creates is judged by the order alone. That is
what keeps a restart and a rebuild from changing what the node decided:

- **Replay.** The node writes its meta record before it stores the event, and a refused
  event is never stored, so a stored registration the meta store does not hold (a
  leftover) is a holder the node evicted, whose prune failed or never ran. At a restart
  over the same meta store the seat a leftover meets was there before the replay, so it is
  judged as it would be live. Usually the order already refuses the leftover, since the
  meta store keeps the winner's first-edition anchor. Where the leftover's alias, or a key
  it claims, was freed and then taken by another account dated after it, the order would
  let the older leftover evict that seat on this node only; once that seat has settled, its
  age refuses the leftover instead. A replay's refusal by age prunes nothing: a meta store
  older than the relay database (a restore not taken from one snapshot) would otherwise
  refuse a registration the node accepted later and delete the only stored copy of it.
  A rebuild into an empty meta store creates every seat it meets, so the order alone
  decides there. Judged by the clock instead, a rebuild would go wrong at once:
  `boot_reconcile` replays newest first (nostr orders events by `created_at`,
  descending), so it would seat the evicted holder first, settled from its first second by
  its old date, and refuse the winner, the opposite of what the node had decided and of
  what its peer holds. A seat a replay creates is dated no earlier than the replay began,
  so a clock that steps back during it does not turn it into one judged by age. What the
  replay still gets wrong is under "What is left".
- **Restoring a node.** Never start a node on a meta store (`private-meta`, inside
  `NGIT_RELAY_DATA_PATH`) older than its relay database: its seats are trusted at the
  restart, so a registration accepted after the meta copy was taken is refused (and kept,
  not deleted) while the peer holds it. Restore both from one snapshot taken with the
  service stopped, or restore the relay database alone and delete `private-meta`, so the
  start rebuilds it.
- **Sync redelivery.** An event the node accepted is a duplicate before admission
  (`process_event_static_inner` looks the id up first). A client that sends an accepted
  edition again gets the same-tenant no-op it got before. A refused registration that
  comes back is refused again while the holder holds the seat: the anchor never moves
  later, and a settled seat stays settled (a rebuild of the meta store is the exception: it
  re-anchors each seat on its newest stored edition).
- **A held registration.** Only a same-tenant replacement refused for the replacement
  cadence is held and retried, and such a registration took part in no conflict when it
  was refused: one that wins a conflict is exempt from the cadence, one that loses is
  refused for the conflict. A conflict it meets at the retry is new, and is judged like any
  arrival. If the order favours it but the claim it meets has settled here meanwhile, it is
  refused here while the peer, which admitted it at once, keeps it, and the pair splits.

### What is left

- **The first hour.** An admitted account can still take a repository's alias in its first
  hour, or, holding one of its keys, the whole repository. The eviction raises the alert
  (`stored_evicted`) and its warning names the offender as `winner_tenant`; the account is
  closed. M4 binds the alias to the account key in the wire format, so that no other
  account can register it at all.
- **The moment a seat settles, and seats that arrive settled.** A node refuses a
  challenger only for a seat it already holds once that seat has settled; a node that saw
  the challenger first, or before the seat settled, keeps the challenger. So a challenger
  that reaches one node of a pair just before the seat settles there and the other just
  after is accepted by one and refused by the other. The lag is seconds when live sync
  carries the challenger, but up to the hourly full re-issue
  (`NGIT_GRASP_P_FULL_REISSUE_INTERVAL_SECS`, 3600 s by default) when it does not, so a
  winner of a seat's first hour that misses live delivery to the peer can split the pair,
  the likelier the later in the hour it won. The same split needs no timing near any
  settle moment for a seat that is already over an hour old when it arrives (dated back by
  its signer, or delivered late): it is settled on arrival, so a challenger that the other
  node saw first is kept there and refused here. Both nodes raise the alert, the
  watchdog's registration check reports the split, and the split stays: each node now
  holds a seat the other's claim cannot displace. There is no operator tool to repair it
  until the offboarding work (issue 1).
- **A conflict planted across a partition** of more than an hour no longer heals by
  itself: each node keeps the seat it had.
- **The victim's self-heal on a mis-anchored node** (a node that never saw the seat's first
  edition, where a claim dated between the editions won; see the R2-B note in `apply`)
  works only while the claimant's seat there is under an hour old.
- **A backdated seat counts as settled at once**, since its anchor is old. That costs a
  victim only a re-registration race it could not have won anyway; two such claims sent to
  the two nodes at once split the pair ("The moment a seat settles", above).
- **A rebuild meets leftovers.** A meta store rebuilt from the relay database decides by
  the order alone and anchors each seat on its newest stored edition. A leftover the node
  failed to prune then takes a seat back on this node only (watchdog registration parity
  FAIL) when the winner that evicted it has published a later edition, or when its alias
  was freed and taken by another account dated after it; the peer keeps the winner, with
  no repair tool before the offboarding work. A restart over the same meta store keeps the
  first-edition anchors and is not affected by the first case; in the second it judges
  the other account's seat by its age, so a leftover can still evict that seat while it
  is under an hour old.
- **Three or more parties.** A chain of conflicts (A and B share one key, B and C another)
  is not order-independent at a replay or a rebuild, as before this change: a later
  registrant can lose its seat there until sync redelivers it.
- **The loser's blob claims** are still dropped at eviction; keeping them needs a claim
  state of its own, because claims are keyed by the alias the winner now holds.

## Who may delete

The maintainer's decision (D6, 2026-10-27): only the account key, the key that signs a
repository's registration, deletes a private repository's data from the server, and only
the whole repository, through that registration. Members cannot delete from the server at
all. The server cannot tell members apart behind a shared key (every member holds the
repository's aux key), so a right to delete for one member would be a right for every
member, the read-only and the removed ones included, to erase everyone's history and to
block the shared key for good. Clients hide content through the encrypted stream instead,
and the ciphertext stays until the repository is deleted.

### What upstream did on a GRASP-P node

Upstream's tombstone gate (`DeletionService::gate`) runs before GRASP-P admission, for
every kind, and upstream checks a kind 5 only for the authorship of the `e` targets it
holds (`DeletionPolicy::validate_request`). So:

- a write key could delete its stored state roots, by `e` id or by an `a` coordinate
  `30641:<key>:<alias>`, and an aux key every stored wrap it signed, by `e` id or by one `a`
  coordinate of the wrap kind: wraps are not addressable, so `3359:<key>:` names every
  event of that kind by the key, dated up to the request;
- a vanish (kind 62) from either removed every stored event of the key, and the gate then
  refused all its later events; a vanish, or a coordinate deletion dated far ahead, sent
  before the key was registered blocked the key once a registration listed it;
- an account could delete its registration by event id alone, though the two nodes of a
  pair can hold different editions for a while, and a far-future coordinate deletion
  blocked its own later registrations of the alias;
- upstream's announcement cascade, which a public repository's deletion, its owner's vanish
  and a newer edition that no longer lists this node all run, follows tags both ways and
  removes what no surviving public repository anchors. Any key may publish a public note
  that tags a public repository it owns and also a registration, a state root or a wrap;
  deleting that public repository then removed the registration, every state root that
  tags it and the wraps the note named, with no request naming any of them.

Kinds 5 and 62 were in no GRASP-P sync filter, and upstream's own filters ask only for
events tagged with a public repository or one of its root events, so a deletion accepted on
one node never reached the other: the registration stayed live there.

### The rule, in four places

- **The guard**, `grasp_p::offboard::guard`, which `grasp_p::admission::admit` calls first
  for every kind 5 and kind 62, from a client or from sync. More than 2048 `e` and `a`
  targets are refused first, in upstream's words and before any lookup; that refusal is
  upstream's own, so it is neither counted nor logged as GRASP-P's. Then it refuses, in this
  order: an `a` coordinate of a state root or a stream-wrap kind (stored, ephemeral and
  legacy), its kind read as upstream reads it, as a number, so `030641` is 30641; an `a`
  coordinate of a registration under another pubkey, or with its kind spelled other than
  `30640` (upstream would delete the event, while the claim hook and the gate, which compare
  text, would miss it); a request with `["k", "30640"]` that names no registration of its
  signer by coordinate; any other request from a key that is a write or aux key of a
  registration on this node (a claim row with no registration counts); an offboard request,
  one naming registrations under its signer's own key by coordinate, without `["k",
  "30640"]` or dated more than 15 minutes ahead (`check_not_future_dated`); from a write or
  aux key, an offboard request that also names a coordinate of any other kind, or an `e`
  target this node does not hold or that is anything but a registration the request names
  by coordinate; and an `e` target this node holds that is a state root, a stream wrap,
  another key's registration, or a registration whose coordinate the request does not name
  too. A vanish is refused from a write or aux key, and from a key that signed a stored state
  root or stream wrap: upstream would remove them, and a wrap names no repository, so there
  is no telling whose history it is. Every other request returns `None`, and upstream
  handles it exactly as on a node without GRASP-P (decision D1): a public repository's
  deletion, an account deleting its own public notes, a stranger's vanish. A store that
  cannot be read refuses with `error:` and deletes nothing. The refusals are `restricted:`,
  or `invalid:` for a malformed offboard request, and none contains "unregistered", the word
  the client widens on. Each counts in `ngit_private_events_rejected_total` under the kind
  `5` or `62`. When the refused request came by sync, `admit` keeps its id in the hold
  (`PrivateRejectedIndex::add_id_only`), as for a refused GRASP-P kind, so the negentropy
  batch that asked for it completes instead of failing on every connect; a store fault and
  the target cap keep nothing.
- **The gate exemption**, in `admit_event` (`src/nostr/builder.rs`, 9 lines in place of 2,
  inert with GRASP-P off): the gate is not called for a state root or a stream wrap of a
  kind this node takes (`grasp_p::offboard::deletion_gate_exempt`). Only this stops a request
  that got in before its key was registered, or before this rule, from blocking that key; no
  check at request time can see the future. Registrations stay gated: a coordinate deletion
  of a registration is exactly what must keep a replay of it out. A legacy kind the node
  refuses keeps upstream's gate and upstream's answer, since admission refuses it anyway.
- **Upstream's deletion paths**, two seams, both inert with GRASP-P off. The cascade's plan
  (`plan_deleted_announcement_cascade` in `src/nostr/lifecycle/deletion/cascade.rs`) leaves
  registrations, state roots and stream wraps out of the events it deletes
  (`grasp_p::offboard::cascade_exempt`), so whatever public event tags them, a public
  repository's deletion, vanish or de-listing does not remove them; they stay in the graph,
  so what the cascade keeps or removes of every public event is upstream's.
  `archive_and_delete_filter` (`archival.rs`, 8 lines added), the step every
  NIP-09, NIP-62 and cascade deletion goes through, leaves a state root or a stream wrap in
  place (`grasp_p::offboard::removal_exempt`): the backstop for a request whose target
  arrived between the guard's lookup and upstream's delete, which no lock covers. Both count
  the legacy kinds whatever the setting, since a node that stopped taking them still holds
  the ones it took. GRASP-P's own removals (an evicted registration, and the hold-and-purge
  work) delete from the store directly and are not affected.
- **The sync filters**, `build_private_offboard_filter` and `build_private_vanish_filters`
  in `src/sync/grasp_p_sync.rs`. The peer set (`grasp_p_filter_set`) carries
  `{kinds:[5], #k:["30640"]}`, unscoped by author, so a node takes an offboard request
  before it holds the registration and refuses the registration when it arrives, and
  `{kinds:[62], authors:[...]}` for every 100 accounts that hold registrations here
  (`PrivateRepoEntry::tenant_hex`, `PrivateSyncIndex::tenants`). Both go to configured peers
  only, on connect, quick reconnect, consolidation and the full re-issue; the vanish filters
  also ride the re-issue an index change sends (`grasp_p_index_filters`), and a change of a
  registration's account is an index change. A synced request passes the same write
  policy, so both nodes judge it alike and run the same claim hook.

An accepted request is upstream's from there: its NIP-09 or NIP-62 handling, then the
claim-freeing hooks in `builder.rs`, unchanged. A deletion request removes no state root and
no wrap, the guard refusing every request that names one this node holds and the removal
exemption keeping any other. They stay stored and served, and new ones are refused because
the registration is gone, until the hold-and-purge work removes them with the repository. An
account's vanish removes its registrations; the state roots and wraps its members signed
stay in the same way.

### What is left

- **Requests accepted before this rule** keep their effect: what they deleted is gone. Their
  tombstones still gate registrations, by design, and no longer gate state roots or wraps.
- **An `e` target this node does not hold** cannot be judged. From a write or aux key the
  request is refused; from any other key, for a state root or a wrap the exemptions make it
  inert. An account's deletion of a registration edition by id alone and without the k tag,
  sent to the node that does not hold that edition, is taken there, and that node then
  refuses the edition when it arrives while the other keeps it; the account's next edition
  heals the split.
- **A request the two nodes judge differently** is acted on by one only: one node has seen a
  key's membership or a target the other has not yet, or runs the previous build. The
  refusing node keeps the request's id for the hold's time to live, so sync with its peer
  completes, and is offered it again once the id expires.
- **An account key that is also a member key cannot vanish.** A key that holds a write or
  aux claim, or signed stored state roots or wraps, closes its repositories one by one with
  offboard requests instead. A key whose membership one node has not seen yet can vanish on
  that node, which then removes that key's own registrations there only.
- **The offboard request stays public** under upstream's request retention (served for
  months after its last use), naming the account key and the alias; it is what keeps a
  replay of the registration out (decision D7).
- **A public event that tags a registration, a state root or a wrap** is refused now
  ("Nothing attaches to private-repository events", below). One stored before that rule, or
  one that names by id a state root or wrap this node did not hold yet when it arrived,
  stays upstream's: upstream's cascade may remove it with a public repository it tags, or
  with one that another such event links to the same registration, state root or wrap, and
  the cascade exemption keeps the private events themselves in place.
- **The hold-and-purge work** must remove state roots and wraps with GRASP-P's own store
  calls: on a GRASP-P node `archive_and_delete_filter` passes over them, and the cascade's
  plan over registrations too.
- **Disrespector mode** (`NGIT_DELETION_REQUEST_DISRESPECTOR=true`): the guard refuses as
  ever, upstream only records what passes, and no registration is ever deleted; refusing
  the combination at boot comes with the hold-and-purge work.
- **Every full re-issue** asks the peer for every offboard request it still serves, and each
  is a duplicate here: one filter, bounded by upstream's request retention.

## Nothing attaches to private-repository events

The maintainer's decisions of 2026-10-28 for a node that serves public repositories
beside private ones (D1): no event of another kind may reference private-repository
content (decision A); a report on it is refused, logged and counted (D10 with D15-1 to
D15-3); an id this node does not hold yet is not recognised (D15-5). All of it is GRASP-P
code: `src/grasp_p/attachment.rs`, `src/grasp_p/reports.rs`, the routing in
`grasp_p::admission::admit`, `is_private_event_kind` and the intake's memory of the reports it
logged in `src/grasp_p/mod.rs`, and the live sync path's skip of the ids admission keeps
(`grasp_p_previously_rejected` in `src/sync/grasp_p_sync.rs`). The one change to upstream's
code is a deletion: the GRASP-P arm for kind 1984 in `admit_event`'s dispatch
(`src/nostr/builder.rs`, 6 lines out, the comment above the `admit` call reworded).
`src/nostr/policy/related.rs` has no seam.

### What upstream did on a GRASP-P node

- **Backward anchors.** `RelatedEventPolicy` stores an event of an unhandled kind, a PR
  included, when one of its `a`, `A` or `q` coordinates names any stored event of that kind
  and author with that `d` tag, or one of its `e`, `E` or `q` ids is any stored event. A
  registration's coordinate `30640:<account>:<alias>`, a state root's and the id of any
  registration, state root or stored wrap all served as anchors, so anyone could store
  plaintext against a private repository, uncharged and outside its quota and collection,
  and have it served to whoever asked for `#a` or `#e` of those coordinates and ids.
- **Forward vouching.** The same rule stores an event that any stored event tags. A GRASP-P
  event could carry any tag (registrations and wraps were not checked for extra tags, a
  state root's first `a` tag wins and the rest went unread), so a wrap or a state root
  could vouch for a public event before it arrived, and upstream's recursive descendant
  frontier (`sync/mod.rs`) took such a GRASP-P event into the threads it follows, asking
  relays that are not peers for what tags it and making its signer an author it looks up.
- **No check at all.** Every kind 10317 is accepted from anyone, with any tags, and the
  relay owner's events of every kind without a dedicated policy are accepted; neither meets
  the related-event rule.
- **Reports.** A kind 1984 took a GRASP-P arm that logged it and counted it in
  `ngit_private_report_events_total`, whatever it named, then went through the related-event
  rule: a report that named a registration by id was stored on it, with whatever blob key
  it carried, and every public report was logged with its reporter's key.
- **The audit hashtag.** Upstream's audit cleanup (`src/audit_cleanup.rs`) hard-deletes every
  event, of any kind, with `["t", "grasp-audit-test-event"]` once it is two hours old, past
  every deletion hook: a GRASP-P event with that tag would go while its claims stayed.

### The rule

`admit` runs before upstream's dispatch, for client and synced events alike, after the
blacklist and the tombstone gate. For an event of a kind GRASP-P does not own (not in
`PRIVATE_EVENT_KINDS`: 30640, 30641, 3359, 23359, 1059 and 21059, whatever
`NGIT_GRASP_P_ACCEPT_LEGACY_WRAP_KIND` says), other than kinds 5 and 62, which stay with the
deletion guard:

- **`attachment::judge`** refuses it when an `a`, `A` or `q` value with a colon has a
  GRASP-P kind before its first colon, read as a number as upstream reads it (`030640`,
  `+30640`), from the event alone and whether or not anything is stored under it; or when
  one of its `e`, `E` or `q` ids (a `q` without a colon) is a stored GRASP-P event, found by
  one query by id and kind against the relay store upstream's rule reads. The answer is
  `restricted: events that reference private repositories are not stored on this
  service`; it names nothing, and contains neither `unregistered` nor upstream's `event
  must reference an accepted repository or accepted event`, which sync keeps an event for
  and retries on. An event with more than 2048 distinct `e`, `E` and `q` ids that parse is
  refused whole first, `invalid: event carries too many references to check`, whatever they
  name: reading only the first ones would let a reference placed after them through. A `q`
  coordinate, a repeated id and a value that does not parse cost no lookup and are not
  counted. Every other event goes on to upstream as on a node without GRASP-P.
- **`reports::judge`**, for a kind 1984, refuses it in the same cases and also when: a
  64-hex value of any tag (in any case, compared in lower case) is a blob this node holds a
  claim for or one on the loaded denylist; an `x` tag sits beside a `server` value that names
  either node of the pair, the node itself or a blob's URL on it (`/<sha256>`, with or
  without an extension), compared as the fingerprint compares names (`fingerprint_domain`,
  once the scheme is in lower case and any user part is dropped), where the pair is this
  node's service address and the peers its operator lists in `NGIT_GRASP_P_SYNC_PEER_URLS`
  and `NGIT_GRASP_P_MIRROR_PEER_URLS`; or a `p` or `P` value is a write or aux key with a
  claim here (D15-2). An account key in `p` does not count, even when its registration lists
  it among its own write or aux keys. A report that points at private content is logged by
  `admission::log_report` (the line `NIP-56 report event received`, its fields unchanged;
  `sha256_tags` lists the `x` values first, in lower case and each once, up to 16), counted
  in `ngit_private_report_events_total` and refused `restricted: reports about private
  repositories are not stored on this service` (D15-3). It is refused each time it comes and
  logged and counted once: the intake remembers the last 4096 report ids it logged, so a
  report that sync fetches again does not page again. Any other report is upstream's, with
  no GRASP-P log line and no count (D15-1): stored on a public anchor, or refused in
  upstream's generic words. More than 2048 distinct 64-hex values, or beside an `x` tag more
  than 2048 distinct `server` values: `invalid`, as above. Every id that parses is a 64-hex
  value, so that bounds the ids too.
- A refusal of a synced event is kept by id in the hold (`add_id_only`), as for a refused
  deletion request, so the sync batch that asked for it completes; while the id is kept, the
  live sync path skips the event, as it does a refused GRASP-P event
  (`grasp_p_previously_rejected`, which took GRASP-P kinds only before). A store fault,
  answered `error:`, is not kept.

For GRASP-P's own kinds `attachment::reference_tag_refusal`, in `admit` after the size check
and before the rate bucket, refuses a registration or a stream wrap (stored, ephemeral,
legacy) with any `e`, `E`, `q`, `a` or `A` tag, a state root with an `e`, `E`, `q` or `A` tag
or more than one `a` tag (the one it has must name its own registration, which the
state-root path checks), and any of them with the audit hashtag. A tag counts by its name,
whatever its values. The refusals are `invalid:`, final for sync (`Rejected(Invalid)`), no
dependency rejection, so nothing is held for a registration and a synced one is remembered
by id; each counts in `ngit_private_events_rejected_total`. cord-git sends none of these
tags: a 30640 carries `d`, `w`, `aux`, `relays` and `server`, a 30641 `d`, one `a`, `m` and
`pack`, an outer wrap none. The refusal comes before the key lookup, so a tagged wrap from an
unregistered key now gets it rather than `unregistered key`.

### Why upstream's related-event rule needs no seam

`check_references` has one caller, `handle_related_event` (`src/nostr/builder.rs`), reached
from the PR arm and the generic arm of the dispatch, both after `admit`.

- **Backward.** A GRASP-P kind never reaches the dispatch on a GRASP-P node: `admit`
  answers every one of them. An event of another kind with a coordinate of a GRASP-P kind,
  or with the id of a stored GRASP-P event, is refused by `admit` before it gets there. The
  rule reads coordinates and ids exactly as `extract_reference_tags` does, so no reference
  the related-event rule would follow passes `admit`.
- **Forward.** `is_referenced_by_accepted` asks whether any stored event tags the incoming
  one. A GRASP-P event stored under this rule carries no `e`, `E`, `q`, `a` or `A` tag but a
  state root's own `a`, which names a 30640, a kind that never reaches the rule.
- **The descendant frontier** follows only events that tag a thread root or a member, and
  a GRASP-P event tags none.

What is left on that path is the race and the residuals below, none of which a seam in
`related.rs` would close any better than `admit` does.

### What is left

- **An id this node does not hold yet** cannot be recognised (D15-5): an event that names a
  registration, state root or wrap by an id still on its way from the peer, beside a public
  anchor, is stored on this node, served here for `#e` of that id, and stays; the peer, which
  holds the private event, refuses it. A coordinate is judged from the event alone and has
  no such gap. The same holds for an id that is stored between `admit`'s query and the
  related-event rule's own, for a stranger's kind 5 naming a wrap before it arrives (stored
  as upstream stores it, and inert for the wrap), and for an event waiting in purgatory,
  which is not judged again when it is promoted.
- **What was stored before this rule** stays: public events that reference private
  content, and GRASP-P events with reference tags (no GRASP-P node has run in production,
  so there is nothing of ours to scan). The cascade exemption keeps the private events of a
  deleted public repository whatever links them.
- **Other ways to name private content.** A blob named only inside a URL (an `r` or `url`
  value ending in a hash) or in an event's content is not matched; a report's hash is
  matched as a bare 64-hex value. An accusation and a key in the content of an event that
  references nothing private are upstream's.
- **The pair's names are the operator's.** A report's `server` value counts only when it
  names this node or a peer on the sync or mirror list; a registration's own `server` values
  are not read, since an account writes them as it likes. A peer listed only by a link
  address is matched by that address, not by its public name, so a report that names the
  public name beside a hash not claimed here is upstream's: M8 lists each peer by its
  `NGIT_DOMAIN`. A URL on the node that is not a blob's, a public repository's say, does not
  count either.
- **Hashes and keys an account chooses.** A state root claims every blob it declares before
  any upload, and a removed repository's claims stay through the GC grace period, so any
  write key can make this node refuse the reports that name a hash it chooses; uploading the
  bytes of a public file claims that file's hash too. A key an account claims as a write or
  aux key, with the key's proof, makes the reports that name it in `p` refused here, so a key
  holder can keep reports on its own public key off this node. Each such report still
  reaches the intake.
- **A hash not claimed here yet.** A report that names a hash this node holds no claim for
  yet, the state root still on its way from the peer, and carries no `server` tag naming the
  pair, is upstream's and stays if it is stored.
- **Ephemeral wraps** are never stored, so an event that names one by id is never
  recognised.
- **Keys in events of other kinds.** An event of another kind that names a write or aux key
  in `p` beside a public anchor is upstream's and is served for `#p` of that key; only a
  report counts such a `p` (D15-2).
- **The hold's id budget is shared.** A refused synced event of a public kind is kept by id
  in the same budget as GRASP-P's own refusals (61,440 ids within the TTL). A flood of
  public events that each reference private content, from a relay this node follows, can
  fill it; the peer's refused GRASP-P events are then not remembered, and are fetched and
  judged again on each round until room frees. That is churn, not a wrong answer. Merge
  request 18 gives them a budget of their own (decided 2026-10-28).
- **Refusals of public events are not counted.** The rule refuses events of any kind, and a
  counter labelled by kind would let any sender create series; the refusal is logged at
  debug level with the event id, author and kind.
- **The denylist now moves acceptance**, of reports only: two nodes with different lists
  take different public reports. It stays out of the fingerprint, since GRASP-P replicates
  no report.
- **Retry churn.** A public event that sync brought before the private event it names, and
  that upstream kept for its related-event retry, is retried when that private event is
  saved, refused, and stays in upstream's retry index until it expires, bounded by
  `RELATED_RETRY_CLOSURE_LIMIT`.
- **The cap refuses public events** with more than 2048 distinct `e`, `E` and `q` ids, and
  reports with more than 2048 distinct 64-hex values or, beside an `x` tag, more than 2048
  distinct `server` values, whatever they name; upstream took them. Repeats and values that
  do not parse are not counted.

### Tests

Unit tests in `src/grasp_p/attachment.rs`, over the real write policy and an in-memory
relay database: `the_private_kinds_are_the_six_grasp_p_kinds_and_the_cascade_list` (also
that the cascade passes over exactly these, for every kind),
`references_are_read_as_upstream_reads_them`,
`a_coordinate_of_a_grasp_p_kind_is_refused_beside_a_public_anchor` and
`an_id_of_a_stored_grasp_p_event_is_refused_beside_a_public_anchor` (each event also tags a
stored public note, so each fails when its check goes),
`a_stored_legacy_wrap_counts_on_a_node_that_retired_the_kind`,
`kinds_upstream_takes_unchecked_are_refused_too` (10317 and the relay owner),
`public_references_are_upstreams`, `an_id_not_stored_yet_is_judged_when_it_is`,
`with_grasp_p_off_upstream_decides_alone`, `past_the_cap_the_event_is_refused_whole`
(repeated ids and junk not counted), `a_refused_synced_event_is_remembered_by_id`,
`grasp_p_events_carry_no_reference_tags` (every kind and tag, client and sync, nothing
held, untagged controls taken) and
`a_tagged_wrap_from_an_unregistered_key_is_not_held`. In `src/grasp_p/reports.rs`:
`a_report_pointing_at_private_content_is_refused` (coordinate, id, claimed and denylisted
blob, `x` beside the names and blob URLs of this node, the sync peer and the mirror peer, a
loosely spelled URL, write and aux key in `p` and `P`),
`a_report_on_public_content_is_upstreams` (the account key, one listed as its own write key
too, other servers, one a registration names among them, a public repository's URL on this
node, and upstream's own answer to an orphan, which fails if the GRASP-P report arm comes
back), `the_relay_owners_report_is_judged_too`,
`a_refused_synced_report_is_remembered_by_id`,
`a_report_is_logged_once_however_often_it_comes`,
`the_intake_forgets_the_oldest_report_first` and `past_the_cap_a_report_is_refused_whole`
(repeats counted once, and `server` values beside an `x`). In `src/grasp_p/admission.rs`:
`the_intake_line_puts_the_reported_hashes_first`, and
`only_dependency_rejections_are_holdable`, which lists the ban's messages as not held. The
cascade test in `src/grasp_p/offboard.rs` now stores its bridge directly, after asserting
that the write policy refuses it. Integration: `exit32_kind1984_report_intake` (rewritten:
eight private reports refused and counted, the other node named by
`NGIT_GRASP_P_MIRROR_PEER_URLS`, three public ones stored and not counted, one of them naming a server the registration lists, an
orphan in upstream's words) and `exit43_nothing_attaches_to_private_repository_events` (a
public repository beside a private one; coordinates before the registration exists, ids
before and after the wrap is stored, a 10317, the tag ban and its count) in `private_repos`,
where `exit3`'s tagged wrap from an unregistered key now gets the ban; and
`exit24_nothing_attaches_to_private_events_on_either_node` in `private_two_node`.

## Configured peers: the only relays GRASP-P syncs with; kept, not muted, redialled

The relay connection a node keeps to the other node of its pair is how private
repositories replicate, and it is the only way: GRASP-P events, and the filters that ask
for them, travel on the connections to the relays the operator listed and on no other.
That is the maintainer's decision, with no setting to widen it; relay and server tags in
registrations never choose a relay to sync with. Upstream's sync manager sends every
relay the same filters, takes events from any of them, and treats every relay as one it
may give up on. The logic is in `src/sync/grasp_p_sync.rs` (the peer set in `src/sync/private_index.rs` and
`src/grasp_p/mod.rs`, the address check in `src/grasp_p/mirror.rs`); upstream's files
carry these seams, each marked `GRASP-P seam:`:

| # | Where | Seam | Lines |
|---|---|---|---|
| 1 | `src/sync/mod.rs`, `handle_disconnect` | `let desired = desired.or_else(\|\| self.grasp_p_peer_needs(relay_url));` after upstream's own two sources | 2 |
| 2 | `src/sync/mod.rs`, `schedule_connect_relay` | `&& self.grasp_p_naughty_mute_applies(&relay_url)` on the naughty-list condition | 2 |
| 3 | `src/sync/mod.rs`, `register_relay` | `self.grasp_p_peer_policy(&relay_url).unwrap_or_else(\|\| self.outbound_target_policy())` where upstream took the node's policy | 4 |
| 4 | `src/sync/relay_connection.rs`, `connect` | `.and_then(\|vetted\| { mirror::vet_relay_dial(self.grasp_p_node, vetted) })` on the result of `authorize_resolved` | 4 |
| 5 | `src/sync/relay_connection.rs`, `vet_nip11_target` | `let resolved = mirror::vet_relay_dial(self.grasp_p_node, resolved)?;` after `authorize_resolved` | 2 |
| 6 | `src/sync/relay_connection.rs`, `RelayConnection` | the field `grasp_p_node` and its builder `with_grasp_p_address_check`, `grasp_p_node: false` in both constructors, and `pub(super)` on it and on `forward_duplicate_events`, so the sync manager's tests can read both | 11 |
| 7 | `src/sync/mod.rs`, `sync_generic_filters` | `filters.extend(self.grasp_p_filters_for(relay_url));` | 2 |
| 8 | `src/sync/mod.rs`, `sync_generic_history` | the same | 2 |
| 9 | `src/sync/mod.rs`, `complete_live_filters` | the same | 2 |
| 10 | `src/sync/mod.rs`, `register_relay` | `.with_grasp_p_address_check(self.config.private_repos_enable)` and `.with_duplicate_event_forwarding(self.grasp_p_is_peer(&relay_url))`, where forwarding went by the switch alone | 4 |
| 11 | `src/sync/mod.rs`, `process_event_static_inner` | `if let Some(refused) = Self::grasp_p_gate(write_policy, event, relay_url, save_context) { return refused; }`, directly after the id and signature check | 4 |
| 12 | `src/sync/mod.rs`, `handle_eose` | `received.extend(self.grasp_p_settled_ids(requested));` beside upstream's own `is_dependency_pending` extension of the negentropy completion check | 2 |

Seams 7 to 9 were `filters.extend(self.grasp_p_filters());`, unmarked, before. The two
older seams in `check_disconnects` and `retry_disconnected_relays`
(`desired_relays.extend(self.grasp_p_peer_relays())`) are unchanged lines; the set they
extend with is narrower now.

- **One set.** The configured peers are the entries of `NGIT_GRASP_P_SYNC_PEER_URLS`,
  minus the ones that name this node, each as the key the sync code files a relay under
  (`configured_peer_relay_keys`: `normalize_relay_url`, the own-address exclusion, then
  `canonical_relay_key`). `PrivateConfig::from_config` builds the set once and the
  service holds it (`PrivateService::sync_peer_relays`, `is_sync_peer`); the sync manager
  reads it through `grasp_p_peer_relays` and `grasp_p_is_peer` for every point below:
  the filters, the re-issue, the source gate, duplicate forwarding, keep-alive, the
  redial, the naughty-list exemption and the dial policy. The scrape's aliases come from
  the same function. So no two of them can disagree about a relay. A relay URL is brought
  to its key before it is compared, by the function `register_relay` files it under, so
  `wss://peer.example/` is the peer `wss://peer.example`. With GRASP-P off there is no
  service and no peer.
- **The bootstrap relay is a peer only when the list names it.** Upstream dials it at
  startup and registers it as operator-configured; that is all a relay named by
  `NGIT_SYNC_BOOTSTRAP_RELAY_URL` alone gets on a GRASP-P node: public sync under
  upstream's rules, no private filters, no GRASP-P events, no duplicate forwarding, no
  keep-alive, no redial, no naughty-list exemption and no alias in the scrape. Upstream
  retires it when its session ends and nothing public wants it, and does not dial it
  again. A relay that is both listed and the bootstrap relay is a peer like any listed
  one, and keeps upstream's exemption from the outbound policy, because it is registered
  as the bootstrap relay and a peer is never retired. Upstream reads the bootstrap URL
  through `canonical_relay_key` alone, without `normalize_relay_url`: spell it as the
  list entry is spelled (a trailing slash after a path makes a different key, and then
  a second connection, which is not a peer). `policy_fingerprint` took its `domains`
  from the bootstrap relay until v4, and takes them from the list now ("Policy
  fingerprint v4 and the event blacklist", below).
- **Egress: the private filters go to peers only** (seams 7 to 9). They name every alias
  and write key the node holds. Every way they reach a relay goes through
  `grasp_p_filters_for(relay_url)`: the live and historic sync at connect
  (`sync_generic_filters`), the quick reconnect and the consolidation
  (`complete_live_filters`, then `sync_generic_history`), every rebuild of a relay's live
  coverage (`complete_live_filters`), and negentropy, which runs inside the historic sync
  of those same filters. The full re-issue builds the whole set unconditionally
  (`grasp_p_filter_set`), the re-issue on an index change the derived filters alone, and
  both send to `grasp_p_live_peers` alone (`grasp_p_reissue_to_live_relays`). Any other
  relay is asked for upstream's filters and nothing more, so this node's subscriptions
  hand no relay outside the list the membership map (the registrations themselves are
  served to any anonymous REQ, CORD-git-v0-spec.md §1), and its subscription slots carry
  no GRASP-P filter. A full re-issue round that finds no live
  peer counts as skipped (`ngit_private_full_reissue_skipped_total`).
- **Ingress: the source gate** (seam 11, `grasp_p_gate`). A 30640, a 30641 or a stream
  wrap of a kind the node takes (stored or ephemeral) that relay sync brings from a relay
  that is not a peer is answered `Rejected(Blocked)` before admission. Nothing of it is
  applied, held or remembered by id, so the same event from a peer or a client is
  admitted as ever, and `Blocked` is a final answer, so a batch or a recovery fetch on
  that relay completes instead of asking again. One call covers every relay-sync path,
  because each ends in `process_event_static_inner` with `SaveContext::RelaySync` and the
  relay the event came from: the event stream of a connection (live subscriptions,
  historic pages, negentropy hydration, duplicate forwarding), missing-event recovery,
  the participant mailbox fetch, NIP-65 discovery and the purgatory dependency fetch. It
  does not gate hold reprocessing or the cadence retry (`HotCacheReprocess`: the event
  came from a peer or a client before it was held), nor events from clients, which never
  pass here. The stream's known-rejected skip comes first and runs no admission either.
  Upstream's related-event closure re-enters the function with its trigger's relay, but
  its candidates are upstream's related events, never a GRASP-P kind, which admission
  always answers itself. Each refusal counts in `ngit_private_sync_foreign_source_total`,
  and the first from a relay logs `Refusing GRASP-P events from a relay that is not a
  configured sync peer` (up to 1024 relays, then only the counter). Without the gate a
  relay outside the list could feed admission with events nobody asked it for.
- **Duplicate forwarding on a peer's connection only** (seam 10). The re-issue that needs
  it goes to peers alone, and every other connection of a GRASP-P node now syncs exactly
  as upstream's. The stricter address check stays on every connection (seams 4 to 6,
  below): it is about the relays customers' events name.
- **Negentropy counts GRASP-P's own decisions** (seam 12, `grasp_p_settled_ids`). A
  requested id that GRASP-P holds for a registration, or has refused and remembers, was
  delivered. Before, a batch that held a new GRASP-P event completed only on the SDK's
  second copy, which duplicate forwarding skips, so it took a second round and logged
  "Negentropy sync incomplete". The skip of known-rejected GRASP-P ids before a fetch
  (`src/sync/history.rs`) is unchanged.
- **Kept when its session ends** (seam 1). A relay whose session ends without the node
  having closed it is kept by upstream only if a repository or a NIP-65 list still names
  it. A configured peer carries neither, so it was retired: its state, its connection
  object, its health record and its metrics were dropped, and the next tick registered it
  again from nothing, with no backoff and a full resync. Now it stays tracked, in the
  disconnected state, with the failure counted, and upstream's reconnect loop redials it
  under upstream's backoff. A node no longer logs `Naturally ended relay session is no
  longer owned; retiring without reconnect` for a peer; it logs `Unexpected relay
  disconnect detected`.
- **Not muted by the naughty list** (seam 2). A dial that fails over DNS, TLS or the
  WebSocket protocol puts the relay on upstream's naughty list, and for twelve hours
  upstream neither dials it nor considers it due. For the pair's other node that is half
  a day without replication after, for example, a certificate that was renewed an hour
  late. The entry is still recorded for a peer, with upstream's warning and its metric;
  only the refusal to dial is lifted. Upstream's reconnect loop still skips a
  naughty-listed relay (`should_attempt_connection` in `src/sync/health.rs`, untouched),
  so the redial below is the only thing that dials such a peer. Nothing removes an entry
  before its twelve hours are over, so a peer that recovered keeps it: it still counts in
  `ngit_sync_naughty_relays_total`, and should its session end again within that time it
  is redialled by the redial below, within five minutes, and not by upstream's quicker
  loop.
- **A bounded redial** (`grasp_p_redial_peers`, on GRASP-P's 5 second tick, no seam).
  A configured peer that is disconnected, has no dial queued or running, and has had
  neither a dial nor a failure for 300 seconds (`PEER_REDIAL_INTERVAL`; 2 seconds under
  `NGIT_TEST=1`) is handed to `schedule_connect_relay`. Upstream's backoff doubles from
  the base to an hour, and after 24 hours of failures it dials once a day; this caps the
  wait at five minutes whatever that backoff says, and at one dial per peer per interval.
  It reads the health tracker's last attempt and last failure and keeps its own record
  of the dials it issued (`PeerRedial`). It does not fight upstream's loop: both go
  through `schedule_connect_relay`, which takes a relay only in the disconnected state
  and moves it to connecting, and through the one-per-relay reservation of dial
  attempts, so two dials of one relay cannot be in flight; and a dial by either resets
  the other's clock. The dial runs in upstream's worker, so nothing here does network
  work under the manager's lock. Only the tick registers a peer that is not tracked yet;
  a peer that is also the bootstrap relay is registered by upstream at startup.
- **A dial policy of its own** (seam 3). Every relay that is not registered as the
  bootstrap relay must pass upstream's outbound target policy, which refuses loopback
  and private addresses. A pair whose nodes talk over a private network therefore had to
  set `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS=true`, which lifts the policy for every relay
  that customers' events name as well. Now the connection to a configured peer is built
  with a permissive policy when `NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS=true`, the
  setting by which the operator already says the pair's link is private, and every
  other connection keeps the node's policy. With that setting `false` a listed peer gets
  the node's policy like any relay. The bootstrap relay is registered as
  operator-configured, so no policy is consulted for it under either value, which is
  upstream's exemption; a listed peer that is also the bootstrap relay keeps it for the
  life of the process, since a peer is never retired. The exception is carried by the
  relay key, as upstream carries its bootstrap exception: an event that names exactly the
  peer's URL shares the peer's connection, and any other URL does not. A permissive
  policy vets nothing and pins nothing for that connection, NIP-11 probe included, which
  is what the operator asked for. The setting is node-local and not in
  `policy_fingerprint`: it decides what a node dials, never what it accepts. Two nodes
  that differ in it do not show in the fingerprint; the node without it mirrors no blob
  over the link and refuses a peer that only the list names, so events then flow one way
  only and `NgitSyncPeerDisconnected` (value 1) on that node reports it. A listed peer
  that is also its bootstrap relay is still dialled. The setting also opens the blob
  mirror to internal addresses, for the peers in `NGIT_GRASP_P_MIRROR_PEER_URLS` only:
  the mirror has no other peers ("The blob mirror fetches from the operator's peers
  only").
- **The stricter address check** (seams 4 to 6, `mirror::vet_relay_dial`). Every
  connection of a GRASP-P node carries the flag `grasp_p_node` (`register_relay` sets it
  from `private_repos_enable`, and it is the only place a connection is built outside
  tests). It used to be the duplicate-forwarding flag, which is now a peer's alone, and
  the check would otherwise have gone with it from the connections that need it most.
  On such a connection, an event-directed target that upstream's policy passed is also
  put to `wraps_non_global`, on every dial and on both NIP-11 probes, in the dial worker
  and never under the manager's lock. It applies to every event-directed relay of the
  node and not to peers alone: the relays that customers' events name are the ones an
  attacker chooses. What it adds to upstream's check is a NAT64 (`64:ff9b::/96`) or 6to4
  (`2002::/16`) address that wraps an address upstream would refuse bare (the mirror's
  own list first, then upstream's `is_globally_reachable` on the wrapped address, which
  knows more ranges), and the local-use NAT64 prefix `64:ff9b:1::/48`, refused whole
  because it is never global. A public relay that is reachable only through such an
  address is not dialled by a GRASP-P node: each attempt fails with `Outbound target
  policy rejected relay`, the relay backs off like any failing relay, and its NIP-11
  probe returns default hints. None should exist: both prefixes are for reaching IPv4
  hosts, and a public relay has a public IPv4 address to be wrapped. Left alone: the
  bootstrap relay (upstream does not vet an operator's own target, and neither does
  this) and a connection with a permissive policy (no address is vetted, so there is
  nothing to check). The check is made on one DNS answer: the probe is held to it and
  the WebSocket dial resolves the name again (issue 3).

**What changed from the first version of this section.** It counted the relay in
`NGIT_SYNC_BOOTSTRAP_RELAY_URL` as a configured peer whether or not the list named it,
because a pair could then be wired through that setting alone. Under the rule above a
relay named there alone is no peer, and loses everything a peer gets: it is no longer
kept when its session ends, no longer exempt from the naughty-list mute, no longer
redialled every five minutes, no longer has an alias in the scrape, and, together with
every other relay outside the list, it is no longer sent the private filters, no longer
forwards duplicates, and may no longer bring GRASP-P events. Its dial policy does not
change: it never had one, as upstream's operator-configured target. A pair wired through
the bootstrap setting alone therefore replicates nothing now; list the peer.

What an operator sees is in `ops/runbook.md`, "Who a node replicates with",
"NgitSyncPeerDisconnected" and "A pair on a private network". At an upstream sync, each
seam is a line or two to carry over. If upstream keeps its own bootstrap relay through a
disconnect, redials it, or exempts operator-configured relays from the naughty list,
nothing here needs to follow, and the rows that pin upstream's rule fail to say so: the
retired rows of `configured_peer_survives_an_ended_session` and
`ended_session_retires_every_relay_with_grasp_p_off`, the control rows of
`failed_first_dial_of_the_bootstrap_relay_is_retried_only_when_listed`, and the bootstrap
row of `naughty_list_does_not_mute_a_configured_peer`.
If upstream starts to verify synced events itself, the source gate still goes directly
after that check. If upstream adds a path that admits relay-synced events without
`process_event_static_inner`, the gate does not see it: look for new calls of
`admit_event` and `save_accepted_event` in `src/sync/`.

Not done here: a peer that is taken out of the settings still needs a restart, as
before; a listed peer that upstream first opened as a NIP-65 discovery connection is
still subject to that connection's idle retirement and comes back through the tick; the
address check is not pinned to the connection (issue 3); a peer reached under a second
name (another host name, a path, another scheme) is no peer on that connection, and
GRASP-P events from it there are refused and counted; on the peer link the GRASP-P and
announcement filters still share one subscription budget; and no alert reads
`ngit_private_sync_foreign_source_total`. The fingerprint's domains and the startup line
`GRASP-P private repositories enabled` follow the list since v4 ("Policy fingerprint v4
and the event blacklist").

## Policy fingerprint v4 and the event blacklist

The maintainer's decisions D2 (the two nodes of a pair have two names, and every
registration lists both), D3 (only the operator's configured peers are sources of GRASP-P
data) and D9 (an account on `NGIT_EVENT_BLACKLIST` is frozen on both nodes) set what the
fingerprint covers and what the blacklist does on a GRASP-P node. All of it is in GRASP-P's
files: `src/grasp_p/mod.rs` (`policy_fingerprint`, `policy_preimage`, `fingerprint_domain`,
`PrivateService::write_blocked`, the wrap path, `verify_blossom_auth`, the startup line and
its two warnings), `src/grasp_p/state_root.rs`, `src/grasp_p/registration.rs` (`apply`),
`src/grasp_p/blacklist.rs`, and the watchdog's same-version text. No upstream code changes.
In `src/config.rs` the help text of `NGIT_EVENT_BLACKLIST`, upstream's setting, and of
`NGIT_GRASP_P_SYNC_PEER_URLS` gained sentences, as did the other three configuration
sources.

### The preimage

- **Domains.** v3 hashed the node's service address and the bootstrap relay. That matched
  only when each node bootstrapped to the other, and since the bootstrap relay is no peer
  unless the list names it ("Configured peers"), it said nothing about replication. v4
  hashes the service address and the configured sync peers, the set the sync code uses
  (`configured_peer_relay_keys`, so an entry that names this node is left out). Each member
  is first brought to the sync key (host in lower case, no default port, no trailing slash)
  and then written without its scheme (`fingerprint_domain`), so `NGIT_DOMAIN=Git.Example` and
  `wss://git.example/` in the peer's list are one name. With the scheme gone, `:80` and `:443`
  are both dropped: a `ws://` key has already lost `:80` and a `wss://` key `:443`, while the
  node's own address has no scheme to lose one by. A peer may be listed over `ws://`, though
  only under its own NGIT_DOMAIN, port and path: a pair that lists each other by private-link
  addresses never matches. Each node of a correctly paired pair lists the other, so both hash
  `{A, B}`; one list for both nodes works too. A list that leaves the other node out, names a
  third, or spells a node under a mount path without its path shows as a mismatch. The
  bootstrap relay is out of it, so a pair may bootstrap its public sync from any relay.
- **Blacklist.** The field `blacklist=` holds the keys on `NGIT_EVENT_BLACKLIST` as sorted
  lowercase hex (`blacklist::blacklisted_keys`). An entry counts only when it is exactly the
  npub of a key, the text upstream's check compares (`EventBlacklistConfig::check`): an
  nprofile, a hex key, an npub in capitals refuse nothing upstream and nothing here, and do
  not count. Order and repeats do not move the digest.
- **Deletion requests.** `deletion_request_disrespector=` is upstream's archival switch,
  `NGIT_DELETION_REQUEST_DISRESPECTOR`. It decides whether an honored kind 5 or 62 frees a
  registration's alias and keys (the `src/nostr/builder.rs` seam asks `actions_deletions`) and
  whether the tombstone gate refuses a deleted registration sent again. With it on one node
  only, an offboard frees the claims there and not on the other, and a later registration that
  reuses them is taken on one node and refused on the other. It had been missing from the
  preimage since v1.
- **Label.** `grasp-p-policy-v4`. It also marks the two rules that changed acceptance with no
  setting since v3, settled seats ("A settled seat is not displaced") and the deletion guard
  ("Who may delete"), so that a pair half on an older build reads as a version skew. No node
  runs v4 in a pair before the rest of M3 lands, so the knobs later M3 changes add join under
  v4; M4 takes v5.
- **Startup.** The line `GRASP-P private repositories enabled` now carries `policy_version`,
  `sync_peers` (the peer set, sorted) where it printed the bootstrap relay as
  `configured_peer`, and `event_blacklist_keys` (how many keys the list refuses). A node with
  GRASP-P on and no peer warns once when its blob mirror is on or a bootstrap relay is set:
  `NGIT_GRASP_P_SYNC_PEER_URLS names no peer of this node`. A node with neither is taken to
  stand alone on purpose.
- **What the published digest gives away.** The whitelist and the blacklist feed the hash
  and are never shown, but a reader who can guess every other input (the defaults, the two
  names) can test a guess of either list against the digest: whether one known account is
  listed, say. The whitelist has had that property since v1.

### The blacklist on GRASP-P writes

Upstream checks the list in `admit_event` (`check_event_blacklist`, `src/nostr/builder.rs`),
first, for events from clients and from sync alike: an event whose author's npub is on it is
refused with `blocked: Event author <npub> is blacklisted`, unless the node's own key signed
it. On a GRASP-P node that refused what the account key signs, its registrations, deletion
requests and vanish, and nothing its write and aux keys sign: state roots and stream wraps
were taken from a client and from the peer. The blob routes never read the list, not even
for a listed signer. An account the operator listed could therefore keep pushing.

`PrivateService::write_blocked(signer, account)` refuses a write when its signer is listed or
the account that holds the registration the write is made under is listed. It is asked in
four places, each once that registration is known, the first three once the write would
otherwise pass, so only a key of that repository learns of the block:

- `state_root::handle`, after the coordinate and write-key checks and before the replay
  check, so no edition of a frozen account counts as accepted;
- `try_handle_wrap`, after the key-claim lookup and the liveness check, for stored and
  ephemeral wraps, whether the write key or the aux key signs;
- `verify_blossom_auth`, after the write-key check: `HEAD /upload` (the preflight),
  `PUT /upload` and `DELETE /<sha256>`;
- `registration::apply`, for a live registration whose signer is a write or aux key that a
  registration holds, after the admission mode: a frozen account's key does not register an
  account of its own. In the same function a listed account's seat counts as settled
  whatever its age (`settle_clock`), so no registration displaces it, for its alias or its
  keys: an earlier-dated registration that lists its keys with valid proofs, which only its
  own keys can make, would otherwise evict it on both nodes within its first hour, free its
  keys under another account and strip its blob claims. A replay asks neither question, so a
  registration the node took before the list is seated again at a restart.

`GET`/`HEAD /<sha256>`, `GET /list` and REQs never ask, so the account's events and blobs
stay served and the customer can take them and leave; removing content stays the denylist's
job. Kinds 5 and 62 need nothing new: the account's own are refused upstream, and the
deletion guard already refuses those of its write and aux keys. An event is refused
`blocked: Account <npub> is blacklisted`, or in upstream's words when the signer itself is
listed; a blob route answers `403` with the same text in `X-Reason`. Neither contains
`unregistered`, the word the client widens on. Refused events count in
`ngit_private_events_rejected_total`; the blob refusals, like the other `403`s, are not
counted. For relay sync `blocked` is a final answer (`Rejected(Blocked)`), so the batch that
brought the event completes; it is no dependency rejection, so the sync hook keeps its id and
not the event, and the peer is not asked for it again until the hold's time to live runs
out. A node that lists the account refuses what its peer took, which is why the list is in
the fingerprint. It is read once at start: a change needs both nodes restarted with the same
list (a reload is M9's).

### What is left

- **The node's own key.** Upstream lets the relay owner's events pass the list; the GRASP-P
  check makes no such exception. Each node of a pair has its own owner key, so upstream's
  exception already differs between the two: a node whose list names its own key takes the
  registrations and deletion requests that key signs, and a peer with another key refuses
  them, with equal fingerprints. A list that names a node's own key is not meaningful; the
  node warns at start (`NGIT_EVENT_BLACKLIST names this node's own key`).
- **Writes in flight when the list arrives.** A write one node took before its restart with
  the list, and the other had not received yet, is refused there for good: `write_blocked`
  cannot tell a write made before the list from a backdated new one. The two nodes then serve
  different data, and an offboard that reached one node only leaves the other holding the
  claims. The runbook says to list an account only once the pair is in step.
- **A pair reached by link addresses.** The domain set compares a peer's entry with that
  peer's own `NGIT_DOMAIN`, so a pair that lists each other by private-link addresses while
  serving public names never matches. Matching it would need a setting that names the peer's
  service address; the maintainer decided on 2026-10-28 that no code is needed: each node
  lists its peer by the peer's `NGIT_DOMAIN` (PLAN.md, M8).
- **Events of other kinds** that tag a frozen registration are refused like any reference
  to private-repository content ("Nothing attaches to private-repository events"); one that
  names the frozen account's state root or wrap by an id this node does not hold yet is
  upstream's, as on any node.
- **The startup line's fields** (`sync_peers`, `policy_version`, `event_blacklist_keys`) and
  its two warnings are named in the runbook, but no test reads the log for them; only the
  predicate behind the peer warning is tested.
- **What was accepted before stays.** A registration in the meta store is kept at a restart
  (`boot_reconcile` asks no admission question of one it holds), and the blob mirror still
  fetches blobs that state roots accepted before the list reference: that is replication of
  what was accepted, and it keeps reads alike on both nodes.
- **The other node keeps asking.** A node that lists an account still names its alias and
  keys in the filters it sends its peer, and refuses what comes again once the hold's time to
  live has run out. When both nodes list it, nothing new reaches either.
- **A listed key in another account's registration** blocks that key's blob writes and,
  upstream, its events; the account's other keys write as before.

### Tests

Unit tests in `src/grasp_p/mod.rs`: `fingerprint_domains_are_the_service_and_its_sync_peers`
(a pair that lists each other, one shared list, spellings of a node, a private link, a mount
path, a one-sided list and a third node; it replaces
`fingerprint_is_symmetric_for_a_pair_under_a_base_path`), `fingerprint_ignores_the_bootstrap_relay`,
`fingerprint_covers_the_event_blacklist`, `fingerprint_covers_the_deletion_request_disrespector`,
`policy_version_is_v4_in_the_preimage_and_the_advert` and
`a_node_meant_for_a_pair_without_a_sync_peer_is_warned`; the first also pins written-out
default ports and a pair listed by link addresses. In `src/grasp_p/blacklist.rs`:
`blacklisted_keys_are_the_keys_upstream_refuses`, `write_refusal_names_the_listed_key` and
`a_listed_account_is_frozen_on_every_write_path`, which runs the real write policy over an
in-memory relay database, seats a registration as one accepted before the list, and sends
state roots and wraps from a client and from sync, blob authorizations, an earlier-dated
registration that claims the frozen keys, and registrations signed by them. Integration:
`exit42_blacklisted_account_is_frozen_and_stays_readable` in `private_repos` (a node
restarted with the list: reads answer, every write is refused, another account writes) and
`exit23_peer_refuses_a_synced_state_root_of_an_account_it_lists` in `private_two_node` (B
restarted with the list refuses a state root A took, while another account's replicates).

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
  through `crate::outbound::OutboundTargetPolicy::authorize_resolved`, then put every
  vetted address to our `wraps_non_global`, which also decodes the NAT64 and 6to4 forms
  that upstream's `is_globally_reachable` lets through (upstream already refuses every
  IPv4-compatible address). Production still
  requires https / wss. Listed GRASP-P peers register as event-directed targets, so
  upstream's dial-time policy applies to them too, unless the operator has declared the
  pair's link private ("Configured peers"). The mirror connects to the addresses its
  client's resolver vetted ("The blob mirror fetches from the operator's peers only");
  the relay dial is vetted and not pinned (M3 #3, the relay half).
- **Duplicate forwarding.** Legacy made `RelayConnection` forward events nostr-sdk reports
  as already seen, unconditionally. It is now behind `with_duplicate_event_forwarding`, set
  only on the connection to a configured peer, so a public node's sync is unchanged and so
  is every other connection of a GRASP-P node ("Configured peers"). The SDK sends a new
  event twice (as `Event`, then inside `Message`); only the copy it did not also deliver as
  `Event` is forwarded. A new GRASP-P event that is rejected and held is therefore not
  accounted for by its second copy; the negentropy completion check counts the ids
  GRASP-P holds or refused as delivered instead (`grasp_p_settled_ids`), so a batch that
  contains one completes in its first round.
- **Hold expiry.** Legacy expired held GRASP-P events inside upstream's rejected-index
  cleanup and shortened that cleanup's interval under `NGIT_TEST=1`. The expiry now runs on
  GRASP-P's own registration timer and upstream's cleanup is untouched.
- **The out-of-order hold.** An event can reach a node before what it depends on: a state
  root before its registration, a stream wrap before the registration that lists its key.
  It is rejected, kept in memory (`PrivateRejectedIndex`, `src/sync/private_index.rs`) and
  tried again when the registration is accepted. No upstream file changed for the rules
  below, apart from the counter, which is one more additive `ngit_private_*` series and
  recorder in `src/metrics/mod.rs`; the sync manager still calls the same three hooks (`grasp_p_previously_rejected`,
  `grasp_p_after_saved`, `grasp_p_after_rejected`) and the negentropy exclusion.
  - **Size first.** `grasp_p::admission::admit` compares the serialized event with
    `NGIT_GRASP_P_MAX_EVENT_BYTES` before the rate bucket and before any lookup, for
    30640, 30641 and every stream-wrap kind, from clients and from sync alike. A synced
    event is otherwise bounded only by the transport's 5 MB message, and an event that
    large can never be accepted, so it is never held.
  - **One decision.** `PrivateService::note_rejected(event, message, synced)` is the only
    code that puts a rejection into the index. The client path reaches it from
    `admission::admit`; the sync path reaches it from `grasp_p_after_rejected`, which also
    sees events refused before admission (blacklist, deletion gate). A full hold is given
    only to a dependency rejection, one a later registration can turn into an acceptance:
    for a 30641 `unregistered alias`, `event author is not a registered write key for this
    alias`, `state root a tag does not match the live registration` and `alias registration
    changed; retry`; for a stored stream wrap `unregistered key` and `registration changed;
    retry`; for a 30640 the cadence rejection, which time cures. Each of these strings is a
    constant in `src/grasp_p/admission.rs` (the cadence one in `registration.rs`), used
    where the rejection is produced and where it is classified, and matched whole.
    Any other rejection keeps only the event id on the sync path, so the node does not
    fetch and validate the same event on every delivery, and keeps nothing on the client
    path. **Rewording one of those messages, or adding a rejection that a registration
    can cure without adding it to `is_dependency_rejection`, silently stops the hold for
    it**: replicated events that arrive early are then not retried from memory and wait for
    a re-issue of the sync filters, at the latest the next full one.
    The table test `admission::tests::only_dependency_rejections_are_holdable` and
    `grasp_p::tests::dependency_rejections_are_held_on_both_paths` are the guard.
  - **Bounds.** At most 4096 held events, of which at most 1024 registrations; a byte
    budget of 32 MiB, or 64 times `NGIT_GRASP_P_MAX_EVENT_BYTES` when that is more, of
    which registrations may use a quarter; at most 65,536 remembered ids, 4096 of them
    reserved for the ids of held events. An event that would exceed the count or the bytes
    is dropped without entering the skip-set, so it can be fetched again, and what is
    already held is untouched. A full skip-set refuses new ids and evicts none: the entries
    it has keep their full TTL, and the cost is that some rejected events are validated
    again. The charge is the serialized size plus the fixed memory cost of each tag and tag
    element, so an event built from many tiny tags is charged for the memory it takes; the
    budget is therefore room for about 64 events of the largest size, fewer when they are
    tag-dense.
  - **No setting, and nothing in `policy_fingerprint`.** The budget is derived from the
    event size limit. None of this changes which events a node finally accepts, only
    whether an early event is retried from memory or fetched again from the peer (a client's
    own early event, when it is not kept, must be published again), so two nodes of a pair cannot disagree about a repository because of it and
    the fingerprint has nothing to cover.
  - **Counter.** `ngit_private_hold_dropped_total{reason}` with `count_cap`, `byte_budget`,
    `not_holdable` and `skip_set_full`. No label carries a tenant, an alias or a key.
- **Peers.** A listed peer is registered and dialled when it is missing from the sync
  index, and retried once a minute (and reported once) while it cannot be registered at
  all. From then on it is never dropped: see "Configured peers".
- **Advertised URLs.** NIP-11 `blob_endpoints` and the blob descriptors are built from
  `Config::service_address()`, so they carry `NGIT_BASE_PATH`. The check that a
  registration names this node compares the same address, path included (see "Under a
  base path the node is its host and its path").
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
  ceiling. For the GRASP-P kinds `NGIT_GRASP_P_MAX_EVENT_BYTES` is checked first on the sync
  path too (see "The out-of-order hold" above); synced events of every other kind are
  bounded only by the SDK's 5 MB message limit.
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

## Upstream syncs

- **v3.0.7 -> v3.0.8 (2026-10-25), by merge.** Only `Cargo.lock` conflicted: v3.0.8's lock plus
  `cargo update --workspace`, which re-adds exactly the edges above and no package. Every seam
  survived the auto-merge (`src/http/mod.rs`, `Cargo.toml`, `nix/module.nix` checked by hand).
  Upstream moved to `bitcoin_hashes` 1.2, where `hash`, `engine`, `from_engine` and the byte-array
  methods are inherent; its `85cd03a` dropped the `Hash` trait imports in its own files, and the
  sync does the same in ours (`src/grasp_p/`, the watchdog, four tests). `tokio-tungstenite` 0.30
  needed no change. Upstream's `9c31db9` makes the persisted-startup REQ test pre-seed its relay,
  which fixes that test on slow CI hosts (it failed every run on alpha's idle-priority runner).
  Upstream's `f1c867e` passes the retained-history exclusions on argv, so the `rev-list --stdin`
  need below is gone; it supersedes our unmerged branch `sovtech/git-2.39-compat`.

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
  Since v3.0.8 (`f1c867e`) upstream no longer needs `--stdin` exclusions, so the 2.42 reason is
  upstream's past; the 2.41 one (empty-repository capabilities) has not been re-measured. The
  check keeps 2.42 until it is; lowering it is a separate change.
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
  constructors `TestRelay::start_with_grasp_p`, `start_with_grasp_p_at_base_path` and
  `start_grasp_p_pair_node` in `tests/common/relay.rs` (upstream's file, with those
  constructors, the `extra_env` option and the two metrics accessors added). They all set
  `NGIT_GRASP_P_METRICS_BIND=127.0.0.1:0`, so a node they start has a metrics endpoint on a
  port the kernel picks unless the test overrides the setting or switches GRASP-P off, and the
  suites read metrics through `TestRelay::grasp_p_metrics`, which finds the port in the node's
  log and panics unless the answer is a 200. Upstream's `fetch_metrics` returns the body of any
  status, and several assertions read a missing series as 0, so on the public port of a GRASP-P
  node they would pass on a 404 page. One use of it is left, in `exit4_disabled_is_noop` of
  `private_two_node`: that node runs with GRASP-P off and serves upstream's `/metrics`.
  `phase0_gates` runs the stock relay (`TestRelay::start`, `start_with_lmdb`) with GRASP-P off:
  it checks what GRASP-P needs from upstream. In the pair tests the peer is listed as sync
  peer and as blob peer and is also the bootstrap relay (`start_grasp_p_pair_node` sets all
  three from the one URL), except `exit14`, `exit16` and
  `exit17_restarted_listed_peer_is_kept_and_redialled` (listed only; `exit16` lists the blob
  peer too, the others need no mirror), `exit18` (bootstrap relay only, which is no peer of
  either kind) and `exit19` (A lists no relay and has no bootstrap relay; B has A as all
  three) in `private_two_node`; `exit11`, `exit15` and `grasp_p_tls` give a blob peer of
  their own, which replaces the fixture's; and both SSRF guards are switched
  off (`NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS=true` and upstream's
  `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS=true`), because the nodes are on loopback. `exit16` is
  the exception to the second: it leaves upstream's guard on. No test runs a pair with GRASP-P's
  own guard on, because that needs peers on public addresses.
- Configured peers ("Configured peers: the only relays GRASP-P syncs with ..."). Unit tests
  in `src/sync/grasp_p_sync.rs` build a real sync manager, its relay and its GRASP-P
  service from one configuration, as at startup; its dial workers get no slot, so a
  scheduled dial stays queued until the test reports its outcome, and nothing opens a
  socket. Time is passed in: the health tracker reads the system clock, which a paused
  runtime does not move. The set: `the_peer_set_is_the_list_alone` (the list, in any
  spelling of a key, never this node, never a bootstrap relay the list leaves out,
  nothing with GRASP-P off). Egress: `grasp_p_filters_go_only_to_configured_peers`,
  `complete_live_filters_carry_grasp_p_only_for_a_peer` (fails without seam 9) and
  `reissue_targets_only_live_configured_peers` (the set, and a re-issue sent to it alone).
  Ingress: `grasp_p_event_from_a_non_peer_is_refused_before_admission_and_not_held`
  (blocked, not held, not stored; the peer's copy is admitted and held; fails without
  seam 11) and `only_relay_sync_of_a_grasp_p_kind_from_a_non_peer_is_gated` (every
  GRASP-P kind, stored, ephemeral and legacy, is refused; hold reprocessing, a client's
  path, a public kind and GRASP-P off pass); in `src/grasp_p/mod.rs`,
  `admits_kind_is_every_kind_admission_claims` (the gate's kinds, legacy on and off) and
  `a_foreign_sync_source_is_reported_once_within_a_bound` (one warning per relay, at most
  1024 relays). `only_a_peer_connection_forwards_duplicates`
  (and that the address check is on every connection; fails without seam 10).
  `negentropy_batch_counts_a_held_grasp_p_event_as_delivered` (one round, nothing left for
  recovery; fails without seam 12). The lifecycle: `configured_peer_survives_an_ended_session`
  (a listed peer, and one that is also the bootstrap relay, are kept with their connection
  and a counted failure; a bootstrap relay the list leaves out and another relay are
  retired) and `ended_session_retires_every_relay_with_grasp_p_off`;
  `disconnected_configured_peer_survives_the_disconnect_check` and
  `connected_peer_is_not_an_empty_relay_disconnect_candidate` (the `check_disconnects`
  path, disconnected and live); `failed_first_dial_of_the_bootstrap_relay_is_retried_only_when_listed`
  (with control rows that pin upstream's behaviour); `naughty_list_does_not_mute_a_configured_peer`
  (the entry is recorded, upstream's loop skips the peer, the redial dials it, another
  relay and a bootstrap relay the list leaves out stay muted); `peer_redial_admits_one_dial_per_interval`
  (the rule alone) and `disconnected_peer_is_redialled_once_per_interval` (on the manager,
  including a dial already queued); `only_a_configured_peer_on_a_private_link_gets_a_permissive_policy`.
  The set itself has `peer_keys_are_sync_keys_once_each_in_list_order` in
  `src/sync/private_index.rs` and `sync_peer_set_is_canonical_and_excludes_own_address` in
  `src/grasp_p/mod.rs`, and the scrape `aliases_exist_for_exactly_the_relays_sync_treats_as_peers`
  and `the_bootstrap_relay_is_a_peer_only_when_listed` in `src/grasp_p/relay_labels.rs`.
  `relay_dial_check_refuses_wrapped_internal_addresses` in `src/grasp_p/mirror.rs` and
  `grasp_p_dial_refuses_a_nat64_wrapped_internal_address` in `src/sync/relay_connection.rs`
  cover the address check, on IP literals, with no lookup and no connection. In
  `private_two_node`: `exit16_pair_replicates_with_the_upstream_guard_on` runs a pair on
  loopback wired through the peer lists alone, with `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS` unset
  and `NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS=true`: events and a blob replicate, and a
  loopback relay that a public announcement names is refused without a connection. It fails
  without seam 3. `exit17_restarted_listed_peer_is_kept_and_redialled` and
  `exit17_restarted_peer_that_is_also_the_bootstrap_relay_is_kept_and_redialled` kill one
  node and start it again on the same address: the other must log the disconnect as one to
  recover from, never retire the peer, dial it again and replicate from it. They fail
  without seam 1. `exit18_bootstrap_relay_that_is_not_a_peer_carries_no_grasp_p_sync`
  wires a node through the bootstrap setting alone: a public announcement crosses, no
  registration does, before or after the connection opened, and the scrape names no
  relay. It fails when the bootstrap relay counts as a peer again, in the set or in the
  aliases. Egress and ingress each stop the registration on their own, so it fails only
  when both go; each has its own unit tests above.
  `exit19_connect_time_sync_replicates_with_the_full_reissue_off` starts a node after its
  peer holds a registration and a state root, with the periodic re-issue off: both must
  arrive. It is the one test that fails without seam 7. Seam 8 alone has
  no test that fails without it: it runs on a quick reconnect and a consolidation, and
  the re-issue covers both in every pair test. `grasp_p_tls` requires a second dial of the
  `wss://` peer after its naughty-list entry, which fails without seam 2 or without the
  redial. No test waits out the 300 seconds, runs a peer down for hours, or resolves a
  name to a NAT64 address, and no integration test has a relay send GRASP-P events it was
  not asked for: the gate is covered by the unit tests.
- Who may delete ("Who may delete"). Unit tests in `src/grasp_p/offboard.rs` build a node's
  write policy and stores as the server does, over an in-memory relay database, and send each
  request both to the guard alone and through `admit_event`:
  `member_keys_cannot_delete_or_vanish` (a live write key and aux key, whatever they name;
  nothing is removed or blocked),
  `a_member_key_names_nothing_beside_its_own_registration_coordinate` (beside a coordinate
  under its own key, an id the node does not hold, its own public note and a public
  repository are refused; the coordinate alone passes and changes nothing),
  `dropped_keys_cannot_delete_what_they_signed` (state root and wraps of both stored kinds by
  id, every coordinate form of their kinds, the vanishes),
  `the_account_deletes_its_repository_by_the_registration_coordinate` (every malformed
  offboard request refused; the accepted one frees the keys and leaves the state root and
  the wrap), `an_offboard_request_by_coordinate_alone_passes`,
  `a_registration_is_deleted_only_by_its_own_account`,
  `an_own_registration_named_by_id_needs_its_own_coordinate` (by id without the k tag, and
  beside another of the account's coordinates),
  `requests_that_touch_no_grasp_p_key_or_event_are_upstreams` (a public repository among
  them), `the_account_vanishes_and_a_member_key_does_not`,
  `too_many_targets_are_refused_first`, `a_refused_synced_request_is_remembered_by_id` and
  `other_kinds_are_not_judged`. The gate:
  `the_gate_exemption_is_state_roots_and_stream_wraps_only` (also on a node that refuses the
  legacy kinds, and the cascade and removal exemptions), and two that fail without the seam,
  `a_vanish_sent_before_registration_does_not_block_the_key` and
  `tombstones_recorded_earlier_block_no_state_root_or_wrap`. Upstream's deletion paths:
  `a_public_cascade_takes_no_registration_state_root_or_wrap` (an outsider's note bridges
  its public repository to a registration, its state root and its wrap; the repository's
  deletion and the outsider's vanish each remove the note and nothing private), and
  `upstream_removes_no_state_root_or_wrap_however_a_request_got_in` (a deletion request and a
  vanish handed to upstream's deletion service directly, past the guard).
  `with_grasp_p_off_upstream_decides_alone` fails if the gate seam or the guard acts with
  GRASP-P off. The filters:
  `private_deletion_filters_ask_for_offboard_requests_and_account_vanishes` and
  `deletion_filters_go_only_to_configured_peers` in `src/sync/grasp_p_sync.rs` (the peer
  set, the index-change set and upstream's live coverage builder),
  `tenants_are_each_account_once_in_order` and the account case of `test_replace_all_diff`
  in `src/sync/private_index.rs`. In `private_two_node`,
  `exit22_offboard_request_reaches_the_peer_and_a_write_key_cannot_delete`: a write key's
  deletion of its state root is refused on both nodes; the account's offboard request, sent
  to A only, reaches B, where the registration is then no longer live; and a second
  account's vanish, sent to A only, reaches B through the vanish filter B adds when its
  index changes, and B stops serving that registration. In `private_repos`, `exit10` now
  has an e-only deletion of a registration and another account's deletion refused, the
  latter checked against a key the tenant still holds. No test makes a store fail, and none
  reaches the `e`-id branch of `free_claims_for_deleted_registrations` any more: an
  accepted offboard request names the coordinate, which frees the claims first.
- The blob routes ("What the blob routes answer"). Unit tests carry the rules, without a
  server: in `src/http/blossom.rs` the headers of every error, of a served blob and of its
  `304`, the `If-None-Match` matching, and the order denylist, existence, conditional
  (`conditional_answer_comes_after_denylist_and_existence`); in
  `src/grasp_p/blossom_auth.rs` the window and the `server` tag for each operation,
  including that a refused list has one reason whatever failed; in
  `src/grasp_p/blob_store.rs` the stored time and the temp sweep (with symlinks and a
  subdirectory); in `src/grasp_p/denylist.rs` the seeded reload, with a file that became
  unreadable and one that stopped parsing, and the unchanged meaning of a missing file;
  in `src/grasp_p/meta.rs` that a claim without the new field still reads. In
  `private_repos`, `exit5` checks the challenge on each `401` and its absence on `403`,
  `400` and `200`, and an authorization for another server; `exit29` checks the headers
  of a served blob, the `304`, and that a conditional request for a denylisted or absent
  hash is never a `304`; `exit30` revalidates one blob before and after its takedown;
  `exit40` checks `uploaded` in the descriptor, in the list and on a repeat upload, and
  that a list without a `server` tag, or with another server's, is the same `401`. The
  list helper of that suite now takes the node's domain, because a list needs the tag.
- Upload slots and the body timeout ("Upload slots and the body timeout"). Unit tests in
  `src/grasp_p/mod.rs` drive `reserve_inflight` without a server: the cap per account and
  its `429`, the node cap and its `503` and which of the two answers first, `0` turning
  the cap per account off, the mirror passing a full node while still bound by the byte
  budget, and the map of accounts being empty after every reservation is dropped, in any
  order and through a panic; one more builds the service and checks the default of 8 and
  the cap of 64 through `reserve_upload`. In `src/http/blossom.rs`, under paused time, a
  silent body is cut after the idle time, a body that sends a byte every ten seconds is
  cut at the total deadline and never without one, and the deadline is computed from the
  declared length (`0` = none, and an absurd length does not panic); the headers of the
  three new answers are checked beside the other errors. In `private_repos`, `exit41`
  runs a real node: a second upload of an account whose one slot is held gets the `429`,
  another account uploads meanwhile, the held upload is cut with `408` once it stops
  sending, and the account then uploads again. No integration test fills the 64 slots
  of the node; the `503` is covered by the unit tests only.
- The blob mirror ("The blob mirror: one queue per account ..."). Unit tests in
  `src/grasp_p/mirror.rs`, without a server: the queue serves accounts in turn, holds an
  account at its share, keeps a hash once and bounds a backlog; the budget gives a
  burst, then the rate, and `0` is no limit; every failure reason has one of two
  schedules and none leaves a blob ungated; the recorded reason does not depend on peer
  order; the peer's length is believed up to the maximum; the deadline grows with the length;
  a shared blob goes to the account with the least backlog, with the other accounts as
  fallbacks and the alias that holds the charge first; a waiting blob moves to the
  account the scan chose; a name that does not resolve is not a refusal; the scan
  forgets the gates of blobs that arrived. Six more run the real worker loop against a fake node with
  time paused: a second account is served while the first holds its share with slow
  fetches, a failing blob is fetched again until it arrives, the budget holds fetches
  back and then lets every one through, scans and jobs are taken while every slot is
  held, what a full backlog dropped comes back with the next scan, and a fetch that
  panics frees its slot. `grasp_p_mirror_attempt_budget_default_and_env_override` in
  `src/config.rs` covers the setting. In `private_two_node`,
  `exit15_one_tenants_backlog_does_not_starve_another` runs a pair with a blob peer that
  answers forty blobs of one account slowly: a second account's blob must arrive within
  seconds while the first account is still behind. `fetch_from_peer` itself (the order
  of its steps, the limits on the body) and the fall-through from one claimant to the
  next in `fetch_blob` have no unit test; `exit1`, `exit3`, `exit5`,
  `exit9`, `exit11` and `grasp_p_tls` run it end to end.
- Registration ("Registration: cheap checks first ..."). Unit tests in
  `src/grasp_p/registration.rs` drive the handler against a real meta store. None counts
  signature checks: each gives a registration a proof that cannot verify and requires the
  refusal of an earlier step, which could not come back if a proof had been verified
  first. They cover the key cap before any proof; every shape refusal before any proof;
  the whitelist and proof of work before any proof; a refused sender that would have
  lost or won a conflict getting the mode's message with nothing pruned and no alert
  recorded, next to a listed sender that still gets the conflict answer; an account off
  the list replacing the registration it holds and being refused a new alias; the write
  transaction refusing by itself when the early check is left out (`apply` called
  directly); the boot replay keeping the conflict checks ahead of the mode; and a node
  under a base path refusing the bare host and another path while accepting a
  registration for a pair. `src/grasp_p/host.rs` has the service comparison (root, mount
  path, trailing slash, other path, other host, port), `src/grasp_p/mirror.rs`,
  `src/sync/private_index.rs` and `src/grasp_p/relay_labels.rs` each have one test of
  their own use of it, and the watchdog has `derive_blob_base_follows_the_relay_mount_path`.
  In `private_repos`, `base_path_registration_and_blob_routes` starts a node under
  `/grasp`: the advert carries the path, a registration naming the bare host or another
  path is refused, one naming the mounted URL is accepted, a blob is uploaded and read
  back under the path, and the same request outside the path is a 404.
  `exit11_registration_conflict_merge` has its late challenger on the whitelist now (it
  tests the conflict, and an unlisted sender no longer reaches it), and a new step
  checks that an unlisted challenger gets the whitelist answer and leaves the conflict
  counter where it was. No pair test runs under a base path.
- Settled seats ("A settled seat is not displaced"). Unit tests in
  `src/grasp_p/registration.rs`; except where named, they pass the node's clock in, so
  their dates are free and the result does not depend on when they run.
  `seat_settles_one_second_after_an_hour` (the boundary, the first edition's age, a seat
  dated after the clock) and `a_settled_seat_turns_only_a_win_into_a_refusal` (an
  order loss is never put down to the settle rule; no clock, no settling) are pure.
  `settled_seat_keeps_its_alias_against_a_backdated_claim` and
  `settled_seat_keeps_its_keys_against_a_backdated_member` (a write key and a shared aux
  key, each claimed under an alias of the claimant's own) require the ordinary conflict
  answer, the prune of the challenger's coordinate, `incumbent_settled=true` and the
  challenger's key in the warning, and the holder's record, key claims, ring and blob
  claim untouched. `settled_squat_refuses_a_widen_without_pruning_the_victim` refuses a
  holder's own widen that claims a key a settled seat holds, and prunes nothing, since the
  holder's coordinate still holds its live registration.
  `a_settled_key_holder_refuses_a_claim_that_would_take_a_young_alias` refuses outright a
  registration that would take a young alias but also claims a settled seat's key, and
  evicts neither holder. `a_stale_own_edition_is_not_refused_by_a_settled_seat` sends a
  holder's first edition again after a key it listed has passed to another account whose
  seat has settled: it is accepted as a no-op with no conflict warning, on a node that saw
  it and on one that did not, where it still lowers the anchor to its own date.
  `young_seat_still_merges_by_created_at` decides at an hour exactly: the earlier claim
  ends up holding the seat in either arrival order (it evicts the holder, or the holder is
  refused), a member's aux-key claim evicts a young repository, and an order loss logs
  `incumbent_settled=false`.
  `handle_judges_seat_age_by_the_node_clock` goes through `handle` with the real clock.
  `replay_reaches_the_decision_made_while_the_seat_was_young` lets a claim win while the
  seat is minutes old, leaves the evicted holder's event in the relay database, and then,
  with both dates decades old, requires the winner after `boot_reconcile` over the same meta
  store, after a rebuild into an empty one (newest event first, the case a clock would get
  wrong) and after replays by hand in both orders. Eight older tests that date their
  seats in 1970 now decide those conflicts at a clock under an hour after the dates
  (`WHILE_YOUNG`): five expect an earlier claim to win and would see it refused at the
  real clock (`eviction_cleans_loser_footprint`, the two `stale_record_*` tests,
  `same_tenant_replacement_cadence`, `key_conflict_winning_replacement_exempt_from_cadence`);
  two would still pass but no longer catch the fault they are about, since the settle rule
  would refuse their squatter whatever the anchor said
  (`same_tenant_replacement_preserves_anchor`, `stale_same_tenant_edition_lowers_anchor`);
  and in `unlisted_sender_takes_part_in_no_conflict` the refused sender has to be one that
  would otherwise win. `write_transaction_refuses_without_the_early_check` only passes the
  clock to `apply`, which now takes it. The integration suites give a seat they expect to
  lose a first edition at most 600 seconds older than the start of the test (`exit15` and
  `exit22` in `private_repos`; the backdated claims of `exit8` in `private_two_node`, 650
  seconds back, are winners), so none of them reaches the settle age.
  `exit21_settled_seat_is_kept_on_both_nodes` in `private_two_node` exercises the rule on a
  pair without waiting: a seat dated two hours back is settled on arrival, reaches B through
  sync, and a claim dated before it is refused by both nodes with the conflict answer, by B
  against the seat sync delivered, while both keep serving the holder's registration
  alone. The log capture of the unit tests installs, once per test binary, a global
  subscriber that takes every warning and discards it: without one, a warning first reached on another test's
  thread while a capture is the only subscriber is cached by tracing-core as unwanted, and
  the capture misses its own line.
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
  under "The NIP-11 probe is vetted, pinned and bounded here",
  `grasp_p_dial_refuses_a_nat64_wrapped_internal_address` in `src/sync/relay_connection.rs`
  (it needs that file's private fields), and fixed commit dates in
  the git helper of `src/git/staging/tests.rs`: one upstream test there builds the same
  commit twice and compares the ids, which only match within one wall-clock second.
