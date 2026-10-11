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
| `src/server.rs` | spawns GC, mirror and denylist reload (`grasp_p::spawn_background_tasks`); passes the service to HTTP; one call to `git::version::ensure_supported` before the storage migration, fatal only when GRASP-P is enabled; one call to `grasp_p::metrics_endpoint::start` ahead of every other background task, whose error stops startup; where `Metrics` is built, the builder call `with_relay_labels(RelayLabels::from_config(..))`, which passes `None` unless GRASP-P is enabled (see below) |
| `src/git/mod.rs` | declares `version` |
| `src/main.rs` | the `version` attribute of `Cli` and of its `Serve` variant, both `grasp_p::build_info::version()` (`Config` sets upstream's version on that subcommand, and a subcommand's own version wins over the propagated one) |
| `src/http/mod.rs` | `HttpService.grasp_p`; widened CORS on OPTIONS; blob routes matched on the base-path-stripped path (`blossom::match_route`) just before NIP-11; one condition on the `/metrics` route, which a node with GRASP-P enabled does not serve (see below) |
| `src/config.rs` | `NGIT_GRASP_P_*` settings and their validation, including the GRASP-08 exclusion |
| `src/sync/mod.rs` | declares `grasp_p_sync` and `private_index`; `grasp_p` state field; GRASP-P filters added to `sync_generic_filters`, `sync_generic_history` and `complete_live_filters`; `register_relay` builds each connection with `with_duplicate_event_forwarding`; timer spawn; previously-rejected skip; after-saved / after-rejected hooks in `process_event_static_inner`; peers kept in `check_disconnects` and counted as desired in `retry_disconnected_relays`; the service handed to both `HistoryJob`s (`historic_sync_with_options`, `spawn_history_queries`); the id and signature check in `process_event_static_inner` (see below) |
| `src/sync/history.rs` | negentropy also skips known-rejected GRASP-P ids |
| `src/sync/relay_connection.rs` | forwards SDK-deduplicated events, only when GRASP-P is enabled, after checking their id and signature and skipping the SDK's second copy of a new event; `fetch_events` drops fetched events whose id or signature does not verify; the NIP-11 probe (`fetch_limit_hints`, `preflight_limit_hints`, and the helpers `vet_nip11_target`, `VettedAddresses`, `nip11_client`, `read_limited_body`, `fetch_nip11_document`) follows no redirect, uses no proxy, reads at most 256 KiB and, for an event-directed target, is vetted on every call and connects only to the vetted addresses (see below) |
| `src/sync/filters.rs`, `src/http/nip11.rs`, `src/nostr/lifecycle/deletion/service.rs`, `src/lib.rs` | additive helpers |
| `src/metrics/mod.rs` | additive helpers (the `ngit_private_*` series and their recorders); the field `Metrics::relay_labels`, its builder `with_relay_labels`, and one statement in `render` between `REGISTRY.gather()` and the encoder, which rewrites the relay labels when the field is set (see below) |
| `Cargo.toml` | direct dependencies `heed` (with its `serde` features), `parking_lot`, `uuid`, `url`, `secp256k1`; the `ngit-private-watchdog` binary target; for the TLS test, the dev-dependencies `openssl` and `tokio-rustls` |
| `tests/common/relay.rs` | the `extra_env` option and the constructors `start_with_grasp_p` / `start_grasp_p_pair_node`, which both set `NGIT_GRASP_P_METRICS_BIND=127.0.0.1:0` ahead of `extra_env`; the accessors `grasp_p_metrics` and `grasp_p_metrics_address` |
| `.env.example`, `docs/reference/configuration.md`, `nix/module.nix` | the `NGIT_GRASP_P_*` settings (the other three config sources) |
| `.gitignore`, `docs/how-to/prometheus-setup.md` | ignores for key files; a pointer to the GRASP-P alert rules and to the address a GRASP-P node is scraped on |

With `NGIT_GRASP_P_REPOS_ENABLE` unset no service is built, and the admission arms, blob
routes, sync filters, timers, duplicate forwarding, the metrics endpoint and the rewrite of
relay labels are all gated on it, and `/metrics` is upstream's public route with upstream's
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
  order, and then the relay in `NGIT_SYNC_BOOTSTRAP_RELAY_URL`, unless the list already
  names it. The bootstrap relay is one of them because a pair can be wired through it
  alone: upstream dials it at startup, it is sent the private filters, and
  `policy_fingerprint` takes the pair's other node from it. If only the list counted,
  the peer of such a node would be dropped from its scrape and `NgitSyncPeerDisconnected`
  would have nothing to read. Both settings are the operator's, so an alias tells nothing
  a customer chose. Relays configured for another purpose (the user index, the Sync+
  fallbacks) get no alias, which keeps the peer alert about the pair. On a pair the one
  peer is `peer-1` on both nodes, whichever setting names it. A peer named by the
  bootstrap setting alone is dialled at startup and not again after its session ends; the
  missing-series half of the alert is what reports that.
- **Each setting is read the way the sync code reads it**: a list entry through
  `normalize_relay_url`, the own-address exclusion of `configured_peer_relay_urls` and
  `canonical_relay_key`; the bootstrap URL through `canonical_relay_key` alone. The label
  upstream writes is that key, and it is compared as it stands. A key has one alias, so
  two series of one family cannot end up with the same labels; a label in any other
  spelling is dropped, never folded in. The unit test
  `aliases_exist_for_exactly_the_relays_sync_dials_as_peers` holds the two readings
  together.
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
the other tests drive are kept by hand. No test runs a pair wired through the bootstrap
relay alone; the unit test `the_bootstrap_relay_is_a_peer_when_no_list_names_it` covers
that mapping.

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
  this node" is the configured domain (`NGIT_DOMAIN`), compared by `host::url_denotes_domain`
  like every other such check: the host without regard to case or a trailing dot, and the
  port when the domain has one. The tag is a bare domain, so the mount path of a node under
  `NGIT_BASE_PATH` is not compared. A refused `GET /list` is still the one identical `401`,
  whichever check failed.
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
  reserves the bytes it expects to read (a configured peer's announced length, otherwise
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
  that does not resolve is `network`, not `blocked`: the address guard connects to
  neither, but a resolver that fails for a moment must not park every blob tried
  meanwhile for the maximum interval. The two are told apart by how the outbound
  policy's error begins (`POLICY_DNS_ERROR_PREFIX`); a unit test fails if upstream
  rewords it. The cost of gating every class is slower recovery: a blob refused with
  `quota` used to be fetched within a minute of space being freed and now waits out its
  backoff, about `NGIT_GRASP_P_MIRROR_RETRY_MAX_SECS` at most. A restart clears every
  gate.
- **Which reason is recorded.** A failure from this node's own state (`quota`, `reserve`,
  `sink`, `write`, `store`) ends the peer loop. Otherwise every peer is tried and the
  class that retries soonest wins, whatever the order of the peers.
- **Order within one fetch.** Address guard, quota preflight against local state,
  request, status, length, byte reservation, temp file, body. A blob the account has no
  room for costs no request, and a wrong length costs no body.
- **Whose length is believed.** A peer from `NGIT_GRASP_P_MIRROR_PEER_URLS` is believed
  up to `NGIT_GRASP_P_MAX_BLOB_BYTES`, so a blob declared with the wrong size is now
  mirrored and charged at its real size, where it used to fail for ever: the replica
  matches the origin. A peer that only a registration's `server` tag names must announce
  exactly the declared size, or the fetch fails as `verify` before the body. With no
  announced length the declared size bounds the read. Both kinds of peer exist until
  mirroring is restricted to the operator's list; the second rule goes away with it.
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
- **Still open.** Each attempt resolves the peer's name again (a cached verdict belongs
  with pinning the resolved address, issue 3). There is no metric for fetches held back
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
  order; the four cases of whose length is believed; the deadline grows with the length;
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
