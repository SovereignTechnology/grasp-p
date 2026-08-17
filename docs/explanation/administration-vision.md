# Administration, Private Analytics, and Runtime Configuration Vision

**Status:** Proposed direction; not yet implemented

**Related:** [Architecture](architecture.md),
[GRASP-08 private services](grasp-08-private-service.md),
[Monitoring](monitoring.md), and
[Configuration reference](../reference/configuration.md)

## Vision

ngit-grasp should be straightforward to operate without requiring every
operator to edit environment files or maintain a separate monitoring stack.
At the same time, declarative deployments must remain authoritative and
predictable.

The service will provide a Nostr-authenticated HTTP management API and an
embedded static web application that uses it. The API will implement the
standard NIP-86 methods that fit ngit-grasp and advertise a longer tail of
namespaced GRASP and ngit-grasp extensions. It will return private operational
information to an authenticated caller as well as accept authorized actions.

The intended operator experience is:

- a hobbyist can start one binary, open `/admin/`, authenticate with a Nostr
  signer, inspect the service, and configure settings that were not fixed by
  the launch environment;
- a NixOS, container, or other declarative deployment keeps command-line,
  credential, and environment-managed values read-only through the API;
- a repository maintainer can inspect private information and perform only
  actions scoped to repositories they maintain;
- a service administrator can inspect service-wide analytics and change the
  settings and operational state delegated to the control plane; and
- monitoring systems can continue scraping Prometheus without making
  Prometheus the source of truth for accounting, quotas, or configuration.

This is a control plane around the existing relay and Git data plane. It must
reuse the existing authorization and repository lifecycle rules rather than
creating a second interpretation of repository ownership.

## Interface boundaries

The same process serves several interfaces with different purposes:

| Interface | Purpose | Data model |
| --- | --- | --- |
| Nostr WebSocket | Repository announcements, states, PRs, and related signed events | Nostr events |
| Git Smart HTTP | Repository fetch and push | Git protocol |
| NIP-86-compatible HTTP API | Private queries, analytics, settings, and actions | JSON request/response |
| `/admin/` | Human-facing management client | Embedded static application |
| `/metrics` | Machine-oriented monitoring and alerting | Prometheus exposition |

Nostr data remains queryable over Nostr. Internal state that is not naturally a
Nostr event---effective configuration, resource usage, queue health, quota
state, and audit records---is returned through the management API. The web
application may use both interfaces and join their results in the browser.

The management API is request/response. A private result is returned directly
to its authenticated caller over TLS; it is not published, persisted as a
public Nostr event, or broadcast to relay subscribers. Private responses use
`Cache-Control: no-store` and must not pass through a shared cache. Unsolicited
live updates are not part of the first design. Polling is sufficient initially;
an authenticated event stream can be designed later if a concrete need
appears.

## Protocol foundation

### NIP-98 authenticates HTTP requests

[NIP-98](https://github.com/nostr-protocol/nips/blob/master/98.md) is the
authentication foundation, not the management API itself. A shared parser will
verify the kind-27235 event, signature, timestamp, and required tags. Explicit
validation profiles then apply different rules without accidentally weakening
one another:

- **Standard NIP-98:** the `u` tag exactly matches the absolute request URL and
  the `method` tag matches the HTTP method.
- **Management NIP-98:** standard validation plus `POST`, a mandatory payload
  hash covering the exact request body, a short validity window, and replay
  rejection for mutations.
- **GRASP-08 repository read:** the existing repository-root `GET` profile,
  whose controlled short-window reuse is necessary for Git Smart HTTP.

The GRASP-08 profile must not be accepted for management calls. Its reusable
credential and intentionally ignored payload are appropriate for a sequence of
Git fetch requests but not for an administrative mutation.

### NIP-86 supplies the management envelope

[NIP-86](https://github.com/nostr-protocol/nips/blob/master/86.md) defines a
JSON request/response protocol over HTTP at the same URI as the relay
WebSocket, selected by `Content-Type: application/nostr+json+rpc`. ngit-grasp
will:

- implement applicable standard methods with their specified names and
  parameter/result shapes;
- implement `supportedmethods` from the beginning;
- advertise extension methods through `supportedmethods`; and
- retain the standard `{ "result": ..., "error": ... }` response envelope.

Extensions use collision-resistant names:

- `grasp.*` for behavior intended to be portable across GRASP
  implementations; and
- `ngit-grasp.*` for this implementation's settings and internal analytics.

The exact extension names and schemas are part of the API contract and require
versioned compatibility once released. The embedded web application discovers
methods and capabilities instead of assuming that its server implements every
method known to the newest client.

## Authentication is not authorization

A valid NIP-98 event establishes the actor pubkey. A separate authorization
layer decides which method and scope that actor may use.

Initial capabilities are:

| Capability | Intended authority |
| --- | --- |
| Public discovery | Anyone |
| Own-account usage | The same pubkey and service administrators |
| Repository read | Maintainers authorized for that exact owner and identifier, and service administrators |
| Repository action | Method-specific subset of those repository maintainers, and service administrators |
| Service observation | Configured service observers and administrators |
| Service administration | Relay owner and explicitly configured service administrators |

Repository authorization uses the existing recursive NIP-34 maintainer
calculation. Every repository-scoped request names both owner and identifier;
an identifier alone is ambiguous because several owners can announce versions
of the same project.

On a GRASP-08 private service, membership is an additional outer admission
check. Membership grants access to the private trust domain but never implies
service-administrator authority. A valid caller who is not authorized for a
scope must receive a stable error that does not reveal whether an otherwise
private repository exists.

The web application can hide controls that the caller cannot use, but the API
is always the security boundary.

## Scoped analytics and future quotas

Not every useful measurement belongs to a repository. API resources and quota
accounting have an explicit scope:

| Scope | Examples |
| --- | --- |
| Service | Capacity, process health, connection totals, and global policy limits |
| Principal | Total storage, repository count, bandwidth allowance, and assigned tier |
| Repository | Storage, Git traffic, last accepted state, and sync health |
| Tier | Defaults, member count, and aggregate usage visible to administrators |

The actor and charged principal are distinct. A maintainer who pushes to a
repository acts under their own signed identity, but resource usage is charged
to the repository owner or another explicitly modeled quota principal.

Prometheus remains observational. Durable accounting counters, reservations,
period boundaries, tier assignments, and overrides belong in the control
database. This avoids high-cardinality private labels in `/metrics` and avoids
using resettable process metrics as enforcement state.

When quotas are introduced, admission will resolve all applicable policies:

1. a service hard ceiling;
2. the principal's assigned tier;
3. an optional principal override; and
4. an optional repository override.

Operations must satisfy every applicable pool. Concurrent resource-consuming
operations will reserve capacity before beginning and commit actual usage or
release the reservation afterward, preventing individually valid operations
from collectively exceeding a limit.

## Embedded management application

A React application will be compiled to fingerprinted static assets and
included in release builds. The Rust process serves the application beneath
`/admin/`; production does not require Node.js or a separate web server.

The application will:

- use a NIP-07 browser signer initially and leave room for a NIP-46 remote
  signer;
- never request, receive, or store an `nsec`;
- sign each management request with a body-bound NIP-98 event;
- use Nostr subscriptions for repository event data;
- use the management API for settings, analytics, accounting, and actions;
- discover supported methods and the caller's capabilities; and
- show the source, mutability, and application state of every setting.

The bundled client and server are released together, but the API remains a
real external interface so alternative clients and automation can use it.
The client must tolerate older or newer servers through capability discovery.
Assets should be self-contained and served with a restrictive content security
policy; externally hosted scripts and fonts are unnecessary.

## Configuration as layered, provenance-aware state

Today `Config` is a startup snapshot populated by clap, environment variables,
`.env`, protected credentials, and defaults. Management requires an explicit
setting registry and preserved provenance rather than a plain struct whose
source has been forgotten.

The proposed precedence, highest first, is:

1. command-line arguments;
2. protected credentials for secret-bearing settings;
3. process environment, including values rendered by the NixOS module;
4. `.env` values;
5. control-database overrides; and
6. built-in defaults.

NixOS is not a separate runtime source: the module renders options into
environment values or protected credentials. The API can still describe such
a setting as operator-managed and read-only.

This ordering gives operators an unconditional escape hatch. Adding a CLI,
credential, environment, NixOS, or `.env` value immediately shadows a database
override. Removing the higher-priority value allows the stored override to
become effective again, so the API must display both the effective value and
any shadowed override and must allow an administrator to clear the override.
It must never silently pretend that a shadowed API write changed the running
service.

Each registered setting describes at least:

- stable API key and human description;
- value type and validation function;
- active value and configured value;
- effective source and optional stored override;
- whether the value is secret;
- whether the API may write an override;
- application mode; and
- revision for optimistic concurrency.

Secrets are never returned. Their API representation says only whether they
are configured, their effective source, and whether rotation is possible by
another mechanism. Bootstrap settings needed to locate or secure the control
plane---relay owner secret, control-database location, database backend, and
initial listener binding---remain operator-managed initially.

API writes use the same parser and validation logic as startup configuration.
A write includes the revision the client observed and fails on a conflicting
newer write instead of losing an update.

## Control database

A dedicated SQLite control database is the preferred implementation. It is
separate from the Nostr event database and repository holding/archive storage.
SQLite is a good fit for small transactional control-plane records, migrations,
auditing, and future quota accounting while preserving the single-binary
operator experience. A short implementation spike should confirm the Rust and
Nix packaging choice before this becomes permanent.

The initial schema needs only a few concepts:

- `setting_overrides`: key, typed JSON value, revision, actor, and timestamps;
- `audit_entries`: actor, authentication event, method, scope, before/after
  summary, result, and timestamp; and
- `nip98_replays`: recently consumed authentication event IDs for mutations.

Future migrations may add service roles, tier definitions, tier assignments,
quota overrides, usage counters, and reservations. Schema migrations run
transactionally and are versioned with the binary.

The database is authoritative only for the control-plane layer. A row cannot
override an operator-managed source. It must also never become a second store
for Nostr repository state.

## Applying configuration changes

Every setting has one of three application modes:

- **Live:** persist, validate, and update the running component atomically.
- **Restart required:** persist the configured value but leave the active
  value unchanged until the next successful restart.
- **Operator only:** visible or redacted through the API but not writable there.

A setting response distinguishes `active_value` from `configured_value` and
includes `pending_restart`. The UI must not describe a persisted restart-bound
change as active.

The first implementation may classify most mutable settings as restart
required. Over time, individual components can consume watch channels or
explicit reconfiguration messages and graduate to live application. This is a
per-setting correctness decision, not a blanket promise: settings that change
storage identity, listener topology, or security boundaries may remain
restart-bound or operator-only indefinitely.

A live update is successful only if persistence and runtime application agree.
If runtime application fails, the operation must report failure and leave an
unambiguous recoverable state; it must not claim success while silently running
the old value.

## First vertical slice

The first milestone deliberately implements one meaningful private read and
one safe action. `supportedmethods` is also required but does not count as the
read because it does not exercise resource authorization.

### Read: `ngit-grasp.getrepositorystats`

Parameters identify an owner and repository identifier. The initial result can
remain small: whether the repository is hosted, Git storage bytes, the latest
accepted state timestamp, and a coarse sync/health summary supported by
existing state.

This method establishes:

- strict management NIP-98 validation;
- private HTTP responses;
- repository scope parsing;
- recursive maintainer authorization;
- indistinguishable absent/unauthorized behavior; and
- a custom method and result schema discoverable by the UI.

### Action: standard `changerelaydescription`

Changing the relay description is a standard NIP-86 method, service-admin
only, non-destructive, and visibly testable through NIP-11 and the landing
page. It is the first setting backed by the override database.

The action:

1. authenticates and authorizes the service administrator;
2. rejects a change when a CLI, environment, NixOS-rendered, or `.env` value
   owns the setting;
3. validates and transactionally stores the override otherwise;
4. updates the live NIP-11/landing-page view;
5. records a structured audit entry; and
6. returns the new value, source, revision, and application state.

This method establishes standard NIP-86 interoperability, persistent mutation,
configuration precedence, audit behavior, optimistic concurrency, and a live
setting update without beginning with deletion, blacklist, or quota
enforcement.

### Thin embedded UI

The same milestone should include the smallest useful compiled application:

- connect a Nostr signer;
- show the authenticated pubkey and discovered capabilities;
- query repository statistics for an owner and identifier; and
- show and, when authorized, edit the relay description.

Completing the read, action, persistence, and bundled UI together proves the
whole delivery path before the API surface expands.

## Evolution after the vertical slice

### 1. Generalize configuration

Move settings into the provenance-aware registry, expose read-only settings,
support validated overrides for eligible settings, and make restart state
visible. Keep bootstrap and secret settings operator-managed.

### 2. Add operational reads and actions

Expose service health, sync state, purgatory summaries, repository lifecycle
state, and safe retry/reconciliation actions. All lifecycle mutations must go
through the existing per-repository locking and deletion/recovery facades.

### 3. Add roles and scoped analytics

Introduce explicit observer and administrator assignments, self-usage views,
and consistent service/principal/repository authorization. Standard NIP-86
roles should be implemented where their semantics fit; NIP-34 repository
maintainers remain a distinct repository-scoped authority.

### 4. Add tiers, accounting, and quotas

Persist tier definitions and assignments, build durable scoped usage
accounting, expose effective-limit explanations, and add reservation-based
enforcement at operation boundaries. API and UI views arrive before automatic
enforcement so operators can validate accounting.

### 5. Graduate settings to live application

Replace restart requirements one setting at a time with component-specific
reconfiguration mechanisms and tests proving that active and configured state
cannot diverge silently.

## Security and correctness requirements

- Invalid NIP-98 requests receive `401 Unauthorized`; valid but unauthorized
  calls do not reveal private target existence.
- Management POST payload hashes are mandatory.
- Mutations reject authentication-event replay and are idempotent where the
  operation permits it.
- The API never accepts the relaxed GRASP-08 Git credential profile.
- The API never returns secrets, raw private keys, or unrestricted process
  environment data.
- All mutations are audited, including rejected attempts after authentication.
- High-cardinality private usage remains out of public Prometheus labels.
- Repository operations reuse current maintainer calculation and lifecycle
  serialization.
- The UI never holds key material and is not trusted to enforce permissions.
- Database migration, configuration validation, and runtime application
  failures are observable and fail without claiming a change succeeded.
- Tests wait on observable state with bounded deadlines; configuration tests do
  not rely on fixed sleeps.

## Deliberately deferred

This vision does not initially promise:

- every setting is API-writable;
- every setting applies live;
- server-initiated real-time management updates;
- a billing or payment system for tiers;
- quota enforcement before trustworthy accounting exists;
- replacement of Prometheus or normal application logs; or
- one control plane managing a fleet of ngit-grasp instances.

Those can build on the same API, authorization, persistence, and capability
patterns once the single-instance path is proven.

## Success criteria

The direction is successful when:

- generic NIP-86 clients can use the standard methods ngit-grasp advertises;
- maintainers can retrieve private repository information without gaining
  service-wide visibility;
- declarative operators can see, but cannot accidentally overwrite,
  operator-managed settings;
- hobbyists can persist eligible settings through the bundled interface;
- every response explains effective source and application state;
- every mutation has an authenticated audit record;
- the binary remains self-contained at runtime; and
- new reads, actions, settings, and quota dimensions can follow established
  patterns instead of adding bespoke authentication and storage paths.
