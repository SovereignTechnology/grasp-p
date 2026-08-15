# GRASP-08: Private Service Authentication — Design

**Status**: Implemented, single-service scope (opt-in via `NGIT_PRIVATE_MODE`)

**Spec**: [GRASP-08](https://github.com/DanConwayDev/grasp/blob/main/08.md)
**Related**: [Architecture](architecture.md), [Defensive Measures](defensive-measures.md), [Repository Lifecycle](repository-lifecycle.md)
**Configuration**: [`NGIT_PRIVATE_MODE`, `NGIT_PRIVATE_MEMBERS`, `NGIT_PRIVATE_PUBLIC_ORIGIN`](../reference/configuration.md)

---

## Overview

GRASP-08 turns a GRASP service into a private one: repository events and Git
objects must not be readable merely because an endpoint is reachable. Every
Nostr WebSocket session must authenticate with NIP-42 and every standard Git
Smart HTTP request must carry a repository-scoped NIP-98 credential before any
repository data is served.

Private mode is a **service-wide access boundary**, not a per-repository ACL.
A private instance is one trust domain: everything it hosts is readable by
every member and by nobody else. Push authorization is unchanged — a private
credential proves membership, and GRASP-01's maintainer-based push rules still
decide who may write which repository.

## What GRASP-08 changes

1. **WebSocket**: after the public upgrade, a message-level proxy issues a
   NIP-42 `AUTH` challenge and validates the response before the connection is
   bridged to the embedded relay. Unauthenticated `REQ`/`EVENT`/`COUNT`/
   `NEG-OPEN` messages receive machine-readable `auth-required:` rejections;
   a valid authentication by a non-member receives `restricted:` and the
   connection is closed. Three invalid attempts or thirty seconds of silence
   terminate the connection.
2. **Git Smart HTTP**: requests under `/<npub>/<identifier>.git` must carry the
   GRASP-08 profile of NIP-98 (see below). Authentication runs before
   repository lookup or request-body collection.
3. **Membership**: one shared member set combines operator-configured npubs
   (`NGIT_PRIVATE_MEMBERS`) with the NIP-11 owner pubkeys of relays referenced
   by *accepted* repository announcements. Membership changes propagate to
   live WebSocket sessions, which are closed when their pubkey is removed.
4. **Discovery stays public**: the NIP-11 document (which advertises NIPs 42
   and 98), the NIP-05 root identity, the landing page, and the icon remain
   unauthenticated so clients can discover the authentication requirement.
   This deliberately discloses the operator identity and the service's
   existence — private mode hides repository *content*, not the service.

Everything else — announcement purgatory, proactive sync, push authorization,
repository lifecycle — is unchanged.

## Why this shape

### Why every failure is the same empty 401

Missing, malformed, expired, and non-member Git credentials all receive an
identical empty `401 Unauthorized` with the same `WWW-Authenticate: Nostr`
challenge. Distinguishable failures would let an unauthenticated party probe
which repositories exist or which pubkeys are members. Authentication runs
before repository lookup for the same reason: a 404-before-auth would be an
existence oracle.

### Why the Git credential differs from generic NIP-98

Generic NIP-98 signs the exact request URL and method and is single-use. A Git
clone is not one request — it is a sequence of `info/refs` and pack-transfer
requests, issued by tooling that cannot re-sign per request. The GRASP-08
profile therefore signs the **canonical repository root** with method `GET`,
ignores payload tags, and is reusable across the standard Smart HTTP endpoints
for a 60-second validity window. Replay within the window is accepted: the
credential grants read access the holder already has for that window, and
write operations remain gated by GRASP-01 push authorization, so replay
confers nothing beyond what the member could do anyway.

The canonical public origin is operator-controlled
(`NGIT_PRIVATE_PUBLIC_ORIGIN`, falling back to `NGIT_DOMAIN`) so that a
reverse proxy cannot influence the identity that credentials sign.

### Why NIP-42 runs outside the embedded relay

`nostr-relay-builder`'s query and write policies do not receive the
authenticated session pubkey, so the access check cannot live inside them.
Instead the proxy authenticates first and only then bridges frames through an
in-memory WebSocket pair to `LocalRelay`. The bridge subscribes to a
membership generation channel; revoking a member closes their live sessions
instead of letting them ride out an old connection.

### Why membership is service-wide

Relays are referenced per repository in NIP-34 announcements, but access here
is per service. Reconciling the two per-repository would require per-session
subscription filtering inside the embedded relay (which the policy interfaces
cannot express, see above) and would turn every query into an ACL join. The
single-service model instead declares the whole instance one trust domain —
the deployment it targets is a team running a private service for its own
repositories. Hosting mutually-distrusting sub-groups on one instance is
explicitly out of scope and belongs to the future multi-service/fleet
proposal. Under this model, per-repository relay lists act as **sync topology
hints** (who to connect to), while the service-wide member set is the **ACL**
(who may read).

### Why accepted-relay owners are admitted dynamically

Two private services mirroring the same repository must be able to read from
each other. When an accepted announcement references another relay, that
relay's NIP-11 `pubkey` is added to the member set, so a peer service (or the
operator of an ordinary relay the team uses) can authenticate without manual
whitelisting on both sides. The consequence — accepting one announcement
grants its referenced relay operators read access to the whole service —
follows directly from the one-trust-domain model and is the operator's
opt-in via announcement admission.

Discovery reuses the NIP-11 document already fetched once per sync
connection, and reconciliation rides the existing five-second maintenance
pass, so dynamic membership adds no polling, subscriptions, connections, or
background tasks.

### Why purgatory announcements grant nothing

Purgatory holds announcements that have *not* passed repository admission.
If purgatory state could contribute relay owners to the member set, anyone
able to get an event into purgatory could mint members. Only announcements
accepted into the repository index count.

### Why private mode refuses to combine with GRASP-06

The GRASP-06 contributor endpoint (`/prs/`) is intentionally unauthenticated —
its entire design premise is that any contributor can push a PR (see
[GRASP-06 design](grasp-06-contributor-pr-submission.md)). That premise is
incompatible with a private service, so `NGIT_PRIVATE_MODE=true` together
with `NGIT_GRASP06_ENABLE=true` is a fatal configuration error rather than a
silently half-open service.

### Why configuration fails closed

Private mode without members would lock everyone out silently, and members
without private mode would suggest an operator believes the service is
private when it is not. Both are startup errors. Malformed member npubs are
fatal rather than skipped: dropping an access-control entry would silently
lock a user out.

## Trust model summary

- **Configured members** (`NGIT_PRIVATE_MEMBERS`) are the permanent base set,
  trusted by operator assertion.
- **Accepted-relay owners** are derived members, trusted transitively via
  announcement admission plus the referenced relay's NIP-11 self-assertion
  (the same HTTPS-from-domain trust anchor a `_@domain` NIP-05 lookup would
  provide, without an extra fetch or format).
- **Membership grants read access only.** Push authorization remains
  GRASP-01's maintainer model; repository admission remains announcement
  policy.
- **Removal is not retroactive.** Removing a member closes their sessions and
  invalidates future credentials, but repositories admitted while they were a
  member remain hosted until the operator curates them.

## Follow-up scope

Deliberately excluded from the initial single-service implementation:

- **Membership-gated announcement admission**: requiring announcement authors
  to be members, so hosting and derived membership can only expand through
  member action. (Non-members cannot reach the relay to publish, but members
  can currently submit third-party-signed announcements, and sync can import
  them from operator-configured sources.)
- **Outbound authentication**: presenting NIP-42 and GRASP-08 NIP-98
  credentials when syncing *from* other private services, using a service
  identity key. This is the missing half of zero-configuration private
  mirroring.
- **Multi-service fleet orchestration** and **encrypted kind-10318 client
  discovery**, which belong to future GRASP proposals.
