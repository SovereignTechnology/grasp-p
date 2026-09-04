# GRASP-06: Contributor Pull Request Submission — Design

**Status**: Implemented (opt-in via `NGIT_GRASP06_ENABLE`)

**Spec**: [GRASP-06](https://gitworkshop.dev/danconwaydev.com/grasp/tree/master/06.md)
**Related**: [Purgatory Design](purgatory-design.md), [Architecture](architecture.md), [Inline Authorization](inline-authorization.md)
**Operator how-to**: [Enable GRASP-06](../how-to/enable-grasp-06.md)

---

## Overview

GRASP-06 adds a contributor-submission git endpoint at `/prs/<npub>/<identifier>.git` where any author can push `refs/nostr/<event-id>` for PRs and PR Updates targeting any repository — even repositories this relay has no accepted announcement for.

It exists to solve one problem: **a contributor should always have somewhere to push a PR**, even when the repository's primary GRASP servers are down, applying SPAM or curation policy that rejects the contribution, or otherwise unable to host it. Without this, the NIP-34 alternative is the "personal fork" announcement, which pollutes repo discovery with forks nobody treats as independent projects.

GRASP-06 is opt-in per operator. A relay that enables it accepts a strictly bounded relaxation of GRASP-01's event-acceptance rules and opens one additional URL namespace.

## What GRASP-06 changes

1. **New URL namespace**: `/prs/<npub>/<identifier>.git` (git smart HTTP, unauthenticated).
2. **Event acceptance relaxation**: PR (kind 1618) and PR Update (kind 1619) events that would be rejected under GRASP-01 for not referencing an accepted repository announcement are instead accepted into purgatory, provided the event's `clone` tag names our `/prs/<signer>/<identifier>.git` endpoint.
3. **Cross-service mirroring**: when a PR or PR Update is released from purgatory via the `/prs/` endpoint, its `refs/nostr/<event-id>` is synced into any accepted repository announcements on this relay whose coordinate appears in the event's `a` tags.

Everything else — authorization on the standard endpoint, repository announcement purgatory, PR purgatory bidirectional waiting, proactive sync, NIP-11, etc. — is unchanged.

## Why this shape

### Why a separate URL namespace

Standard `/<npub>/<identifier>.git` carries the GRASP-01 authorization model: pushes are authorised against the repository announcement's maintainer set. That model fundamentally cannot serve the contributor-submission use case, since the contributor is not in the maintainer set and the announcement may not even exist on this relay. Rather than overloading the standard endpoint with two auth models, GRASP-06 introduces a distinct namespace whose rules are deliberately different.

### Why `refs/nostr/<event-id>` is the only accepted ref form

The ref name is the nostr event id. The event is signed, its `c` tag pins a commit, and the ref must match that commit for the event to be released from purgatory. This makes the ref:

- immutable once locked (the signed event's commit never changes),
- self-verifying (server can recompute the binding from the event),
- trivially garbage-collectable (ref name maps 1:1 to an event-id lifecycle).

No `refs/heads/*` or other namespaces are accepted — there is no authorised maintainer to decide what branches mean.

### Why no HTTP auth on push

The entire gate is the signed PR/PR Update event. The event's signer, d-tag and `c` tag determine whether the ref is valid. Adding NIP-98 or similar would be redundant — a forged push without a matching event is dropped in purgatory within 20 minutes, and a matching event cannot be produced without the signer's key.

### Why the event must name us in its `clone` tag

Two reasons:

1. **Intent check**: it proves the contributor explicitly chose this relay as a destination, not that we happen to match a naming pattern by accident.
2. **Preventing replay/fan-out abuse**: without the `clone` tag, every GRASP-06 relay on the network would accept every PR event that happens to match its URL shape, multiplying storage pressure across the ecosystem.

### Why mirror `/prs/ → /<maintainer>/` but not the other way

The contributor chose to publish to `/prs/`. Mirroring into any accepted repository on this relay makes the PR visible at the expected location for clients browsing that repo. Not mirroring the reverse direction preserves the maintainer's declared `clone` intent on their own pushes — we do not invent new hosting locations for their events.

Identifier-family object storage makes the mirror a ref-only operation. Owner
and contributor views for the same identifier resolve one shared object
inventory, so accepting or mirroring a PR does not copy its object graph.

## Architecture

### URL routing

```
GET/POST /<npub>/<id>.git/*    → existing standard endpoint (unchanged)
GET/POST /prs/<npub>/<id>.git/* → new GRASP-06 endpoint (this doc)
```

`prs` is a reserved top-level path segment. Because valid npubs start with `npub1`, there is no collision with existing routing.

### Fetch semantics

```
GET /prs/<npub>/<id>.git/info/refs?service=git-upload-pack
POST /prs/<npub>/<id>.git/git-upload-pack

  GRASP-06 disabled      → 404
  Repo exists on disk    → serve from disk (normal git-upload-pack)
  Repo does not exist    → synthesize empty-repo response (no disk state created)
```

Synthesizing the empty response avoids creating a directory per URL probe. It also means clients can speculatively clone any well-formed `/prs/<npub>/<id>.git` URL and get a zero-ref repo back, matching what they would get the moment before any contributor has pushed.

### Push semantics

```
POST /prs/<npub>/<id>.git/git-receive-pack

  GRASP-06 disabled                       → 404
  Pushed ref not refs/nostr/<64-hex>      → reject (ERR pkt-line)
  Repo does not exist                     → git init --bare on first valid ref seen
  For each refs/nostr/<event-id> pushed:
    event found in DB or purgatory:
      signer ≠ URL npub                   → reject ref
      identifier (d-tag) ≠ URL identifier → reject ref
      commit ≠ event's c tag              → delete ref
      all match                           → ref locked; retain family tip; release event from purgatory;
                                            mirror to matching standard repos
    event not yet seen:
      accept ref; create or update PR placeholder in purgatory
                  scoped to (submitter, identifier, event-id)
  After receive-pack:
    repo ended with zero refs             → rm -rf the repo directory
```

The flow mirrors the existing `refs/nostr/<event-id>` path at the standard endpoint (see [`src/git/handlers.rs:handle_receive_pack`](../../src/git/handlers.rs) and the PR purgatory entries in [`src/purgatory/types.rs`](../../src/purgatory/types.rs)) — it just skips the `authorize_push` path that checks the maintainer set, and applies the spec's validation invariant instead.

#### On-demand bare repo creation

The first push to `/prs/<submitter>/<identifier>.git` creates a thin bare view
whose alternate is the identifier family. A per-`(submitter, identifier)`
[`PrsPathState`](../../src/grasp06/receive.rs) still protects view creation and
cleanup. A separate per-family write lease serializes object-producing work
across all owner and contributor views for that identifier. `git-receive-pack`
writes objects to the family while updating only the selected view's refs.
Off-push cleanup may remove an empty contributor view, but never removes family
objects or retained roots.

### Event acceptance relaxation

The existing PR event policy in [`src/nostr/policy/pr_event.rs`](../../src/nostr/policy/pr_event.rs) calls `fetch_repository_data_excluding_purgatory` to require an accepted announcement in the database before accepting a PR event. Under GRASP-06 this check is loosened for events that satisfy:

- signer pubkey,
- a d-tag on any `a` tag,
- and a `clone` tag pointing at this relay's `/prs/<signer>/<d-tag>.git`.

Such events skip the "references accepted announcement" check and are accepted into purgatory directly. They remain in purgatory until the matching push arrives at `/prs/<signer>/<d-tag>.git` (standard 30-minute TTL applies).

Events that qualify under the existing GRASP-01 rules still flow through the normal path unchanged — the GRASP-06 branch is only taken when the existing path would have rejected.

The clone-URL match is implemented in [`src/grasp06/policy.rs`](../../src/grasp06/policy.rs) as a strict comparator: it requires `http`/`https` scheme, an exact (case-insensitive) authority match against `config.domain`, no query string or fragment, exactly two path segments `<npub-segment>/<repo-segment>.git`, the npub segment decoding via `PublicKey::from_bech32` to the event's signer, and the percent-decoded identifier matching one of the event's `a`-tag `<d>` values. Anything else fails the relaxation and the event falls through to the existing rejection path.

### Cross-service mirror

When a PR or PR Update's purgatory entry is released via a `/prs/` push:

1. Save event to DB and remove from purgatory (as today).
2. For each `a` tag in the event of the form `30617:<pubkey>:<d-tag>`:
   - Resolve to a local repo path `<git_data_path>/<pubkey-npub>/<d-tag>.git`.
   - If that repo has an active (non-purgatory) announcement, install `refs/nostr/<event-id>` in its view after checking the commit resolves through the shared family.

The mirror installs the same ref to the same commit. Git alternates keyed by
identifier make the objects immediately available without a copy.

The mirror is **one-directional**: pushes to `/<maintainer>/<id>.git` are not mirrored into `/prs/*`. Only the `/prs/` → `<maintainer>/` direction fires, and only when the source repo path is under `prs_base_path`.

The mirror also does **not back-fill** retroactively. If an announcement for one of the event's `a` coords is accepted *after* a matching `/prs/` push has already happened, the ref remains only at `/prs/<signer>/<d>.git`; clients can still fetch it via the event's `clone` tag. Back-filling on announcement promotion is deferred — the simplest correct shape ships first, and the spec allows clients to resolve the PR through `/prs/` indefinitely.

### Purgatory integration

No new purgatory entry types are strictly required. The existing `PrPurgatoryEntry` already supports event-first and git-first patterns keyed by event id. Under GRASP-06:

- **Event-first**: event arrives, GRASP-06 relaxation accepts it, normal purgatory `add_pr` call, waits for any push that materialises `refs/nostr/<event-id>` with matching commit — at either the standard endpoint or `/prs/`.
- **Git-first**: push arrives at `/prs/<npub>/<id>.git`, normal `add_pr_placeholder` call keyed by event-id. Validation at the `/prs/` receive-pack handler additionally records the `(submitter, identifier)` tuple for later matching (see Implementation Plan §5).

Placeholder entries created at `/prs/` should be validated against `(submitter == url_npub) && (d-tag == url_identifier)` when their event arrives. A small additional field on `PrPurgatoryEntry` captures the scoping when the placeholder was created by the `/prs/` path.

### Exclusion from other subsystems

- **Empty-repo cleanup** ([`src/cleanup_empty_repos.rs`](../../src/cleanup_empty_repos.rs)): skips `<git_data_path>/prs/*` via [`is_prs_repo_path`](../../src/grasp06/paths.rs) before recursing, so contributor-submission repos cannot be misreported as orphans.
- **Repo landing pages** ([`src/http/mod.rs::parse_repo_url`](../../src/http/mod.rs)): refuses any path starting with `/prs/` as a defensive guard, regardless of `grasp06_enable`. The `HttpService` routing also intercepts `/prs/*` earlier when the feature is on.
- **Proactive sync** (GRASP-02): `/prs/` repos are not replicated between relays. The proactive-sync subsystem derives every subscription from the DB-resident announcement set; `/prs/` repos have no announcement and so are excluded by construction. No filesystem walk discovers them. A GRASP-06 relay is authoritative for the PRs it accepts. Clients that need a PR should fetch it from the relay the event's `clone` tag names.
- **Repo listings / NIP-11**: `/prs/` repos are not advertised as repositories. They are a submission side-channel, not first-class hosted repos. GRASP-06 itself is advertised in the relay's NIP-11 `supported_grasps` list when the flag is on.

### Zero-ref `/prs/` cleanup

A `/prs/<submitter>/<identifier>.git` bare repo can become zero-ref through three runtime paths — each cleaned up inline at the site where the last ref is removed — plus a startup recovery pass that catches anything left behind by a previous run. There is no periodic sweep over `<git_data_path>/prs/`:

1. **Probe push leaves no valid refs.** The `/prs/` receive handler validates each pushed `refs/nostr/<event-id>` against the database and purgatory. If every ref fails validation, the bare repo is empty at the end of the push. The handler removes it before returning, under a brief end-of-push critical section on the per-path mutex (the mutex is *not* held across `git-receive-pack` itself — only across the init+register and decrement+cleanup windows).
2. **Scoped placeholder fails validation against a later-arriving event.** When a PR event arrives whose `(signer, identifier, commit)` does not match the placeholder a `/prs/` push registered, the PR-event policy ([`src/nostr/policy/pr_event.rs`](../../src/nostr/policy/pr_event.rs)) takes the per-path mutex, deletes the corresponding `refs/nostr/<event-id>` ref, and discards the placeholder. It removes the bare directory only when `in_flight == 0` (no push is currently mid-receive) and `list_refs` reports empty.
3. **Scoped placeholder expires without a matching event.** The standard purgatory sweep ([`src/purgatory/mod.rs`](../../src/purgatory/mod.rs), every 60 seconds) walks expiring `PrPurgatoryEntry` rows. For entries with a `prs_scope`, the sweep best-effort deletes the dangling `refs/nostr/<event-id>` ref and — under the same `in_flight == 0` guard — the bare repo itself. The sweep is synchronous, so it uses `try_lock` on the per-path mutex: if a push is briefly holding the mutex (during init or end-of-push), the cleanup is skipped this cycle. In the worst case a dangling ref is left on disk; this is harmless because any future push to the same path simply ignores it, and the next purgatory sweep will retry.
4. **Startup recovery.** Before the HTTP server starts accepting requests, [`src/grasp06/cleanup.rs::scan_on_startup`](../../src/grasp06/cleanup.rs) walks `<git_data_path>/prs/<hex>/<id>.git` once and removes any bare repo with zero refs, plus any submitter directories left empty as a result. This catches dirs left behind by a previous run — crashes mid-push, crashes mid-cleanup (between `delete_ref` and `remove_dir_all`), or clean shutdowns with unresolved scoped placeholders whose in-memory state was lost. Nothing is in flight at startup so no locking is needed; the same `list_refs` / `remove_dir_all` shape as the runtime paths applies. Gated on `grasp06_enable` — operators who have turned the feature off do not have their existing `/prs/` data scanned.

The shared lock map is wired through:

- [`HttpService`](../../src/http/mod.rs) holds it as `repo_init_locks` and passes it into every `/prs/` request.
- [`PolicyContext`](../../src/nostr/policy/mod.rs) holds the same `Arc<DashMap<…>>` so the PR-event policy can lock without going through HTTP.
- [`Purgatory::set_prs_cleanup_ctx`](../../src/purgatory/mod.rs) wires the lock map (plus `git_data_path`) into purgatory at startup so the expiry sweep has everything it needs to act on a scoped placeholder.

Off-push deletion paths and the receive handler therefore share a single source of truth for "is a push currently in flight to this `(submitter, identifier)`" — the per-path `in_flight` counter, read under the same mutex that gates its updates.

## Flow examples

### Event-first (most common)

```
1. Contributor publishes kind 1618 PR event to network.
   Event's `a` tag: 30617:<maintainer-pubkey>:my-project
   Event's `c` tag: <commit-hash>
   Event's `clone` tag: https://grasp-06-relay.example/prs/<contributor-npub>/my-project.git

2. Event reaches grasp-06-relay via WebSocket.
   - Existing PR policy: no accepted announcement for <maintainer>:my-project → would reject.
   - GRASP-06 relaxation: event has `clone` tag naming our /prs/ endpoint, matches
     signer+d-tag invariant → accept to purgatory.
   - Response: OK true "purgatory: won't be served until git data arrives".

3. Contributor runs `git push https://grasp-06-relay.example/prs/<contributor-npub>/my-project.git
   <commit-hash>:refs/nostr/<event-id>`.

4. Server receives push:
   - Creates /prs/<hex>/my-project.git if missing.
   - git-receive-pack writes refs/nostr/<event-id>.
   - Post-push check: finds PR event in purgatory. Signer matches URL npub.
     d-tag matches URL id. Commit matches event's c tag. Ref is locked.
   - Event promoted: saved to DB, removed from purgatory, subscribers notified.
   - Mirror: if we have an accepted announcement 30617:<maintainer>:my-project
     locally at <maintainer>/my-project.git, copy refs/nostr/<event-id> into it.
```

### Git-first

```
1. Contributor pushes first (race between git push and event propagation).
   Server creates /prs/<hex>/<id>.git, accepts refs/nostr/<event-id>.
   No matching event anywhere → placeholder created scoped to
   (submitter=<url-npub>, identifier=<url-id>, event-id).

2. Event arrives:
   - Placeholder is found by event-id.
   - Validation: signer matches placeholder.submitter, d-tag matches placeholder.identifier,
     c tag matches stored commit → ref locked; event promoted.

3. If event never arrives within 20 minutes: ref deleted, repo dir may be removed
   if it becomes ref-less.
```

### Non-matching event

```
1. Push arrives with refs/nostr/<event-id> for commit A.
2. Event arrives with c tag = commit B (mismatch).
   - Ref refs/nostr/<event-id> deleted from /prs/<npub>/<id>.git.
   - Event goes through normal PR policy; if no matching git data elsewhere, purgatory.
   - Placeholder discarded.
```

## Configuration

One new flag:

- `NGIT_GRASP06_ENABLE` (bool, default `false`) — opts the relay in.

No further knobs in the initial implementation. Future additions (stubbed for plan only, not built): allowlist, per-npub disk quota, per-ref size cap, PoW difficulty.

## Interactions with planned but unbuilt features

### Maintainer curation (not yet specified)

GRASP-06 anticipates but does not depend on curation. The envisaged integration when curation lands:

- Maintainer curation-remove of a PR event → deletes the mirrored `refs/nostr/<event-id>` at `<maintainer>/<id>.git` and removes the event from the event DB.
- The origin ref at `/prs/<contributor-npub>/<id>.git` **survives** — the contributor can republish the event to another relay and clients fetching from there can still pull the commits.

This is the design rationale for the mirror being one-directional and the `/prs/` ref surviving independently.

### Deletion requests (in-progress on separate branch)

Deletion of the contributor's own PR event (NIP-09) → the deletion-request branch will decide and implement the ref-lifecycle behaviour. GRASP-06 v1 does not add hooks or no-op scaffolding for this.

### Object-pool deduplication

The identifier family is the shared object inventory. Mirroring installs a view
ref and does not copy objects; no URL or spec change is required.

## Anticipated failure modes and mitigations

| Mode | Mitigation |
|---|---|
| Probe attacks that create empty `/prs/<any>/<any>.git` dirs | Synthesise empty-repo response for fetches without creating disk state; zero-ref cleanup after receive-pack discards empty probes |
| Oversized pushes | None in v1; future config knob (`NGIT_GRASP06_MAX_BYTES_PER_REF`) |
| Spam PR events without pushes | Standard 30-min purgatory TTL drops them |
| Mismatched event vs push commits | Ref deleted on detection (same as standard endpoint `refs/nostr/` behaviour) |
| Concurrent pushes to same `(npub, id)` | git-receive-pack's file locking handles intra-repo concurrency; different repos are independent |
| Cross-endpoint double-push of same event | Both endpoints materialise the ref independently; second push validates via DB lookup of already-promoted event (no purgatory entry needed) |

## File touchpoints (informational)

The implementation plan details exactly what changes where. At a glance:

- New: `src/grasp06/` module (endpoint parsing, receive-pack handler, fetch synthesis, mirror).
- Modified: `src/http/mod.rs` (route `/prs/*` ahead of standard routing), `src/nostr/policy/pr_event.rs` (relaxation branch), `src/purgatory/types.rs` (optional placeholder scope field), `src/purgatory/mod.rs` (scope-aware placeholder lookup), `src/cleanup_empty_repos.rs` (skip `/prs/*`), `src/sync/*` (skip `/prs/*`), `src/config.rs` (new flag), `src/http/nip11.rs` (advertise GRASP-06).

See `plans/grasp-06-implementation-plan.md` for the sequenced work breakdown.

---

*Part of the [ngit-grasp explanation docs](./)*
