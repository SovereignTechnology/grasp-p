# Identifier-family Git object storage

**Status:** Accepted for implementation

**Date:** 2026-08-17

## Decision

ngit-grasp will store Git objects once per repository identifier and object
format, while continuing to expose a separate bare repository view for every
owner and every GRASP-06 contributor route.

The shared object inventory is always enabled. Its default durable backend is
the local filesystem. An S3-compatible backend is an explicit operator opt-in
that keeps repository views and metadata local, stores immutable packs in
object storage, and hydrates a bounded local cache on demand.

We deliberately do not garbage-collect Git objects in this change. Deleting or
rolling back a Nostr state changes which refs a view exposes; it does not remove
objects from the identifier family. This preserves the current ability to
recover from deletion-state mistakes and late rollback decisions.

## Context

The current layout creates a complete bare repository at both
`<npub>/<identifier>.git` and, when GRASP-06 is enabled,
`prs/<submitter>/<identifier>.git`. State and PR synchronization copy missing
objects between those repositories. Repositories with the same NIP-34 `d` tag
therefore store the same large blobs and history repeatedly.

That duplication has two costs:

- local installations consume space for every owner and contributor copy;
- the first push to an apparently empty `/prs/` or related owner route uploads
  history the service already possesses.

Buzz's Git-on-object-storage implementation demonstrates useful S3 mechanics:
create-only content-addressed packs, verified hydration, a local pack cache,
and publication only after durable writes. Its manifest is repository-scoped,
however, so byte-identical pack files deduplicate globally but independently
packed copies of the same Git objects do not. ngit-grasp instead needs a shared
semantic inventory at the identifier boundary.

## Goals

- Deduplicate objects across all local owner and `/prs/` views that share an
  identifier.
- Let receive-pack advertise already stored family history anonymously so a
  client does not resend it.
- Preserve the existing URL, authorization, ref, HEAD, purgatory, deletion,
  archive, and rollback semantics.
- Keep local storage as the zero-configuration default.
- Make S3-compatible storage opt-in and make a cache miss affect latency, not
  correctness.
- Upgrade existing installations automatically, idempotently, and before the
  server accepts traffic.

## Non-goals

- Reclaiming unreachable objects or old packs.
- Changing NIP-34 identifiers, repository URLs, or public ref names.
- Making one Git object family span independent ngit-grasp installations.
- Introducing a distributed writer lock or claiming multi-instance S3 writes
  in the first implementation.
- Converting archives and holding snapshots to S3 in the first implementation.
  Restores import their objects back into the family through the same write
  path.

## Model and terminology

A **coordinate** is an owner plus identifier, such as
`30617:<owner>:<identifier>`. A **view** is the small bare repository served at
that coordinate. A view owns only refs, `HEAD`, configuration, hooks if any,
and an alternate link; it does not own the shared object inventory.

A **family** is:

```text
(service storage root, Git object format, NIP-34 identifier)
```

The service storage root is an implicit tenant boundary. Object-format
separation prevents a future SHA-256 repository from being mixed with SHA-1
objects. Owner is intentionally absent: related owner announcements and
contributor submissions for the same identifier share objects.

An identifier collision means the service may reveal that it already has a
reachable object ID for another repository with that identifier. This is an
accepted GRASP storage and delivery trade-off. Authorization still determines
which named refs a client can see or update.

## Local layout

Existing public paths remain stable. Internal state lives below `.grasp`, which
normal repository scans must ignore:

```text
<git-data>/
  .grasp/
    storage-version
    migration/
    families/
      sha1/
        <identifier>.git/       # bare family inventory and internal refs
    s3-cache/                   # present only for the S3 backend
  <owner-npub>/
    <identifier>.git/           # thin view: refs + HEAD + alternate
  prs/
    <submitter-hex>/
      <identifier>.git/         # thin view: refs + HEAD + alternate
```

Identifiers are already constrained to one safe filesystem component. Family
path construction must reuse the same validation and must never accept an
unvalidated event tag as a path.

Each view's `objects/info/alternates` names its family's object directory. The
view config sets:

```ini
[core]
    alternateRefsPrefixes = refs/grasp/bases/
```

This limits anonymous receive-pack negotiation to current family base tips.
The family can retain additional history without advertising every retained
tip on every push.

## Ref ownership

Views keep all client-visible refs:

- `refs/heads/*` and `refs/tags/*` follow the authorized repository state;
- `refs/nostr/*` follows accepted or purgatory PR state;
- `HEAD` follows the authorized state for that owner.

The family repository uses internal refs only:

- `refs/grasp/bases/<digest>` records tips useful for receive negotiation;
- `refs/grasp/retained/<digest>` is append-only and records every accepted tip
  that must remain recoverable.

The suffix is derived from the ref name and object ID rather than user input.
Updating or deleting a view ref may update the base set, but must never delete
a retained ref in this phase.

## Why Git alternates solve the upload problem

Git receive-pack includes tips from alternate repositories as anonymous
`.have` entries. With a view's alternate pointing at the family repository, an
empty `/prs/` view can say “this object graph is already here” without
advertising another owner's `refs/heads/main`.

The service already opts into `uploadpack.allowReachableSHA1InWant` and the
related tip capability. Fetching a known reachable object from the family is
therefore also an accepted behavior. Named-ref visibility and push
authorization remain view-specific.

For local writes, receive-pack writes its quarantine and final objects into the
family object directory while it updates refs in the selected view. Other Git
commands that can create objects, including proactive fetch and archive
restore, must use the same family object directory. Read-only commands can use
the view normally because its alternate resolves the inventory.

## Durability and the success fence

The invariant is:

> When a client observes a successful push, every Git object needed by the
> accepted ref updates is durable in the configured family backend.

The local backend satisfies the fence when Git has atomically installed the
objects in the family object directory and receive-pack has completed.

The S3 backend cannot release receive-pack's terminal success immediately.
The handler must retain the final protocol status until it has:

1. indexed and verified the received objects;
2. written new immutable packs to S3 using create-only, content-addressed keys;
3. durably published the updated family manifest;
4. installed append-only retained roots and the intended view refs; and
5. fsynced the small local metadata needed to reconstruct the views.

Only then may the terminal success reach the client. A failure before the
fence returns a push error and leaves the previously published family manifest
and view refs authoritative. Staged packs may become harmless orphans; no old
pack is deleted.

## S3 backend

S3 stores immutable data; local disk remains the execution surface for Git:

```text
packs/<object-format>/<sha256(pack-bytes)>
indexes/<object-format>/<sha256(pack-bytes)>
manifests/<object-format>/<sha256(canonical-manifest)>
families/<object-format>/<encoded-identifier>/pointer
```

A canonical manifest contains its schema version, object format, identifier,
complete pack-key set, and parent manifest digest. The mutable family pointer
names the current immutable manifest. Initial implementation permits one
ngit-grasp writer per storage root; conditional pointer writes are still used
to detect an accidental second writer rather than silently losing an update.

Hydration resolves pointer to manifest, verifies every downloaded pack against
its key digest, installs or regenerates its index, and links the pack/index
pair into the local family object directory. Cache entries are immutable,
byte-bounded, and pinned for the lifetime of the Git request. Eviction may make
the next request slower but cannot remove durable data.

S3 lifecycle rules must not expire `packs/`, `indexes/`, `manifests/`, or
family pointers. Garbage collection requires a separate design that accounts
for rollback roots, old manifests, in-flight hydrations, and archives.

## No-GC recovery invariant

Until explicit garbage collection is designed and approved:

> A family's durable inventory contains every Git object ever accepted for
> that family by this service.

Consequences:

- disable automatic Git maintenance and pruning for family repositories;
- create retained roots for every accepted branch, tag, and PR tip;
- do not use S3 lifecycle deletion on family objects;
- never compact by packing only the current visible ref closure;
- if pack-count compaction becomes necessary, repack the union of every object
  in all selected packs, publish the replacement in addition to the old
  immutable packs, and leave physical deletion to future GC work.

This intentionally spends storage to preserve rollback choices. Deduplication
still removes the much larger multiplier caused by owner and `/prs/` copies.

## `/prs/` behavior

A missing `/prs/<submitter>/<identifier>.git` route is no longer synthesized
from a truly empty temporary repository. It is synthesized as an empty thin
view whose alternate is the identifier family. Therefore:

- upload-pack still advertises no named refs for a missing route;
- receive-pack may advertise family base tips as anonymous `.have` lines;
- the first contributor push sends only objects the family does not have;
- pushes remain restricted to `refs/nostr/<event-id>`;
- placeholder and expiry cleanup removes view refs or an empty view, never
  family objects or retained roots.

Mirroring a PR into an owner view becomes a ref update after an object
availability check. It no longer copies the object graph.

## V2 to v3 migration boundary

V3 changes the on-disk meaning of every served Git repository. Owner and
`/prs/` paths become thin views whose objects and write serialization belong to
the identifier family under `.grasp`. Migration happens automatically on the
first v3 launch, but the result is not safe for v2: v2 has no family lock,
retained-root, or shared-object write model. A software rollback therefore
requires restoring the Git and relay-data snapshot taken before v3; changing
only the binary is not supported.

V3 can encounter an object graph which was already incomplete in legacy
storage. Migration copies every Git-readable object and preserves the backup;
it does not manufacture a missing ancestor or infer its provenance. Earlier
manual copies or data migrations, an incomplete source repository, and other
pre-existing storage damage can all produce the same unmarked symptom. The
integrity report therefore describes the evidence (`missing_oids`, broken
links, and `shallow_views`) rather than assigning a cause from a missing object
alone.

One known and narrower source has an unambiguous marker. State Git-data fallback
was introduced by commit `623cae5` on 2026-01-05 with
`git fetch --depth=1`, carried into the rewritten purgatory sync path, and
changed to a full fetch by commit `f25eea8` on 2026-01-12. The first tagged
release was v1.0.0 on 2026-02-26 and already contained the fix, so no tagged v1
or v2 release shipped the shallow-fetch behavior. Only operators who deployed
an untagged source revision from that seven-day interval can have repositories
created by this bug. The affected fallback ran only when a pending State or PR
event named OIDs which had not arrived through an ordinary push.

V3 treats that legacy `shallow` marker as compatibility state rather than a
reason to delete or disable the repository. Migration preserves the marker on
the thin view and retains the legacy backup. After the listener starts, the
ordinary integrity worker requests the complete closure from other accepted
clone servers. On success it removes the marker; the next v3 launch retires the
now-redundant backup. On failure the existing shallow repository and backup
remain, and an `ERROR` identifies the family with a non-zero `shallow_views`
count.

An incomplete graph with `shallow_views=0` is a different case. V3 still tries
every accepted clone source, but all listed servers may share the same missing
history or the complete source may no longer be announced. Such a family stays
unresolved until an operator obtains the missing closure from a known-complete
maintainer clone or bundle. Matching a signed State event is not enough to
prove this closure: State authorizes ref tips, while storage integrity also
checks every object reachable behind those tips.

## Startup migration

Migration runs after configuration validation and before purgatory restoration,
deletion reconciliation, background sync, or accepting HTTP connections. It is
versioned, exclusive, crash-safe, and idempotent.

For each legacy bare repository:

1. Classify the path as an owner view, `/prs/` view, archive/holding data, or
   internal data. Only owner and `/prs/` views migrate in this version.
2. Discover the object format and identifier; create the family inventory if
   absent with automatic maintenance disabled.
3. Copy every legacy object—including objects not currently reachable from a
   visible ref—into a staging family inventory. Copying the entire object
   database, not only `rev-list --all`, preserves rollback material.
4. Record every legacy ref tip as an append-only retained root and useful tips
   as base roots.
5. Verify with `git fsck`, verify every legacy object ID exists in the family,
   and verify the proposed view's refs and `HEAD` exactly match the legacy
   repository.
6. Write and fsync a per-repository migration journal entry.
7. Atomically rename the legacy repository to a migration backup, atomically
   install the thin view, then mark that journal entry complete.

On restart, the journal determines whether to resume copying, finish a rename,
or restore the legacy directory. Every state transition is safe to repeat.

Backups are retired family by family rather than accumulating until the whole
migration finishes. After the last view of a family is installed, each of its
backups must pass a retirement gate: the family contains every Git-readable
object of the backup, every affected view is a correctly wired thin view whose
refs and `HEAD` match its journal snapshot, and every family pack is indexed
and passes `git verify-pack`. The ordinary family integrity inspection must
also report the family and all of its views healthy. This final check catches
corrupt loose objects, missing history, broken ref targets, invalid alternates,
and shallow views. An unhealthy family keeps its backups while the non-blocking
integrity worker attempts repair after startup. Only a healthy family writes a
durable `retired` journal state, deletes the backup, and removes the journal
before the next family is migrated. Peak migration overhead is therefore
bounded by the family currently in flight except for the small set of families
still awaiting repair.

Backup deletion is itself durable: every directory entry removed while
deleting and pruning a backup is fsynced before its journal is removed. A
power loss therefore leaves either a discoverable `retired` journal that
finishes deletion or no backup entry to rediscover.

Packs without an index are Git-invisible, so the superset proof cannot vouch
for them; they are moved into content-addressed directories beneath
`.grasp/migration/unindexed-packs/` before their backup is deleted. Repeated
migrations preserve different payloads even when their original pack filenames
match, while an identical payload converges on the same quarantine path.

A server-side `shallow` marker is a compatibility boundary, not valid final
family storage. Migration copies it onto the installed thin view so the view
keeps serving exactly what the legacy repository served, and excludes its
backup from retirement until the family holds the complete reachable closure
of the backup's refs. Closure recovery is the ordinary integrity repair: the
family reports truncated parents as missing objects and marked views as
`shallow_views`, repair fetches the closure from accepted clone sources, and
once complete removes the marker. The backup retires on the next launch. An
unrecoverable closure retains both marker and backup and keeps the family
reported as unresolved; it never blocks startup because recovery depends on
remote servers. Client-requested shallow clones and fetches remain supported
throughout.

Retirement failures during an active migration are fail-closed and keep the
backup. Journals from a migration that already committed are handled
leniently on later launches: their ref snapshots are stale once the server
has served traffic, so the gate skips snapshot equality, and an unverifiable
backup (for example one whose migrated view was later deleted by repository
lifecycle) is retained with a warning as operator-managed rollback material.
Installations whose backups were verified and deleted manually simply have
their completed journals removed.

The global `storage-version` advances only after every eligible repository is
complete. A server must fail startup on an unrepairable mismatch rather than
serve a partially converted storage root.

Fresh installations create the current version marker and family layout on
their first launch. Switching from local to S3 is a separate backend migration:
upload and verify all local family inventories first, then change the backend
marker. It must never reinterpret an absent S3 pointer as an empty family when
local objects exist.

## Concurrency

Operations that mutate one family are serialized by a per-family lock. This
covers pushes to different owner or `/prs/` views with the same identifier,
proactive fetches, archive restores, retained/base ref updates, and S3 manifest
publication. Read requests take a hydrated family lease; they do not hold the
writer lock after their pack set has been pinned.

View lifecycle locks remain responsible for “may this path be removed?” The
family lock is responsible for “is this object inventory and manifest update
atomic?” Neither lock grants authorization.

## Storage and authorization integrity

Storage integrity is defined for an object-format/identifier family, not for
one owner path. The storage pass checks the family pack set and object graph,
then checks every owner and `/prs/` view with the same identifier for the
correct alternate and for refs whose targets are available in the family.
Multiple independent histories in one identifier are valid, and unreachable
objects are not an error: retained delete-state and rollback data intentionally
remain present.

The relay starts one non-blocking pass after migration, database
initialization, and construction of the hardened outbound Git client. Broken
alternate wiring is repaired locally. For missing OIDs, the pass tries clone
URLs from accepted repository announcements, excluding this service and
applying the same SSRF policy, DNS pinning, credentials, process containment,
and missing-OID behavior used by proactive sync. It then runs the same
integrity check again. An unresolved family produces an `ERROR` log containing
bounded counts and OID/diagnostic samples; it does not make availability depend
on remote servers.

Authorization integrity is the second, view-scoped layer. It derives each
owner view's branch, tag, and `HEAD` set from the NIP-01-preferred accepted
State event published by the confirmed maintainer component resolved from
that selected owner coordinate. It derives
`refs/nostr/<event-id>` from accepted PR and PR Update events when the same
confirmed-maintainer overlap as normal event processing selects the view, or
when an exact standard clone URL names that owner and identifier on this
service. Foreign hosts, different coordinates, URL suffixes, and `/prs/` URLs
cannot authorize a standard owner view. GRASP-06 views separately require the
signer and this relay's clone URL to name that exact submitter/identifier
coordinate. Exactly scoped active purgatory entries are recognized so an
in-flight push is not mistaken for corruption.

The pass creates or updates missing/wrong authorized refs once their objects
are available, deletes stale State-governed branch and tag refs, and repairs
`HEAD`. Before giving up on a missing expected object it uses the same accepted
clone URLs and hardened fetch path as storage healing. It does not delete an
unexplained PR or unknown-namespace ref: that ref may be evidence of a past
authorization bypass. Instead it emits a bounded, structured `ERROR` with
`manual_inspection=true`, the view and ref, and actual/expected targets. An
authorized State still in purgatory also defers State mutation and is reported
for inspection rather than racing event promotion.

Both startup passes run in the background after database initialization. By
default they cover every installed identifier family. A temporary
`NGIT_STARTUP_INTEGRITY_IDENTIFIERS` scope can limit both passes to named
families during staged release-candidate validation; an empty scope is required
for the final full sweep. The passes do not extend the offline migration window
or make relay availability depend on a remote Git server. Their stable terminal
log messages are `Git
storage-integrity startup pass completed` and `Git authorization-integrity
startup pass completed`. Because the authorization pass is online, it refreshes
the accepted events immediately before mutation and refuses to overwrite any
ref that changed after its initial snapshot.

This is also the migration repair path. Migration remains a deterministic,
offline conversion that preserves every Git-readable object and the exact
legacy refs. Once those paths are thin family views, the ordinary family pass
can heal pre-existing missing objects. Unindexed legacy packs are preserved
under `.grasp/migration/unindexed-packs/` when their backup is retired; there
is no separate legacy repair subsystem.

Operators can queue an identifier-scoped storage and event-authorization check
in the live process:

```console
ngit-grasp integrity-check --identifier example
ngit-grasp integrity-check --identifier example --repair
```

Without `--repair`, the command reports structural faults, ref differences,
and manual-inspection findings without changing objects, refs, or `HEAD`. With
`--repair`, it also heals storage from accepted clone sources and applies the
same unambiguous State/PR/PR-Update ref fixes as the startup pass. Unexplained
PR refs remain preserved in both modes. The command writes a durable request
beneath `.grasp/integrity-requests/`. The server consumes it while holding its
normal in-process family locks, so a manual repair cannot race an
object-producing request in another view. Completion is reported separately as
`Manual Git storage-integrity request completed` and `Manual Git
authorization-integrity request completed` with the identifier and repair mode.

## Security and privacy trade-offs

- Sharing is restricted to one validated identifier, object format, and
  service storage root. It is not a process-global object pool.
- Anonymous `.have` entries disclose object IDs already useful to the family.
  The user has explicitly accepted this in exchange for avoiding duplicate
  uploads.
- `allowReachableSHA1InWant` can deliver a known object reachable through a
  related repository's family inventory. This is also explicitly accepted.
- Clients still cannot enumerate another view's named refs through their own
  URL. Upload-pack materializes only the selected view's refs and HEAD.
- S3 credentials and bucket details are operator secrets/configuration and
  must not be written into manifests, logs, or Nostr events.

## Rejected alternatives

### Keep full per-owner repositories and run periodic repack

Alternates would still be absent during the first push, so bandwidth remains
duplicated. Cross-repository repack also has no natural safe deletion rule while
rollback recovery is open.

### One global object pool

This maximizes deduplication but turns any known object ID on the service into
a cross-repository reachability surface. Identifier families give the desired
related-repository behavior with a smaller disclosure and failure domain.

### Repository-scoped S3 manifests only

This follows Buzz closely but deduplicates only byte-identical packs. Two packs
containing the same large blob may have different bytes and keys, so the main
ngit-grasp duplication remains.

### Partial clone or LFS

Both require client/repository participation and change repository semantics.
The service must deduplicate ordinary Git repositories transparently.

### Garbage-collect unreachable objects during migration

This would reduce the migration footprint but discard exactly the history used
for rollback after delete-state events. It is deferred until rollback retention
and physical deletion have an explicit policy.

## Delivery sequence

The implementation is intentionally reviewable as a local-first stack:

1. this decision and its invariants;
2. family paths, local inventory, thin-view construction, and Git-level tests;
3. standard and `/prs/` handler integration plus ref-only synchronization;
4. launch-time legacy migration, restart recovery, and operator documentation;
5. one optional S3 layer containing manifests, verified hydration, cache,
   local-family adoption, configuration, and the durability fence.

Steps 3 and 4 ship together as the first deployable local-storage milestone.
It can be operated and observed before the S3 layer is considered. Every layer
retains the public repository layout, and S3 never changes the default from
local storage.
