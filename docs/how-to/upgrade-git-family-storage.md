# Upgrade from v2 to v3 Git family storage

Version 3 replaces complete per-owner and `/prs/` bare repositories with thin
views backed by one local object family per repository identifier. The upgrade
requires no new configuration and runs automatically before the server accepts
traffic.

**Plan a maintenance window.** The relay does not serve HTTP or WebSocket
traffic until the storage migration finishes. The largest GRASP service
migrated so far spent 50 minutes 59 seconds in the storage migration, from
21:44:16 UTC until completion was logged at 22:35:14 UTC. The HTTP server began
listening about two seconds later, so total relay downtime was almost exactly
51 minutes. That run migrated 2,294 repository views into 2,014 identifier
families, retired 2,291 backups, and retained three for automatic integrity
repair. Treat this as a production scale reference rather than a fixed
estimate: migration time depends on the dataset and storage performance.

This is a one-way Git-data migration. A v2 binary does not understand the
family locking and write model and must not be run against a migrated
`NGIT_GIT_DATA_PATH`. Rolling back means restoring a complete pre-upgrade
snapshot, not only installing the older binary.

## Before upgrading

1. Schedule and announce a maintenance window during which the relay will not
   accept HTTP or WebSocket traffic.
2. Stop writes to the relay and take a filesystem snapshot of both the Git and
   relay data directories. Keep it for the rollback window.
3. Check free space on `NGIT_GIT_DATA_PATH`. Plan for the current footprint
   plus roughly one extra copy of the largest identifier family: every owner
   and `/prs/` repository sharing one identifier. The migration retires each
   healthy family's legacy repositories before processing the next family.
4. Keep Git and relay data on durable storage. Do not enable Git garbage
   collection for this rollout; retained objects preserve recovery from
   deletion-state mistakes.

## Upgrade

Deploy v3 with the existing configuration and start the relay. It remains
unavailable while the launch migration runs. The migration is journaled,
crash-safe, and safe to resume by restarting the same v3 release. It:

1. Builds and verifies one identifier family at a time, including unreachable
   objects retained for rollback.
2. Replaces each owner and `/prs/` repository with a thin view that preserves
   its refs, `HEAD`, configuration, and observable Git behavior.
3. Deletes a legacy backup only after its object superset, view wiring, packs,
   and ordinary family integrity report all verify.
4. Keeps any unhealthy family's backup while the running server automatically
   attempts repair from accepted clone URLs.

Progress is stored below `.grasp/migration/`; the completed layout is marked by
`.grasp/storage-version`. Do not edit these files while the service is running.
A later v3 restart sees that completed marker and does not repeat the offline
v2 conversion; the production-scale 51-minute cost applies to the first
v2-to-v3 migration, not every v3 deployment.

Confirm that the service reaches its normal listening state, then follow the
logs until both terminal integrity summaries appear:

```text
Git storage-integrity startup pass completed
Git authorization-integrity startup pass completed
```

For a release-candidate deployment, operators may temporarily limit both
startup passes to selected identifiers while validating runtime and log output:

```bash
NGIT_STARTUP_INTEGRITY_IDENTIFIERS=repo-one,repo-two
```

The equivalent NixOS option is
`startupIntegrityIdentifiers = [ "repo-one" "repo-two" ];`. A scoped summary
establishes integrity only for those names; it is not the v3 security sweep.
Remove the scope and observe a successful all-family pair of terminal summaries
before declaring the upgrade complete. The relay stays online during both
scoped and full passes.

Any service that enabled GRASP-06 on a tagged release through v2.1.2 should
treat its hosted Git repositories as potentially containing unauthorized
objects or refs until the full v3 integrity pass has completed and every
reported exception has been resolved. Conforming Nostr Git clients that resolve
refs from valid signed State, PR, and PR Update events are not expected to
accept this unauthorized data; direct Git consumers do not have that
protection. Passing a selected scope is useful validation evidence, but it does
not clear repositories that were not named.

These passes are non-blocking: the relay is online while they inspect and heal
the migrated views. In the storage summary, an `unresolved` or `failed` count
above zero has a corresponding `ERROR` naming the identifier. In the
authorization summary, a `manual_inspection` or `failed` count above zero has
a corresponding `ERROR` naming the exact view, ref, actual target, expected
target, and reason. The server has already attempted safe automatic repair.
It deliberately preserves unexplained `refs/nostr/*` and unknown-namespace
refs as evidence instead of guessing that deletion is safe.

The authorization pass treats the accepted event database as authoritative:

- the latest State event from the owner's confirmed maintainer set defines
  all and only `refs/heads/*`, `refs/tags/*`, and `HEAD`;
- accepted PR and PR Update events define `refs/nostr/<event-id>` in an owner
  view when either the confirmed-maintainer overlap selects that view or an
  exact standard clone URL names that owner and identifier on this service;
  foreign hosts, different coordinates, suffixes, and `/prs/` URLs do not
  authorize the owner view;
- a GRASP-06 contributor view additionally requires the event signer, clone
  URL, and repository identifier to match that exact `/prs/` coordinate;
- precisely scoped active purgatory entries are tolerated as in-flight state.
  Legacy unscoped placeholders are preserved but reported because they cannot
  prove which owner and identifier originally received the push.

To repeat both checks for one family without restarting the relay, queue a
check-only request first and inspect the two manual completion summaries:

```console
ngit-grasp integrity-check --identifier repo-one
ngit-grasp integrity-check --identifier repo-one --repair
```

Only the second command applies safe fixes. Re-run the check-only command after
repair; `repair_needed`, `manual_inspection`, and `failed` must all be zero for
that identifier to be considered clean.

A retained backup protects an unhealthy family's legacy data. A non-zero
`shallow_views` count identifies the marked depth-one fallback used only by a
seven-day untagged development interval; no tagged v1 or v2 release shipped
that behavior. Do not attribute an unmarked `missing_oids` result to that bug.
It means the incomplete graph predated the v3 conversion, but its exact origin
cannot be inferred from the missing object alone. Earlier manual copies or data
migrations, an incomplete source, and other legacy storage damage can have the
same result.

### Recover an unresolved object graph

Automatic repair can only use objects available from the accepted clone URLs.
If all announced servers inherited the same gap, ask a maintainer with a
known-complete local clone to run the following, substituting the OIDs from the
relay's `ERROR` log:

```bash
git fsck --full
git cat-file -e '<missing-oid>^{commit}'
git cat-file -e '<child-oid>^{commit}'
git cat-file -p '<child-oid>'
git update-ref refs/integrity-repair/<child-short-id> '<child-oid>'
git bundle create repository-integrity-repair.bundle \
  refs/integrity-repair/<child-short-id>
git update-ref -d refs/integrity-repair/<child-short-id>
git bundle verify repository-integrity-repair.bundle
sha256sum repository-integrity-repair.bundle
```

The `fsck` and both `cat-file` checks must succeed. Transfer the bundle and its
SHA-256 digest through agreed channels; an ordinary push or `ngit sync` may be
a no-op when the relay already advertises the authorized tip. Import the bundle
under a temporary ref, remove that ref after the objects are present, queue the
identifier with `--repair`, and finish with a check-only request. Do not delete
the retained migration backup until storage reports `unresolved=0` and
`failed=0`.

## Roll back

Stop v3 and restore the pre-upgrade Git and relay-data snapshot together before
starting v2. Do not point v2 at thin family views, even if ordinary clones
appear to work: v2 does not coordinate writes through the shared family or
preserve its durability invariants.

The storage model, legacy incomplete-history repair, and detailed retirement
guarantees are described in
[Identifier-family Git object storage](../explanation/git-family-object-storage.md#v2-to-v3-migration-boundary).
