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

Any service that enabled GRASP-06 on a tagged release through v2.1.2 must treat
its hosted repositories as potentially compromised until the full pass has
completed and every reported exception has been resolved. Passing a selected
scope is useful validation evidence, but it does not clear repositories that
were not named.

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
- accepted PR and PR Update events define `refs/nostr/<event-id>` in every
  owner view selected by the existing maintainer-overlap rules;
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

A retained backup protects an unhealthy family's legacy data, and a legacy
shallow view continues serving at its pre-upgrade level rather than being made
less usable.

## Roll back

Stop v3 and restore the pre-upgrade Git and relay-data snapshot together before
starting v2. Do not point v2 at thin family views, even if ordinary clones
appear to work: v2 does not coordinate writes through the shared family or
preserve its durability invariants.

The storage model, automatic shallow-history compatibility repair, and detailed
retirement guarantees are described in
[Identifier-family Git object storage](../explanation/git-family-object-storage.md#v2-to-v3-migration-boundary).
