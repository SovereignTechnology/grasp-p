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

Confirm that the service reaches its normal listening state, then check the
terminal integrity summary:

```text
Git identifier-family integrity startup pass completed
```

An `unresolved` or `failed` count above zero has a corresponding `ERROR` naming
the identifier. The server has already attempted automatic repair. A retained
backup protects an unhealthy family's legacy data, and a legacy shallow view
continues serving at its pre-upgrade level rather than being made less usable.

## Roll back

Stop v3 and restore the pre-upgrade Git and relay-data snapshot together before
starting v2. Do not point v2 at thin family views, even if ordinary clones
appear to work: v2 does not coordinate writes through the shared family or
preserve its durability invariants.

The storage model, automatic shallow-history compatibility repair, and detailed
retirement guarantees are described in
[Identifier-family Git object storage](../explanation/git-family-object-storage.md#v2-to-v3-migration-boundary).
