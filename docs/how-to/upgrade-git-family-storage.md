# Upgrade a server to identifier-family Git storage

This procedure upgrades existing owner repositories and `/prs/` repositories
to ref-only views backed by one local object family per repository identifier.
It requires no new configuration and keeps all durable Git storage local.

The upgrader runs automatically on every relay launch after configuration has
been validated and before purgatory restoration, background sync, or HTTP
request handling. A failed migration stops startup; restarting resumes from its
fsynced journal.

## Before deploying

1. Stop writes to the relay and take a filesystem snapshot of both the Git and
   relay data directories. An older binary cannot serve the new thin views, so
   this external snapshot is the clean release-level rollback boundary.
2. Check free space on `NGIT_GIT_DATA_PATH`. During the first launch the server
   retains every original repository and builds a verified family union. Plan
   for at least the current owner and `/prs/` repository footprint again, plus
   room for the largest identifier family. Deduplication reduces the final
   family size but should not be assumed for preflight capacity planning.
3. Keep Git and relay data on durable storage.
4. Do not configure Git GC for this rollout. Unreachable objects and migration
   backups intentionally preserve delete-state rollback material.

## Perform the upgrade

Deploy the new release with the existing configuration and start the relay.
For every identifier, launch migration inventories all objects from all
matching owner and `/prs/` paths, including unreachable objects, verifies the
union, then atomically replaces each repository with a thin view. Original
repositories move to:

```text
<git-data>/.grasp/migration/backups/
```

Progress and restart state live under `.grasp/migration/journal/`. The global
`.grasp/storage-version` marker is written only after every eligible view has
been reconciled and verified. Do not edit these files while the service is
running.

Confirm the service reaches its normal listening state and exercise a clone,
fetch, and push for both a normal repository and a `/prs/` route. Retain the
external snapshot and `.grasp/migration/backups/` for the rollback window. The
server never deletes those backups automatically.

## Failure and rollback

- A migration failure is fail-closed. Fix the reported filesystem or Git error
  and restart; the journal resumes the safe transition.
- To roll the software release back, stop the service and restore the complete
  pre-upgrade Git and relay-data snapshot together. Do not point an older
  binary at migrated thin views.

There is deliberately no automatic cleanup step. Backup retirement and
unreachable-object pruning remain deferred until rollback and delete-state
retention have an explicit policy. S3 adoption is a separate optional rollout
and is not required for this local storage model.
