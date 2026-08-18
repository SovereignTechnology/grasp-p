# Upgrade a server to identifier-family Git storage

This procedure upgrades existing owner repositories and `/prs/` repositories
to ref-only views backed by one local object family per repository identifier.
It requires no new configuration and keeps all durable Git storage local.

The upgrader runs automatically on every relay launch after configuration has
been validated and before purgatory restoration, background sync, or HTTP
request handling. A failed migration stops startup; restarting resumes from its
fsynced journal.

After runtime database initialization, a non-blocking integrity pass checks
the resulting identifier families and views. It attempts to fetch missing
objects from clone URLs in accepted repository announcements and emits an
`ERROR` log for any family that remains unhealthy. Network repair never holds
up the listening service or changes whether the structural migration commits.

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

Watch for the terminal startup-pass summary:

```text
Git identifier-family integrity startup pass completed
```

An `unresolved` or `failed` count above zero is accompanied by an `ERROR` log
for each affected identifier. This reports pre-existing missing data without
putting startup into a network-dependent restart loop.

## Check or repair one identifier on demand

Queue a read-only check for every object format and owner/`/prs/` view sharing
an identifier:

```console
ngit-grasp integrity-check \
  --git-data-path /var/lib/ngit-grasp/git \
  --identifier example
```

Add `--repair` to repair alternate wiring and try accepted clone servers for
missing OIDs:

```console
ngit-grasp integrity-check \
  --git-data-path /var/lib/ngit-grasp/git \
  --identifier example \
  --repair
```

The command queues a durable request for the running relay rather than opening
or mutating a family from a second process. The worker normally consumes it
within five seconds and writes the result to the service log. A request queued
while the relay is stopped is processed after its next startup integrity pass.
Repeated requests for the same identifier and mode safely coalesce.

## Failure and rollback

- A migration failure is fail-closed. Fix the reported filesystem or Git error
  and restart; the journal resumes the safe transition.
- A post-migration integrity repair failure is fail-open because the damage
  predates conversion or arose after it. Inspect the identifier's `ERROR` log,
  repair or update its listed clone sources, and queue `integrity-check
  --repair` again.
- To roll the software release back, stop the service and restore the complete
  pre-upgrade Git and relay-data snapshot together. Do not point an older
  binary at migrated thin views.

There is deliberately no automatic cleanup step. Backup retirement and
unreachable-object pruning remain deferred until rollback and delete-state
retention have an explicit policy. S3 adoption is a separate optional rollout
and is not required for this local storage model.
