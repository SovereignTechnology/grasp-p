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
   relay data directories. An older binary cannot serve the new thin views,
   and legacy backups are retired during migration, so this external snapshot
   is the rollback boundary for the release.
2. Check free space on `NGIT_GIT_DATA_PATH`. Migration processes one
   identifier family at a time and retires that family's legacy backups after
   verification before starting the next family. Plan for the current
   footprint plus roughly one extra copy of the largest identifier family
   (all owner and `/prs/` repositories sharing one identifier), not the whole
   dataset. Deduplication reduces the final family size but should not be
   assumed for preflight capacity planning.
3. Keep Git and relay data on durable storage.
4. Do not configure Git GC for this rollout. Unreachable objects intentionally
   preserve delete-state rollback material inside each family.

## Perform the upgrade

Deploy the new release with the existing configuration and start the relay.
For every identifier, launch migration inventories all objects from all
matching owner and `/prs/` paths, including unreachable objects, verifies the
union, then atomically replaces each repository with a thin view. While a
family converts, its original repositories are held under:

```text
<git-data>/.grasp/migration/backups/
```

Once every view of a family is installed, each of that family's backups is
verified — every Git-readable backup object present in the family, the thin
views wired and matching their journal snapshot, and every family pack
indexed and valid — and the ordinary family integrity report must be healthy.
Only then is the backup deleted before the next family is migrated. Peak
migration overhead is therefore bounded by the family currently in flight,
apart from families retained for automatic repair. A pack without an index is
invisible to Git and cannot be vouched for by that verification; such packs
are preserved by content under `.grasp/migration/unindexed-packs/` for manual
`git index-pack` recovery.

Progress and restart state live under `.grasp/migration/journal/`; each
journal is removed after its backup retires. The global
`.grasp/storage-version` marker is written only after every eligible view has
been reconciled and verified. Do not edit these files while the service is
running.

Confirm the service reaches its normal listening state and exercise a clone,
fetch, and push for both a normal repository and a `/prs/` route. Retain the
external pre-upgrade snapshot for the rollback window; the retired migration
backups are gone once their family verifies.

A legacy repository carrying a server-side `shallow` marker is a deliberate
truncation and is not valid family storage. Migration installs its thin view
with the marker intact, so clients keep seeing exactly what the legacy
repository served, and retains its backup with an `ERROR` log naming the
unresolved family. The integrity pass then tries to fetch the complete
reachable closure from accepted clone sources; once the family is complete, a
later launch removes the marker and retires the backup. If the closure cannot
be recovered, the backup stays and the family keeps being reported as
unresolved. Shallow clones and fetches requested by clients are unaffected
and remain supported.

Installations that migrated under a release which kept backups indefinitely
retire them on the next launch after the same verification, except that the
stale journal ref snapshot is no longer enforced against views whose refs
have legitimately changed in service. A backup that cannot be verified — for
example its migrated view was later deleted by repository lifecycle, or the
family cannot prove it contains every backup object — is kept with a warning
and remains operator-managed. Installations whose backups were already
verified and deleted manually start normally; their completed journals are
compacted away.

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

- A migration or backup-retirement failure during an active migration is
  fail-closed: the family's legacy backup is kept, startup stops, and a
  restart resumes from the fsynced journal. A backup is never deleted before
  its family verifies.
- Pre-existing damage does not block retirement. An object that was already
  absent from the legacy repository cannot be preserved by keeping its backup,
  so retirement proceeds; the condition stays visible through the integrity
  startup pass and `integrity-check --repair`.
- A post-migration integrity repair failure is fail-open because the damage
  predates conversion or arose after it. Inspect the identifier's `ERROR` log,
  repair or update its listed clone sources, and queue `integrity-check
  --repair` again.
- To roll the software release back, stop the service and restore the complete
  pre-upgrade Git and relay-data snapshot together. Do not point an older
  binary at migrated thin views.

Backup retirement only removes verified legacy copies. Unreachable-object
pruning inside families remains deferred until rollback and delete-state
retention have an explicit policy. S3 adoption is a separate optional rollout
and is not required for this local storage model.
