# Deployment contract

This reference defines the runtime assumptions shared by every supported
ngit-grasp deployment. Environment-specific guides should provide these
properties rather than inventing a different layout.

## Process

ngit-grasp is one long-running process. It serves Git Smart HTTP, Nostr
WebSockets, NIP-11, landing pages, and Prometheus metrics from one HTTP port.
The process must:

- have `git` and trusted CA certificates available at runtime;
- receive `SIGTERM` during a controlled stop;
- have enough shutdown time to persist state and clean up temporary refs; and
- run as a non-root user after writable storage has been prepared.

## Required configuration

`NGIT_DOMAIN` is the only required application setting. It is the canonical
public hostname, without a URL scheme or path:

```text
NGIT_DOMAIN=ngit.example.com
```

When the relay is mounted below a shared hostname, set `NGIT_BASE_PATH` to the
public path. Otherwise keep the default `/`.

The listener defaults to `127.0.0.1:7334`. A container or managed platform must
override it to an externally reachable container address. The supplied image
does this automatically, using `0.0.0.0:${PORT}` when the platform provides
`PORT` and `0.0.0.0:7334` otherwise.

See the [configuration reference](configuration.md) for optional policy,
sync, curation, resource-limit, and private-service settings.

## Public endpoint

The public endpoint must preserve HTTP methods, request bodies, query strings,
and WebSocket upgrades. TLS normally terminates at Caddy, nginx, an ingress,
or the hosting platform.

Configure `NGIT_TRUSTED_PROXY_CIDRS` only when all of the following are true:

- the backend is unreachable except through the named proxies;
- the proxy overwrites or safely appends forwarding headers; and
- every trusted hop is represented by an exact address or narrow CIDR.

Leaving the setting empty is safe. The relay then ignores forwarding headers
and records the proxy address instead of the original client address.

## Durable state

Every production deployment must persist these three items together:

| Path | Contents |
| --- | --- |
| `.relay-owner.nsec` | Generated relay identity, unless an external credential supplies it |
| `git/` | Git object families, repository views, holding data, and maintenance queues |
| `relay/` | LMDB relay events, lifecycle metadata, cursors, and rejected-event state |

The container contract places them below `/data`:

```text
/data/.relay-owner.nsec
/data/git/
/data/relay/
```

The NixOS and generic systemd deployments use the same relative layout below
their configured state directory.

Back up the entire state directory from one point in time. A simple portable
backup should stop the service first; a storage-level snapshot may instead
quiesce or atomically snapshot the filesystem. A backup that omits the owner
key changes the relay identity on restore. A backup that captures Git and LMDB
at unrelated times can restore an inconsistent authorization view.

## One writer

An ngit-grasp state directory has exactly one writer. Do not:

- run multiple replicas against one filesystem or network volume;
- attach independent local volumes to replicas and load-balance between them;
- use rolling or blue/green replacement that overlaps two writers; or
- scale the service to zero when that can discard or detach its durable volume.

Run one instance and scale it vertically. Separate instances are supported
only when each has its own domain, relay identity, and state directory.

## Identity and secrets

The default is intentionally low ceremony: on first start, ngit-grasp creates
`.relay-owner.nsec` with mode `0600` in its working directory and reuses it on
later starts. Protect and back up that file.

To supply an existing identity:

- use the `relay_owner_nsec` systemd credential where available;
- mount `.relay-owner.nsec` into the persistent state directory; or
- as a less preferred container fallback, use the
  `NGIT_RELAY_OWNER_NSEC` secret environment variable.

Never put an nsec in a command-line argument, image, Compose file, Nix store,
checked-in environment file, or hosting template.

## Health and verification

The HTTP listener starts only after configuration validation, storage
initialization, migrations, and startup integrity work. Until a dedicated
health route exists, platform health checks should request the configured base
path and accept any `2xx` response.

After deployment, run:

```bash
scripts/verify-deployment.sh https://ngit.example.com
```

The verifier checks NIP-11, an HTTP/1.1 WebSocket upgrade, and Prometheus
metrics with bounded network deadlines. Set `VERIFY_METRICS=false` only when
metrics were deliberately disabled.

## Upgrade and rollback

Pin deployments to a reviewed tag or revision. Before changing versions:

1. read `CHANGELOG.md` and any linked migration guide;
2. take a restorable snapshot of the complete state directory;
3. stop the old writer before starting the new one;
4. wait for startup migrations and integrity summaries; and
5. run the deployment verifier.

A binary or image rollback is not necessarily a data rollback. When a release
changes storage, restore the matching pre-upgrade state snapshot before
starting the older version. The
[Git family storage upgrade guide](../how-to/upgrade-git-family-storage.md)
documents the current one-way migration boundary.
