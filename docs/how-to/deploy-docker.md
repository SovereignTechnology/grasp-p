# Deploy with Docker or Podman

This is the portable default for a Linux host. The repository ships a
multi-stage `Dockerfile`, a loopback-only Compose service, and an optional
Caddy overlay for automatic HTTPS.

The image contains ngit-grasp, Git, CA certificates, and a small init process.
It prepares `/data` and then runs ngit-grasp as UID/GID `10001`.

Stable release images are published through Nostr, with their OCI blobs stored
on Blossom. Docker and Podman can pull them through the ncontainer gateway:

```bash
docker pull ncontainer.io/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp:latest
```

`latest` tracks the newest stable release. Replace it with an explicit release
version for a reproducible deployment. Release candidates are also published
under their prerelease channel, such as `rc`.

## Prerequisites

- Docker Engine with Compose v2, or a compatible Podman Compose setup
- durable local storage for the named volume
- a domain whose DNS points to the host
- ports 80 and 443 available when using bundled Caddy

Review the [deployment contract](../reference/deployment-contract.md) before
placing the state volume on remote or managed storage.

## Fresh VPS with automatic HTTPS

Create the small deployment environment file:

```bash
cp deploy.env.example .env
```

Set `NGIT_DOMAIN` in `.env`, then start the relay and Caddy:

```bash
export NGIT_IMAGE="ncontainer.io/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp:latest"
docker compose -f compose.yaml -f compose.caddy.yaml pull ngit-grasp
docker compose -f compose.yaml -f compose.caddy.yaml up --no-build -d
docker compose -f compose.yaml -f compose.caddy.yaml ps
scripts/verify-deployment.sh https://ngit.example.com
```

Caddy obtains and renews the certificate. The relay is also published on
`127.0.0.1:7334` for local diagnostics, but it is not directly reachable from
the network.

The bundled Caddy configuration serves ngit-grasp at the domain root. To share
a hostname using `NGIT_BASE_PATH`, use an existing reverse proxy and configure
its path routing explicitly.

## Existing reverse proxy

Start only the relay service:

```bash
export NGIT_IMAGE="ncontainer.io/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp:latest"
docker compose pull ngit-grasp
docker compose up --no-build -d
curl -H 'Accept: application/nostr+json' http://127.0.0.1:7334
```

To build a checked-out source revision instead, leave `NGIT_IMAGE` unset and
use `docker compose up --build -d` with the same Compose file selection.

Proxy the public HTTPS hostname to `http://127.0.0.1:7334`. Preserve WebSocket
upgrades, request methods, bodies, and query strings. Forwarded client IP
headers are ignored by default; configure `NGIT_TRUSTED_PROXY_CIDRS` only after
identifying the exact container-visible proxy address and keeping the backend
private.

## State and identity

The `ngit-grasp-data` named volume is mounted at `/data` and contains all
durable state. The first start creates `/data/.relay-owner.nsec`; retaining the
volume retains the public identity advertised in NIP-11.

Inspect the resolved volume without guessing its Compose prefix:

```bash
docker volume inspect ngit-grasp_ngit-grasp-data
```

Do not use `docker compose down --volumes` in production. It deletes the relay
identity, events, and Git repositories.

## Operations

```bash
# Logs
docker compose logs --follow ngit-grasp

# Controlled restart
docker compose restart ngit-grasp

# Stop while retaining state
docker compose stop

# Start again
docker compose start
```

When the Caddy overlay is active, include both `-f` arguments for commands that
must operate on the complete project.

## Backup

Stop the writer, archive the complete volume, and start it again:

```bash
docker compose stop ngit-grasp
docker run --rm \
  --volume ngit-grasp_ngit-grasp-data:/data:ro \
  --volume "$PWD:/backup" \
  alpine:3.22 \
  tar -czf /backup/ngit-grasp-data.tar.gz -C /data .
docker compose start ngit-grasp
```

Store the archive away from the Docker host. Test restoration into a separate,
non-public deployment before relying on it.

## Upgrade

Read `CHANGELOG.md`, take a backup, select an explicit release tag, and replace
the container without overlapping the old and new writers:

```bash
export NGIT_IMAGE="ncontainer.io/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit-grasp:3.0.2"
docker compose pull ngit-grasp
docker compose stop ngit-grasp
docker compose up --no-build -d ngit-grasp
scripts/verify-deployment.sh https://ngit.example.com
```

Replace `3.0.2` with the intended release. For a source-built deployment,
check out that tag and run `docker compose build --pull ngit-grasp` before
starting the service instead.

For storage-changing releases, follow the linked migration guide and restore
the pre-upgrade volume snapshot before attempting a binary rollback.

## Validate the image locally

The repository includes a destructive-to-test-resources-only integration
check. It builds the image, creates uniquely named temporary container and
volume resources, replaces the container, and confirms the NIP-11 pubkey did
not change:

```bash
scripts/test-container-deployment.sh
```

Set `CONTAINER_ENGINE=podman` to exercise a compatible Podman CLI.
