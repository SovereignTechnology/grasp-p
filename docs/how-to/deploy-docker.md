# Deploy with Docker or Podman

This is the portable default for a Linux host. The repository ships a
multi-stage `Dockerfile`, a loopback-only Compose service, and an optional
Caddy overlay for automatic HTTPS.

The image contains ngit-grasp, Git, CA certificates, and a small init process.
It prepares `/data` and then runs ngit-grasp as UID/GID `10001`.

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
docker compose -f compose.yaml -f compose.caddy.yaml up --build -d
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
docker compose up --build -d
curl -H 'Accept: application/nostr+json' http://127.0.0.1:7334
```

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

Pin or check out the intended tag, read `CHANGELOG.md`, take a backup, and
rebuild without overlapping the old and new writers:

```bash
docker compose stop ngit-grasp
docker compose build --pull ngit-grasp
docker compose up -d ngit-grasp
scripts/verify-deployment.sh https://ngit.example.com
```

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
