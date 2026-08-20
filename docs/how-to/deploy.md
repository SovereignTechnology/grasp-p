# Deploy ngit-grasp

ngit-grasp supports several single-instance production layouts. Choose the
guide matching the host you already operate; every guide implements the same
[deployment contract](../reference/deployment-contract.md).

| Environment | Start here | Supplied artifact |
| --- | --- | --- |
| Docker or Podman host | [Docker and Compose](deploy-docker.md) | `Dockerfile`, `compose.yaml`, optional Caddy overlay |
| NixOS | [NixOS module](deploy-nixos.md) | `nixosModules.default` |
| Debian, Ubuntu, or another systemd Linux | [Static binary and systemd](deploy-linux.md) | Static flake package and service unit |
| Proxmox LXC or VM | [Proxmox](deploy-proxmox-lxc.md) | Direct systemd or Compose path |
| Railway, Render, or Fly.io | [Managed hosting](deploy-paas.md) | Provider configuration templates |

For a fresh internet-facing VPS, the shortest supported path is Docker Compose
with the Caddy overlay:

```bash
cp deploy.env.example .env
# Set NGIT_DOMAIN in .env and point its DNS records at this server.
docker compose -f compose.yaml -f compose.caddy.yaml up --build -d
scripts/verify-deployment.sh https://ngit.example.com
```

The Caddy path requires ports 80 and 443. If the host already has a reverse
proxy, follow the loopback-only path in the Docker guide instead.

## Unsupported layouts

Do not deploy ngit-grasp to serverless functions, an ephemeral filesystem, or
multiple replicas. It owns long-lived WebSockets, background synchronization,
local Git repositories, LMDB state, and a durable relay identity.

Kubernetes can run the container as a one-replica StatefulSet with a
ReadWriteOnce volume, but the repository does not yet ship or promise a Helm
chart. A container host or systemd service is simpler unless Kubernetes is an
existing operational requirement.
