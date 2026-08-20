# Deploy in a Proxmox LXC container or VM

ngit-grasp has no kernel-virtualization or nested-container requirement. The
preferred Proxmox layout is an unprivileged Debian or Ubuntu LXC running the
static binary as a systemd service.

## Container requirements

- an unprivileged LXC or ordinary VM with systemd
- network access to public HTTPS and WebSocket relays
- inbound HTTP/HTTPS through the Proxmox network or an external proxy
- durable storage sized for Git repositories, LMDB, holding data, and backups

Docker nesting is not required for the direct binary path. Leave it disabled
unless using the Compose alternative below.

## Direct systemd path

Follow [Deploy a static binary with systemd](deploy-linux.md) inside the guest.
Keep `/var/lib/ngit-grasp` on storage included in the guest's snapshot and
backup policy.

When the Proxmox host bind-mounts a dataset into an unprivileged LXC, map its
ownership to the container's `ngit-grasp` UID/GID before starting the service.
Verify this from inside the container:

```bash
sudo -u ngit-grasp test -w /var/lib/ngit-grasp
sudo -u ngit-grasp git --version
```

Terminate TLS either inside the guest with Caddy or at an upstream proxy. If
the upstream proxy connects directly to ngit-grasp, add only that private
source address to `NGIT_TRUSTED_PROXY_CIDRS` and prevent other clients from
reaching port 7334.

## Compose alternative

If the guest already operates Docker or Podman, follow the
[Docker guide](deploy-docker.md). Docker inside LXC generally requires the
Proxmox nesting feature; the static binary path avoids that extra layer.

Do not mount the host Docker socket into the relay container. ngit-grasp needs
Git, not a container daemon.

## Backup and upgrade

For a simple consistent backup:

1. stop `ngit-grasp` inside the guest;
2. snapshot or back up the guest and its attached state storage;
3. start the service; and
4. verify the public endpoint.

Proxmox snapshots are not a substitute for an off-host backup. Before a
storage-changing upgrade, confirm that the state volume participates in the
snapshot and that the snapshot can be restored without starting a second
writer against the production domain.
