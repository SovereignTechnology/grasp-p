# Deploy a static binary with systemd

Use this path for a conventional Debian, Ubuntu, Fedora, or other systemd Linux
server when containers are unnecessary. Build the portable binary on a Nix
build machine, then copy only the binary and service files to the server.

## Build a pinned binary

From a clean checkout of the reviewed tag or revision:

```bash
nix build .#static
file result/bin/ngit-grasp
```

Copy `result/bin/ngit-grasp`, `deploy/systemd/ngit-grasp.service`, and
`deploy/systemd/ngit-grasp.env.example` to the server through your normal
authenticated deployment channel.

The deployment host does not need Nix or Rust. It does need Git and trusted CA
certificates:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates git
```

Use the equivalent packages on non-Debian distributions.

## Install

```bash
getent group ngit-grasp >/dev/null || sudo groupadd --system ngit-grasp
id -u ngit-grasp >/dev/null 2>&1 || \
  sudo useradd --system --gid ngit-grasp --home-dir /var/lib/ngit-grasp \
    --create-home --shell /usr/sbin/nologin ngit-grasp
sudo install -Dm755 ngit-grasp /usr/local/bin/ngit-grasp
sudo install -Dm644 ngit-grasp.service \
  /etc/systemd/system/ngit-grasp.service
sudo install -Dm640 -o root -g ngit-grasp ngit-grasp.env.example \
  /etc/ngit-grasp/ngit-grasp.env
sudo install -d -m 0750 -o ngit-grasp -g ngit-grasp \
  /var/lib/ngit-grasp \
  /var/lib/ngit-grasp/git \
  /var/lib/ngit-grasp/relay
```

Edit `/etc/ngit-grasp/ngit-grasp.env` and set `NGIT_DOMAIN`.

If restoring an existing identity, install `.relay-owner.nsec` as mode `0600`
owned by `ngit-grasp` under `/var/lib/ngit-grasp`. Otherwise the first start
generates it there.

## Reverse proxy and TLS

Keep the service bound to `127.0.0.1:7334`. For Caddy, a domain-root virtual
host is:

```caddyfile
ngit.example.com {
    reverse_proxy 127.0.0.1:7334
}
```

Point DNS at the server and replace `ngit.example.com` in both Caddy and the
ngit-grasp environment file. Caddy preserves WebSocket upgrades automatically.

## Start and verify

On the server:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ngit-grasp
sudo systemctl status ngit-grasp --no-pager
sudo journalctl -u ngit-grasp -n 50 --no-pager
```

From the repository checkout on the operator workstation:

```bash
scripts/verify-deployment.sh https://ngit.example.com
```

The service unit applies a restrictive umask, filesystem protection, private
temporary directory, empty capability set, and bounded five-minute shutdown.

## Upgrade and rollback

Build the new pinned binary before touching the server. Read `CHANGELOG.md`,
stop the service, snapshot `/var/lib/ngit-grasp`, install the new binary, and
start the service:

```bash
sudo systemctl stop ngit-grasp
sudo install -Dm755 ngit-grasp /usr/local/bin/ngit-grasp
sudo systemctl start ngit-grasp
```

Run the verifier and inspect startup integrity summaries. If the release
changed storage, restoring the old binary also requires restoring its matching
state snapshot.
