# How-To: Deploy ngit-grasp to Production

**Purpose:** Deploy ngit-grasp to a production NixOS server  
**Difficulty:** Intermediate  
**Time:** 30-60 minutes

---

## Problem

You want to:
- Deploy ngit-grasp to a NixOS server
- Configure it as a systemd service
- Set up reverse proxy (Caddy)
- Ensure proper security and monitoring

---

## Prerequisites

- NixOS server with SSH access
- Flakes enabled on server and local machine
- Domain name configured (DNS pointing to server)
- Basic knowledge of NixOS configuration

---

## Solution

### Step 1: Add ngit-grasp to Your Server's Flake

In your server's `flake.nix`, add ngit-grasp as an input:

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
    ngit-grasp.url = "github:DanConwayDev/ngit-grasp";
    # or use a specific git repository:
    # ngit-grasp.url = "git+https://git.shakespeare.diy/npub.../ngit-grasp.git";
  };

  outputs = { self, nixpkgs, ngit-grasp, ... }@inputs: {
    nixosConfigurations.your-hostname = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      specialArgs = { inherit inputs; };
      modules = [
        ./configuration.nix
        # ... other modules
      ];
    };
  };
}
```

---

### Step 2: Create Service Configuration

Create a new file for your ngit-grasp service (e.g., `services/ngit-grasp.nix`):

```nix
{ inputs, ... }:

{
  imports = [ inputs.ngit-grasp.nixosModules.default ];

  services.ngit-grasp.production = {
    enable = true;
    domain = "ngit.example.com";
    
    # Network
    bindAddress = "127.0.0.1";
    port = 8082;
    
    # Storage
    dataDir = "/persistent/ngit-grasp";
    
    # Identity
    relayName = "My GRASP Relay";
    relayDescription = "A Rust GRASP implementation with proactive sync";
    relayOwnerNsecFile = "/run/agenix/ngit-grasp-relay-owner-nsec";
    
    # Sync - bootstrap from relay.ngit.dev
    syncBootstrapRelayUrl = "wss://relay.ngit.dev";
    
    # Metrics
    metricsEnabled = true;
    
    # Logging
    logLevel = "info";
  };

  # Caddy reverse proxy
  services.caddy.virtualHosts."ngit.example.com" = {
    extraConfig = ''
      reverse_proxy 127.0.0.1:8082 {
        header_down X-Real-IP {http.request.remote}
        header_down X-Forwarded-For {http.request.remote}
      }
    '';
  };
}
```

**Key configuration options:**

- **Instance name** (`production`): Can be any name. Used for systemd service (`ngit-grasp-production`)
- **domain**: Your relay's domain (used in GRASP validation)
- **port**: Local port (use reverse proxy for HTTPS)
- **dataDir**: Where git repos and database are stored
- **relayOwnerNsecFile**: Path to file containing relay owner's nsec
  - Passed to ngit-grasp as a protected systemd credential, not a process argument
  - The runtime secret file must already exist (for example through agenix or sops-nix)
  - Permissions on that external source file remain the operator or secret manager's responsibility
  - Alternative: `relayOwnerNsec = "nsec1..."` (less secure, in nix store)
  - If neither option is set, ngit-grasp loads or creates `.relay-owner.nsec` in `dataDir`
- **syncBootstrapRelayUrl**: Bootstrap relay to sync from on startup

See [nix/example-configuration.nix](../../nix/example-configuration.nix) for more examples.

---

### Step 3: Import the Service

Import your service configuration in your main configuration file:

```nix
# In configuration.nix or services/default.nix
{
  imports = [
    ./services/ngit-grasp.nix
    # ... other services
  ];
}
```

---

### Step 4: Update Flake Lock

```bash
cd /path/to/server/config
nix flake update ngit-grasp
git add flake.lock
git commit -m "Add ngit-grasp and update flake.lock"
```

---

### Step 5: Validate Configuration

Before deploying, validate the configuration builds:

```bash
nix flake check
```

---

### Step 6: Deploy to Server

Deploy the new configuration to your server:

```bash
# Build and switch in one command (builds on server)
nixos-rebuild switch --flake .#your-hostname \
  --target-host user@server.example.com \
  --use-remote-sudo \
  --build-host user@server.example.com
```

**Alternative:** Build locally, then deploy:

```bash
# Build locally
nixos-rebuild build --flake .#your-hostname

# Deploy to server
nixos-rebuild switch --flake .#your-hostname \
  --target-host user@server.example.com \
  --use-remote-sudo
```

**Note:** Building locally requires your machine to trust the server's nix signing key.

---

### Step 7: Verify Deployment

SSH to the server and check the service:

```bash
ssh user@server.example.com

# Check service status
systemctl status ngit-grasp-production

# View logs
journalctl -u ngit-grasp-production -f

# Check if listening on port
ss -tlnp | grep 8082
```

---

### Step 8: Test Functionality

From your local machine, test the relay:

```bash
# Test NIP-11 relay info
curl https://ngit.example.com -H "Accept: application/nostr+json" | jq

# Test WebSocket connection
websocat wss://ngit.example.com
# Then type: ["REQ","test",{}]
# Should receive events

# Test git clone (if you have repos)
git ls-remote https://ngit.example.com/<npub>/<repo>.git
```

---

## Configuration Options

### Required
- `enable` - Enable this instance
- `domain` - Domain where relay is hosted

### Network
- `bindAddress` - IP to bind to (default: "127.0.0.1")
- `port` - Port to listen on (default: 7334)

### Storage
- `dataDir` - Base directory for data (default: /var/lib/ngit-grasp-{name})
- `databaseBackend` - "lmdb" | "memory" (default: "lmdb")

### Identity
- `relayName` - Relay name for NIP-11 (default: "{domain} grasp relay")
- `relayDescription` - Relay description
- `relayOwnerNsecFile` - Runtime secret file loaded as a systemd credential (recommended)
- `relayOwnerNsec` - Inline nsec (less secure)

### Sync
- `syncBootstrapRelayUrl` - Bootstrap relay URL (optional)
- `syncDisableNegentropy` - Disable NIP-77 negentropy (default: false)
- `syncMaxBackoffSecs` - Max backoff for reconnection (default: 3600)
- `syncDisconnectCheckIntervalSecs` - Check interval (default: 60)
- `syncBaseBackoffSecs` - Base backoff time (default: 5)

### Metrics
- `metricsEnabled` - Enable /metrics endpoint (default: true)
- `metricsConnectionPerIpAbuseThreshold` - Abuse threshold (default: 10)
- `metricsTopNRepos` - Number of top repos to track (default: 10)

### Logging
- `logLevel` - "trace" | "debug" | "info" | "warn" | "error" (default: "info")

### Security
- `user` - User to run as (default: "ngit-grasp-{name}")
- `group` - Group to run as (default: "ngit-grasp")

See [nix/module.nix](../../nix/module.nix) for complete option definitions.

---

## Systemd Service

The NixOS module creates a systemd service: `ngit-grasp-{instance-name}`

```bash
# Start/stop/restart
systemctl start ngit-grasp-production
systemctl stop ngit-grasp-production
systemctl restart ngit-grasp-production

# Enable/disable autostart
systemctl enable ngit-grasp-production
systemctl disable ngit-grasp-production

# View logs
journalctl -u ngit-grasp-production -f
journalctl -u ngit-grasp-production --since "1 hour ago"

# Check status
systemctl status ngit-grasp-production
```

---

## Multiple Instances

You can run multiple instances on the same server:

```nix
services.ngit-grasp = {
  production = {
    enable = true;
    domain = "ngit.example.com";
    port = 8082;
    dataDir = "/persistent/ngit-production";
  };
  
  staging = {
    enable = true;
    domain = "ngit-staging.example.com";
    port = 8083;
    dataDir = "/persistent/ngit-staging";
    logLevel = "debug";
  };
};
```

Each instance:
- Runs as separate systemd service: `ngit-grasp-production`, `ngit-grasp-staging`
- Has its own user: `ngit-grasp-production`, `ngit-grasp-staging`
- Stores data in separate directory
- Can have different configuration

---

## Troubleshooting

### Service won't start

**Check logs:**
```bash
journalctl -u ngit-grasp-production -n 50
```

**Common issues:**
- Port already in use: Check with `ss -tlnp | grep 8082`
- Data directory permissions: Should be owned by service user
- Invalid nsec file: Check file exists and contains valid nsec

### Can't connect via WebSocket

**Check:**
- Service is running: `systemctl status ngit-grasp-production`
- Firewall allows connections: `nix-shell -p nmap --run "nmap -p 443 ngit.example.com"`
- Caddy is configured correctly: `systemctl status caddy`
- DNS resolves: `dig ngit.example.com`

### Sync not working

**Check logs for sync errors:**
```bash
journalctl -u ngit-grasp-production | grep -i sync
```

**Common issues:**
- Bootstrap relay URL incorrect or unreachable
- Network connectivity issues
- Bootstrap relay doesn't support negentropy (disable with `syncDisableNegentropy = true`)

### High memory/CPU usage

**Monitor metrics:**
```bash
curl http://localhost:8082/metrics
```

**Tune configuration:**
- Reduce `metricsTopNRepos`
- Increase `syncMaxBackoffSecs`
- Tune `syncMaxBackoffSecs` for your network conditions

---

## Rollback

If deployment fails, rollback to previous configuration:

```bash
# On the server
nixos-rebuild switch --rollback

# Or remotely
nixos-rebuild switch --rollback \
  --target-host user@server.example.com \
  --use-remote-sudo
```

---

## Upgrading

To upgrade ngit-grasp:

```bash
# Update flake input
nix flake update ngit-grasp

# Review changes
git diff flake.lock

# Commit
git add flake.lock
git commit -m "Update ngit-grasp"

# Deploy
nixos-rebuild switch --flake .#your-hostname \
  --target-host user@server.example.com \
  --use-remote-sudo \
  --build-host user@server.example.com
```

---

## Security Hardening

The NixOS module includes systemd hardening:

- `NoNewPrivileges = true` - Prevents privilege escalation
- `ProtectSystem = "strict"` - Read-only filesystem except dataDir
- `ProtectHome = true` - No access to home directories
- `PrivateTmp = true` - Private /tmp
- `RestrictAddressFamilies` - Only allow needed network families
- `SystemCallFilter` - Restrict system calls

Additional recommendations:

1. **Use a runtime secret file instead of an inline key:**
   ```nix
   relayOwnerNsecFile = "/run/agenix/ngit-grasp-relay-owner-nsec";
   # NOT: relayOwnerNsec = "nsec1...";  # Ends up in nix store!
   ```

   The module exposes the file to ngit-grasp as the `relay_owner_nsec`
   systemd credential. The key does not appear in `ExecStart` or the process
   command line. ngit-grasp does not modify the external source file; keep its
   ownership and permissions restricted through your secret manager.

2. **Restrict data directory permissions:**
   ```bash
   chmod 750 /persistent/ngit-grasp
   chown ngit-grasp-production:ngit-grasp /persistent/ngit-grasp
   ```

3. **Use HTTPS (reverse proxy required):**
   - ngit-grasp binds to localhost by default
   - Use Caddy/nginx for TLS termination
   - Caddy handles certificates automatically

4. **Monitor logs regularly:**
   ```bash
   journalctl -u ngit-grasp-production --since today | grep -i error
   ```

---

## Monitoring

### Prometheus Metrics

ngit-grasp exposes Prometheus metrics at `/metrics`:

```bash
curl http://localhost:8082/metrics
```

See [Prometheus Setup](./prometheus-setup.md) for complete monitoring guide.

### Basic Health Checks

```bash
# Check if service is running
systemctl is-active ngit-grasp-production

# Check if port is listening
nc -zv localhost 8082

# Check relay info
curl https://ngit.example.com -H "Accept: application/nostr+json"

# Check disk usage
du -sh /persistent/ngit-grasp/*
```

---

## Related Documentation

- [Configuration Reference](../reference/configuration.md) - All configuration options
- [NixOS Module](../../nix/module.nix) - Module source code
- [Example Configuration](../../nix/example-configuration.nix) - More examples
- [Prometheus Setup](./prometheus-setup.md) - Monitoring guide
- [Nix Flakes How-To](./nix-flakes.md) - Nix development environment

---

*Part of the [ngit-grasp how-to guides](./)*
