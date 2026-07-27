# Example NixOS configurations using ngit-grasp module
# 
# Usage:
#   1. Add to your server's flake.nix inputs:
#      inputs.ngit-grasp.url = "github:DanConwayDev/ngit-grasp";
#
#   2. Import the module in your configuration:
#      imports = [ inputs.ngit-grasp.nixosModules.default ];
#
#   3. Configure one or more instances (examples below)

{ inputs, ... }:

{
  imports = [ inputs.ngit-grasp.nixosModules.default ];

  # ============================================================================
  # EXAMPLE 1: Single Instance Configuration
  # ============================================================================

  services.ngit-grasp.production = {
    enable = true;
    domain = "ngit.danconwaydev.com";

    # Network
    bindAddress = "127.0.0.1";
    port = 8082;

    # Storage
    dataDir = "/persistent/ngit-danconwaydev-com-ngit-grasp";

    # Identity
    relayName = "DanConwayDev's ngit-grasp";
    relayDescription =
      "personal instance of ngit-grasp, a Rust GRASP implementation with proactive sync";

    # Option 1: Use a runtime secret file (recommended). The module loads it
    # as a systemd credential, keeping the nsec out of the process command line.
    relayOwnerNsecFile = "/run/agenix/ngit-grasp-relay-owner-nsec";

    # Option 2: Inline nsec (less secure, ends up in nix store)
    # relayOwnerNsec = "nsec1...";

    # Option 3: Auto-generate (default if neither above is set)
    # ngit-grasp will create .relay-owner.nsec in dataDir automatically

    # Sync
    syncBootstrapRelayUrl = "wss://relay.ngit.dev";

    # Metrics
    metricsEnabled = true;

    # Logging
    logLevel = "info"; # Options: trace, debug, info, warn, error
  };

  # Caddy reverse proxy for production instance
  services.caddy.virtualHosts."ngit.danconwaydev.com" = {
    extraConfig = ''
      reverse_proxy 127.0.0.1:8082 {
        header_down X-Real-IP {http.request.remote}
        header_down X-Forwarded-For {http.request.remote}
      }
    '';
  };

  # ============================================================================
  # EXAMPLE 2: Multiple Instances on Same Server
  # ============================================================================

  # Uncomment to run multiple instances:

  # # Production instance
  # services.ngit-grasp.prod = {
  #   enable = true;
  #   domain = "ngit.example.com";
  #   port = 8082;
  #   dataDir = "/persistent/ngit-production";
  #   relayName = "Production GRASP Relay";
  #   syncBootstrapRelayUrl = "wss://relay.ngit.dev";
  #   logLevel = "info";
  # };
  # 
  # # Testing/staging instance
  # services.ngit-grasp.staging = {
  #   enable = true;
  #   domain = "ngit-staging.example.com";
  #   port = 8083;
  #   dataDir = "/persistent/ngit-staging";
  #   relayName = "Staging GRASP Relay";
  #   syncBootstrapRelayUrl = "wss://relay.ngit.dev";
  #   logLevel = "debug";  # More verbose logging for testing
  # };
  # 
  # # Development instance with in-memory database
  # services.ngit-grasp.dev = {
  #   enable = true;
  #   domain = "localhost";
  #   bindAddress = "127.0.0.1";
  #   port = 8084;
  #   dataDir = "/tmp/ngit-dev";
  #   databaseBackend = "memory";  # No persistence
  #   relayName = "Development GRASP Relay";
  #   metricsEnabled = false;
  #   logLevel = "trace";  # Maximum verbosity for debugging
  # };
  # 
  # # Caddy configuration for multiple instances
  # services.caddy.virtualHosts = {
  #   "ngit.example.com" = {
  #     extraConfig = "reverse_proxy 127.0.0.1:8082";
  #   };
  #   "ngit-staging.example.com" = {
  #     extraConfig = "reverse_proxy 127.0.0.1:8083";
  #   };
  # };

  # ============================================================================
  # NOTES
  # ============================================================================

  # Instance names (e.g., "production", "prod", "staging") can be anything.
  # They are used for:
  #   - systemd service names: ngit-grasp-<name>
  #   - default user names: ngit-grasp-<name>
  #   - default data directories: /var/lib/ngit-grasp-<name>

  # Systemd service management:
  #   systemctl status ngit-grasp-production
  #   systemctl restart ngit-grasp-staging
  #   journalctl -u ngit-grasp-prod -f

  # Each instance runs as a separate user but shares the same group by default.
  # You can customize user/group per instance if needed.
}
