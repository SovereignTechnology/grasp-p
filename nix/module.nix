{ config, lib, pkgs, ... }:

with lib;

let
  # Build ngit-grasp package (shared across all instances)
  ngit-grasp = pkgs.rustPlatform.buildRustPackage {
    pname = "ngit-grasp";
    version = "1.2.0";
    src = ../.;
    cargoLock = {
      lockFile = ../Cargo.lock;
    };

    nativeBuildInputs = with pkgs; [ pkg-config ];
    buildInputs = with pkgs; [ openssl ];

    # Disable tests during Nix build (many require git in PATH for sandboxing)
    # Tests run successfully in dev environment and CI where git is available
    doCheck = false;
  };

  # Per-instance options
  instanceOptions = { name, ... }: {
    options = {
      enable = mkEnableOption "this ngit-grasp instance";

      domain = mkOption {
        type = types.str;
        example = "ngit.example.com";
        description =
          "Domain where this relay is hosted (used in GRASP validation)";
      };

      bindAddress = mkOption {
        type = types.str;
        default = "127.0.0.1";
        description = "IP address to bind to";
      };

      port = mkOption {
        type = types.port;
        default = 7334;
        description = "Port to listen on";
      };

      dataDir = mkOption {
        type = types.path;
        default = "/var/lib/ngit-grasp-${name}";
        description = "Base directory for data storage";
      };

      relayName = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "My GRASP Relay";
        description =
          "Relay name for NIP-11 (defaults to \${domain} grasp relay)";
      };

      relayDescription = mkOption {
        type = types.str;
        default = "Git Nostr Relay - a grasp implementation";
        description = "Relay description for NIP-11";
      };

      relayOwnerNsecFile = mkOption {
        type = types.nullOr types.path;
        default = null;
        example = "/persistent/ngit-grasp/relay-owner.nsec";
        description = ''
          Path to file containing relay owner's nsec (private key).
          If file doesn't exist, ngit-grasp will auto-generate a random nsec and save it.
          Takes precedence over relayOwnerNsec if both are set.
        '';
      };

      relayOwnerNsec = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "nsec1...";
        description = ''
          Relay owner's nsec (private key) for signing and authentication.
          Less secure than relayOwnerNsecFile as it ends up in nix store.
          Only used if relayOwnerNsecFile is not set.
        '';
      };

      syncBootstrapRelayUrl = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "wss://relay.ngit.dev";
        description = "Bootstrap relay URL to sync from on startup (optional)";
      };

      databaseBackend = mkOption {
        type = types.enum [ "lmdb" "memory" ];
        default = "lmdb";
        description = ''
          Database backend type:
          - lmdb: LMDB backend (persistent, general purpose)
          - memory: In-memory database (fastest, no persistence)
        '';
      };

      metricsEnabled = mkOption {
        type = types.bool;
        default = true;
        description = "Enable Prometheus metrics endpoint at /metrics";
      };

      metricsConnectionPerIpAbuseThreshold = mkOption {
        type = types.int;
        default = 10;
        description =
          "Connections per IP before flagging as potential abuse in metrics";
      };

      metricsTopNRepos = mkOption {
        type = types.int;
        default = 10;
        description = "Number of top bandwidth repos to track in metrics";
      };

      logLevel = mkOption {
        type = types.str;
        default = "info";
        example = "debug";
        description = ''
          Logging level for application logging.
          Can be a simple level (trace, debug, info, warn, error) or a filter expression.
          Examples: "info", "debug", "ngit_grasp=debug,actix_web=info"
        '';
      };

      syncMaxBackoffSecs = mkOption {
        type = types.int;
        default = 3600;
        description =
          "Maximum backoff time in seconds for sync relay reconnection (default: 1 hour)";
      };

      syncDisconnectCheckIntervalSecs = mkOption {
        type = types.int;
        default = 60;
        description = "Interval in seconds for checking disconnected relays";
      };

      syncBaseBackoffSecs = mkOption {
        type = types.int;
        default = 5;
        description = "Base backoff time in seconds for relay reconnection";
      };

      syncDisableNegentropy = mkOption {
        type = types.bool;
        default = false;
        description = "Disable NIP-77 negentropy sync (use REQ+EOSE instead)";
      };

      rejectedHotCacheDurationSecs = mkOption {
        type = types.int;
        default = 120;
        description =
          "Hot cache duration in seconds for rejected announcements (default: 2 minutes)";
      };

      rejectedColdIndexExpirySecs = mkOption {
        type = types.int;
        default = 604800;
        description =
          "Cold index expiry in seconds for rejected announcements (default: 7 days)";
      };

      naughtyListExpirationHours = mkOption {
        type = types.int;
        default = 12;
        description = "Hours before removing relay from naughty list";
      };

      holdingRetentionSecs = mkOption {
        type = types.int;
        default = 7776000;
        description =
          "Retention window in seconds for deleted events in holding DB (default: 90 days)";
      };

      holdingCleanupIntervalSecs = mkOption {
        type = types.int;
        default = 86400;
        description =
          "Interval in seconds between holding DB and deletion-request retention cleanup passes (default: 24 hours)";
      };

      deletionRequestRetention = {
        unusedServedSecs = mkOption {
          type = types.ints.positive;
          default = 2592000;
          description = ''
            Time in seconds an unused deletion or vanish request remains served
            from relay-observed first_seen_at (default: 30 days).
          '';
        };

        unusedUnservedGatingAdditionalSecs = mkOption {
          type = types.ints.positive;
          default = 15552000;
          description = ''
            Additional time in seconds after unused serving ends that a deletion
            or vanish request remains unserved but eligible to gate admission
            (default: 180 days).
          '';
        };

        usedServedAfterLastUsedSecs = mkOption {
          type = types.ints.positive;
          default = 23328000;
          description = ''
            Normal-mode time in seconds a used deletion or vanish request
            remains served after last_used_at (default: 270 days, 9 fixed
            30-day months). Used requests remain served indefinitely when
            deletionRequestDisrespector is enabled.
          '';
        };

        usedUnservedGatingAdditionalSecs = mkOption {
          type = types.ints.positive;
          default = 7776000;
          description = ''
            Additional normal-mode time in seconds after used serving ends that
            a deletion or vanish request remains unserved but continues gating
            admission (default: 90 days, 3 fixed 30-day months). This duration
            does not expire used requests when deletionRequestDisrespector is enabled.
          '';
        };
      };

      archiveAll = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Enable GRASP-05 archive mode: accept all repository announcements.
          WARNING: Storage and bandwidth risk.
        '';
      };

      archiveWhitelist = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "npub1alice..." "npub1bob.../linux" "bitcoin-core" ];
        description = ''
          GRASP-05 archive whitelist entries.
          Formats: <npub>, <npub>/<identifier>, <identifier>
        '';
      };

      archiveGraspServices = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "git.example.com" "git.nostr.dev" ];
        description = ''
          GRASP-05 archive GRASP services: list of GRASP server domains to archive.
          Archives all repositories from the specified GRASP server domains.
          Must be bare domains only (e.g., git.example.com, NOT wss://git.example.com).
          Mutually exclusive with archiveAll and archiveWhitelist.
          Automatically sets archiveReadOnly to true by default.
        '';
      };

      archiveReadOnly = mkOption {
        type = types.nullOr types.bool;
        default = null;
        description = ''
          Archive read-only mode (relay is read-only sync of archived repositories).
          When true:
            - NIP-11 includes GRASP-05 in supported_grasps
            - NIP-11 curation field describes archive scope
            - Repository announcements not listing this service are accepted per whitelist/archive-all
          Default: true if archiveAll, archiveWhitelist, or archiveGraspServices is set, false otherwise
          Note: Setting to true without archive config causes startup error
          Note: Cannot be used with repositoryWhitelist (mutually exclusive)
        '';
      };

      grasp06Enable = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Enable the GRASP-06 contributor PR submission endpoint at
          /prs/<npub>/<identifier>.git.

          When enabled, the relay exposes an unauthenticated PR submission
          endpoint that accepts pushes of refs/nostr/<event-id> from any
          contributor. Security relies on the signed PR/PR-Update events the
          refs reference, not on HTTP-level auth.

          When disabled (default), /prs/* returns 404 and event acceptance is
          unchanged.

          See: https://github.com/DanConwayDev/grasp/blob/main/06.md
        '';
      };

      repositoryWhitelist = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "npub1alice..." "npub1bob.../linux" "bitcoin-core" ];
        description = ''
          Repository whitelist for GRASP-01 acceptance.
          Announcements must BOTH list our service AND match this whitelist.
          Formats: <npub>, <npub>/<identifier>, <identifier>
          Cannot be used with archiveReadOnly=true (mutually exclusive)
          When set, NIP-11 curation field indicates curated repository acceptance
        '';
      };

      deletionRequestDisrespector = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Ignore NIP-09 deletion requests and NIP-62 request-to-vanish events
          and act as an archival server.

          When enabled, incoming NIP-09 (kind 5) deletion requests and NIP-62
          request-to-vanish events are stored but NOT acted upon: their targets
          remain fully accessible. This preserves content and prevents
          "left-pad" scenarios. NIP-11 supported_nips will NOT advertise NIP-09
          (deletion) or NIP-62 (request to vanish).

          This ONLY affects NIP-09 and NIP-62 user-initiated requests. It does
          NOT prevent blacklist-triggered deletions (operator moderation).

          When disabled (default), both request types are honoured and NIP-09
          and NIP-62 are advertised in NIP-11.

          See: docs/explanation/repository-lifecycle.md
        '';
      };

      repositoryBlacklist = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "npub1spam..." "npub1alice.../bad-repo" "malware" ];
        description = ''
          Repository blacklist for blocking specific repositories/pubkeys/identifiers.
          Blacklist takes precedence over ALL whitelists (archive and repository).
          Formats: <npub>, <npub>/<identifier>, <identifier>
          Blacklisted repos are rejected with specific reasons (npub/identifier/both).
          Does not affect NIP-11 curation field (operational, not curation policy).
        '';
      };

      blacklistAutoRestore = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Automatically restore repositories deleted by blacklist parity on
          startup when they are no longer blacklisted and still within the
          holding retention window.
        '';
      };

      eventBlacklist = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "npub1spam..." "npub1abuser..." ];
        description = ''
          Event blacklist for blocking all events from specific authors (npubs).
          Takes precedence over ALL other validation (checked first).
          ALL events from these authors are rejected from relay storage and purgatory.
          Applies to announcements, state events, PRs, and all other event types.
          Does not affect NIP-11 metadata (operational, not curation policy).
        '';
      };

      maxConnections = mkOption {
        type = types.nullOr types.int;
        default = null;
        description =
          "Maximum total connections to the relay (default: unlimited, defers to OS/infrastructure limits)";
      };

      user = mkOption {
        type = types.str;
        default = "ngit-grasp-${name}";
        description = "User account under which this instance runs";
      };

      group = mkOption {
        type = types.str;
        default = "ngit-grasp";
        description = "Group under which this instance runs";
      };
    };
  };

  # Create systemd setup service to ensure directories exist before main service
  # This runs without namespace restrictions so it can create directories
  # that ReadWritePaths needs to exist before namespace setup
  mkSetupService = name: cfg: {
    description = "Create data directories for ngit-grasp (${name})";
    before = [ "ngit-grasp-${name}.service" ];
    requiredBy = [ "ngit-grasp-${name}.service" ];

    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart =
        "${pkgs.bash}/bin/bash -c '${pkgs.coreutils}/bin/mkdir -p \"${cfg.dataDir}/git\" \"${cfg.dataDir}/relay\" && ${pkgs.coreutils}/bin/chown -R ${cfg.user}:${cfg.group} \"${cfg.dataDir}\" && ${pkgs.coreutils}/bin/chmod 750 \"${cfg.dataDir}\" \"${cfg.dataDir}/git\" \"${cfg.dataDir}/relay\"'";
    };
  };

  # Create systemd service config for an instance
  mkService = name: cfg: {
    description = "ngit-grasp GRASP relay (${name})";
    after = [ "network.target" "ngit-grasp-${name}-setup.service" ];
    requires = [ "ngit-grasp-${name}-setup.service" ];
    wantedBy = [ "multi-user.target" ];

    environment = {
      NGIT_DOMAIN = cfg.domain;
      NGIT_BIND_ADDRESS = "${cfg.bindAddress}:${toString cfg.port}";
      NGIT_GIT_DATA_PATH = "${cfg.dataDir}/git";
      NGIT_RELAY_DATA_PATH = "${cfg.dataDir}/relay";
      NGIT_RELAY_DESCRIPTION = cfg.relayDescription;
      NGIT_DATABASE_BACKEND = cfg.databaseBackend;
      NGIT_METRICS_CONNECTION_PER_IP_ABUSE_THRESHOLD =
        toString cfg.metricsConnectionPerIpAbuseThreshold;
      NGIT_METRICS_TOP_N_REPOS = toString cfg.metricsTopNRepos;
      NGIT_SYNC_MAX_BACKOFF_SECS = toString cfg.syncMaxBackoffSecs;
      NGIT_SYNC_DISCONNECT_CHECK_INTERVAL_SECS =
        toString cfg.syncDisconnectCheckIntervalSecs;
      NGIT_SYNC_BASE_BACKOFF_SECS = toString cfg.syncBaseBackoffSecs;
      NGIT_REJECTED_HOT_CACHE_DURATION_SECS =
        toString cfg.rejectedHotCacheDurationSecs;
      NGIT_REJECTED_COLD_INDEX_EXPIRY_SECS =
        toString cfg.rejectedColdIndexExpirySecs;
      NGIT_NAUGHTY_LIST_EXPIRATION_HOURS =
        toString cfg.naughtyListExpirationHours;
      NGIT_HOLDING_RETENTION_SECS = toString cfg.holdingRetentionSecs;
      NGIT_HOLDING_CLEANUP_INTERVAL_SECS =
        toString cfg.holdingCleanupIntervalSecs;
      NGIT_DELETION_REQUEST_RETENTION_UNUSED_SERVED_SECS =
        toString cfg.deletionRequestRetention.unusedServedSecs;
      NGIT_DELETION_REQUEST_RETENTION_UNUSED_UNSERVED_GATING_ADDITIONAL_SECS =
        toString cfg.deletionRequestRetention.unusedUnservedGatingAdditionalSecs;
      NGIT_DELETION_REQUEST_RETENTION_USED_SERVED_AFTER_LAST_USED_SECS =
        toString cfg.deletionRequestRetention.usedServedAfterLastUsedSecs;
      NGIT_DELETION_REQUEST_RETENTION_USED_UNSERVED_GATING_ADDITIONAL_SECS =
        toString cfg.deletionRequestRetention.usedUnservedGatingAdditionalSecs;
      NGIT_ARCHIVE_ALL = if cfg.archiveAll then "true" else "false";
      NGIT_ARCHIVE_WHITELIST = concatStringsSep "," cfg.archiveWhitelist;
      NGIT_ARCHIVE_GRASP_SERVICES =
        concatStringsSep "," cfg.archiveGraspServices;
      NGIT_REPOSITORY_WHITELIST = concatStringsSep "," cfg.repositoryWhitelist;
      NGIT_REPOSITORY_BLACKLIST = concatStringsSep "," cfg.repositoryBlacklist;
      NGIT_BLACKLIST_AUTO_RESTORE =
        if cfg.blacklistAutoRestore then "true" else "false";
      NGIT_EVENT_BLACKLIST = concatStringsSep "," cfg.eventBlacklist;
      NGIT_LOG_LEVEL = cfg.logLevel;
      NGIT_GRASP06_ENABLE = if cfg.grasp06Enable then "true" else "false";
      NGIT_DELETION_REQUEST_DISRESPECTOR =
        if cfg.deletionRequestDisrespector then "true" else "false";
    } // optionalAttrs (cfg.maxConnections != null) {
      NGIT_MAX_CONNECTIONS = toString cfg.maxConnections;
    } // optionalAttrs (cfg.relayName != null) {
      NGIT_RELAY_NAME = cfg.relayName;
    } // optionalAttrs (cfg.archiveReadOnly != null) {
      NGIT_ARCHIVE_READ_ONLY = if cfg.archiveReadOnly then "true" else "false";
    } // optionalAttrs cfg.metricsEnabled { NGIT_METRICS_ENABLED = "true"; }
      // optionalAttrs (cfg.syncBootstrapRelayUrl != null) {
        NGIT_SYNC_BOOTSTRAP_RELAY_URL = cfg.syncBootstrapRelayUrl;
      } // optionalAttrs cfg.syncDisableNegentropy {
        NGIT_SYNC_DISABLE_NEGENTROPY = "true";
      } // optionalAttrs
      (cfg.relayOwnerNsec != null && cfg.relayOwnerNsecFile == null) {
        # Only set inline nsec if file is not specified
        NGIT_RELAY_OWNER_NSEC = cfg.relayOwnerNsec;
      };

    serviceConfig = {
      Type = "simple";
      User = cfg.user;
      Group = cfg.group;

      # Working directory where .relay-owner.nsec will be created if needed
      WorkingDirectory = cfg.dataDir;

      # Directory creation is handled by ngit-grasp-${name}-setup.service
      # which runs before this service and creates dataDir with proper ownership

      # Add git, openssh, and coreutils to PATH for purgatory sync operations
      Environment =
        "PATH=${pkgs.git}/bin:${pkgs.openssh}/bin:${pkgs.coreutils}/bin";

      # Command to run
      ExecStart = if cfg.relayOwnerNsecFile != null then
      # Use nsec from file - need to use shell to read the file
        "${pkgs.bash}/bin/bash -c '${ngit-grasp}/bin/ngit-grasp --relay-owner-nsec \"$(${pkgs.coreutils}/bin/cat ${cfg.relayOwnerNsecFile})\"'"
      else
      # Let ngit-grasp auto-generate nsec in .relay-owner.nsec file in dataDir
        "${ngit-grasp}/bin/ngit-grasp";

      # Restart policy
      Restart = "always";
      RestartSec = "10s";

      # Hardening
      NoNewPrivileges = true;
      PrivateTmp = true;
      ProtectSystem = "strict";
      ProtectHome = true;
      ReadWritePaths = [ cfg.dataDir ];

      # If using nsecFile, grant read access
      ReadOnlyPaths =
        optionals (cfg.relayOwnerNsecFile != null) [ cfg.relayOwnerNsecFile ];

      # Additional hardening
      ProtectKernelTunables = true;
      ProtectKernelModules = true;
      ProtectControlGroups = true;
      RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
      RestrictNamespaces = true;
      LockPersonality = true;
      RestrictRealtime = true;
      RestrictSUIDSGID = true;
      PrivateDevices = true;

      # Capabilities
      CapabilityBoundingSet = "";
      AmbientCapabilities = "";

      # System call filtering
      SystemCallFilter = [ "@system-service" "~@privileged" "~@resources" ];
      SystemCallErrorNumber = "EPERM";
    };

    # Directory creation handled by both ExecStartPre (above) and tmpfiles (below)
    # ExecStartPre ensures directories exist at service start time
    # tmpfiles provides boot-time setup and consistency
  };

  enabledInstances =
    filterAttrs (_: cfg: cfg.enable) config.services.ngit-grasp;

in {
  options.services.ngit-grasp = mkOption {
    type = types.attrsOf (types.submodule instanceOptions);
    default = { };
    description = ''
      ngit-grasp GRASP relay instances.

      Multiple instances can be configured with different domains and ports.
      Each instance runs as a separate systemd service.
    '';
    example = literalExpression ''
      {
        production = {
          enable = true;
          domain = "ngit.example.com";
          port = 8082;
          dataDir = "/persistent/ngit-production";
        };
        
        testing = {
          enable = true;
          domain = "ngit-test.example.com";
          port = 8083;
          dataDir = "/persistent/ngit-testing";
        };
      }
    '';
  };

  config = mkIf (enabledInstances != { }) {
    # Create users for all enabled instances
    users.users = mapAttrs' (name: cfg:
      nameValuePair cfg.user {
        isSystemUser = true;
        group = cfg.group;
        description = "ngit-grasp service user (${name})";
        home = cfg.dataDir;
      }) enabledInstances;

    # Create shared group (all instances use the same group by default)
    users.groups.ngit-grasp = { };

    # Create systemd services for all enabled instances
    # Each instance has a setup service (creates directories) and main service
    systemd.services = (mapAttrs'
      (name: cfg: nameValuePair "ngit-grasp-${name}" (mkService name cfg))
      enabledInstances) // (mapAttrs' (name: cfg:
        nameValuePair "ngit-grasp-${name}-setup" (mkSetupService name cfg))
        enabledInstances);

    # Create data directories with proper ownership using tmpfiles
    # This runs as root before the service starts
    # Note: Parent directories are created with root:root ownership (mode 0755)
    # to ensure the path exists, while dataDir itself gets proper service ownership
    systemd.tmpfiles.rules = flatten (mapAttrsToList (name: cfg: [
      # Create parent directories if they don't exist (root-owned, standard perms)
      "d ${dirOf cfg.dataDir} 0755 root root -"
      # Create service-owned directories
      "d ${cfg.dataDir} 0750 ${cfg.user} ${cfg.group} -"
      "d ${cfg.dataDir}/git 0750 ${cfg.user} ${cfg.group} -"
      "d ${cfg.dataDir}/relay 0750 ${cfg.user} ${cfg.group} -"
    ]) enabledInstances);
  };
}
