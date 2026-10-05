{ config, lib, pkgs, ngitGraspSourceRevision ? "unknown", ... }:

with lib;

let
  # Build ngit-grasp package (shared across all instances)
  ngit-grasp = pkgs.rustPlatform.buildRustPackage {
    pname = "ngit-grasp";
    version = "3.0.7";
    src = ../.;
    NGIT_BUILD_REVISION = ngitGraspSourceRevision;
    cargoLock = {
      lockFile = ../Cargo.lock;
    };

    nativeBuildInputs = with pkgs; [ pkg-config ];
    buildInputs = with pkgs; [ openssl ];

    # Disable tests during Nix build (many require git in PATH for sandboxing)
    # Tests run successfully in dev environment and CI where git is available
    doCheck = false;
  };

  relayOwnerNsecCredential = "relay_owner_nsec";

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

      basePath = mkOption {
        type = types.str;
        default = "/";
        example = "/grasp";
        description = ''
          Public URL path where this relay is mounted. Use "/" for a
          domain-root deployment or a normalized path such as "/grasp".
        '';
      };

      bindAddress = mkOption {
        type = types.str;
        default = "127.0.0.1";
        description = "IP address to bind to";
      };

      trustedProxyCidrs = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "127.0.0.1/32" "::1/128" "10.0.0.0/8" ];
        description = ''
          IP address ranges for reverse proxies whose Forwarded,
          X-Forwarded-For, or X-Real-IP headers may identify WebSocket
          clients. Leave empty unless ngit-grasp is behind a trusted proxy.
          Keep the backend unreachable from untrusted networks and include
          every trusted proxy hop needed to resolve a forwarding chain.
        '';
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
        example = "/run/agenix/ngit-grasp-relay-owner-nsec";
        description = ''
          Runtime secret file containing the relay owner's nsec (private key),
          used for the NIP-05 root identity when served at the domain root,
          startup kind-0/kind-10002 seeding, trusted service-event
          admission, NIP-11 relay information, and relay authentication.
          The service receives it as a systemd credential named
          `${relayOwnerNsecCredential}`, so the secret is never placed in the
          process command line.

          Leave this null to use relayOwnerNsec or to load/generate
          .relay-owner.nsec in dataDir. If set, point it at a runtime secret
          file (agenix, sops-nix, etc.), not a Nix-store path.
          ngit-grasp does not modify this external source file; its ownership
          and permissions remain the operator or secret manager's responsibility.
        '';
      };

      relayOwnerNsec = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "nsec1...";
        description = ''
          Relay owner's nsec (private key) for the NIP-05 root identity when
          served at the domain root, startup kind-0/kind-10002 seeding,
          trusted service-event admission, NIP-11 relay information, signing,
          and authentication.
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

      syncPlusEnabled = mkOption {
        type = types.bool;
        default = true;
        description = ''
          Enable GRASP-03 Sync+ mailbox discovery on top of proactive
          GRASP-02 sync. This has no effect unless the relay service, and
          therefore its proactive sync manager, is enabled.
        '';
      };

      userIndexRelays = mkOption {
        type = types.listOf types.str;
        default = [
          "wss://purplepag.es"
          "wss://index.hzrd149.com"
          "wss://indexer.coracle.social"
        ];
        description = ''
          Relays receiving the relay-owner kind-0/kind-10002 identity events
          and used to discover eligible accepted repository participants'
          NIP-65 relay lists.
        '';
      };

      syncPlusFallbackRelays = mkOption {
        type = types.listOf types.str;
        default = [
          "wss://relay.ditto.pub"
          "wss://relay.damus.io"
          "wss://nos.lol"
          "wss://relay.primal.net"
        ];
        description = ''
          Bounded inbox fallback relays used for eligible Sync+ authors only
          after a user-index query succeeds without a NIP-65 relay list.
        '';
      };

      syncRecursiveDescendantLimit = mkOption {
        type = types.ints.positive;
        default = 500;
        description = ''
          Soft limit on recursive query-frontier members below each event
          which directly tags a repository root. Direct root-tagging events
          do not consume the limit.
        '';
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

      startupIntegrityIdentifiers = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "repo-one" "repo-two" ];
        description = ''
          Repository identifiers checked by the automatic startup storage-
          and authorization-integrity passes. An empty list checks every
          installed identifier family and is required for a complete sweep.
          A non-empty list is intended only for staged validation.
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
          Application logging level or explicit tracing filter expression.
          Bare levels keep dependency logging at warn.
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

      syncAllowNonGlobalTargets = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Allow event-directed sync targets that are not globally reachable
          (loopback, private, link-local addresses and local hostnames).
          Disables the SSRF protection for untrusted announcement/PR URLs;
          intended only for tests and closed development networks. The
          operator-configured bootstrap relay is always allowed regardless.
        '';
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
            from relay-observed first_seen_at (default: 30 days). Production
            periods should be at least one day; sub-day values are for tests.
          '';
        };

        unusedUnservedGatingAdditionalSecs = mkOption {
          type = types.ints.positive;
          default = 15552000;
          description = ''
            Additional time in seconds after unused serving ends that a deletion
            or vanish request remains unserved but eligible to gate admission
            (default: 180 days). Production periods should be at least one day;
            sub-day values are for tests.
          '';
        };

        usedServedAfterLastUsedSecs = mkOption {
          type = types.ints.positive;
          default = 23328000;
          description = ''
            Normal-mode time in seconds a used deletion or vanish request
            remains served after last_used_at (default: 270 days, 9 fixed
            30-day months). Used requests remain served indefinitely when
            deletionRequestDisrespector is enabled. Production periods should
            be at least one day; sub-day values are for tests.
          '';
        };

        usedUnservedGatingAdditionalSecs = mkOption {
          type = types.ints.positive;
          default = 7776000;
          description = ''
            Additional normal-mode time in seconds after used serving ends that
            a deletion or vanish request remains unserved but continues gating
            admission (default: 90 days, 3 fixed 30-day months). This duration
            does not expire used requests when deletionRequestDisrespector is
            enabled. Production periods should be at least one day; sub-day
            values are for tests.
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

          See: https://gitworkshop.dev/danconwaydev.com/grasp/tree/master/06.md
        '';
      };

      privateMode = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Enable GRASP-08 private-service authentication. All Nostr clients
          must authenticate with NIP-42 and all standard Git Smart HTTP
          requests must carry a repository-scoped NIP-98 credential.
          Cannot be combined with grasp06Enable.
        '';
      };

      privateMembers = mkOption {
        type = types.listOf types.str;
        default = [ ];
        example = [ "npub1alice..." "npub1bob..." ];
        description = ''
          Permanently configured GRASP-08 service members. The effective
          whitelist also includes NIP-11 owners of relays referenced by
          accepted repository announcements. At least one valid configured
          npub is required when privateMode is enabled; malformed entries make
          the service fail at startup.
        '';
      };

      privatePublicOrigin = mkOption {
        type = types.str;
        default = "";
        example = "https://private.example";
        description = "Canonical external origin used by private Git NIP-98 credentials.";
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

      relayMaxSubscriptions = mkOption {
        type = types.ints.positive;
        default = 500;
        description = "Maximum active REQ subscriptions per WebSocket connection";
      };
      relayMaxEventSizeBytes = mkOption {
        type = types.ints.positive;
        default = 192 * 1024;
        description = "Maximum serialized event size in bytes";
      };
      relayFilterLimit = mkOption {
        type = types.ints.positive;
        default = 500;
        description = "Per-filter result cap, including when limit is omitted";
      privateReposEnable = mkOption {
        type = types.bool;
        default = false;
        description = ''
          GRASP-P master switch: enable private repository hosting
          (kind-30640/30641/1059/21059 + blob routes). Every other
          private* option is a no-op unless this is true.
        '';
      };

      privateRegistrationMode = mkOption {
        type = types.enum [ "open" "whitelist" "pow" "paid" ];
        default = "whitelist";
        description = ''
          GRASP-P admission mode for NEW private-repo aliases. WP-E: the
          shipped default is whitelist — open is staging/self-use only (in
          open mode any fresh key receives the full per-tenant quota, so
          ~50 pseudonymous tenants can exhaust the global budget). paid is
          reserved and fails validation. Part of the policy_fingerprint
          preimage (grasp-p-policy-v3): operators who never set the mode
          will see their fingerprint change on upgrade — paired nodes must
          run identical values.
        '';
      };

      privatePowBits = mkOption {
        type = types.int;
        default = 20;
        description = ''
          GRASP-P: NIP-13 leading-zero bits required on kind-30640
          registrations when privateRegistrationMode = "pow". Must be
          1..=40.
        '';
      };

      privateTenantWhitelist = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = ''
          GRASP-P: npubs (bech32) allowed to register new aliases when
          privateRegistrationMode = "whitelist". Empty (default) rejects
          ALL new registrations — a valid "accept nothing" posture;
          startup warns loudly in that state. Part of the
          policy_fingerprint preimage: paired nodes must run identical
          lists.
        '';
      };

      privateMaxBlobBytes = mkOption {
        type = types.int;
        default = 268435456;
        description = ''
          GRASP-P: per-blob size cap in bytes (enforced pre- and
          mid-stream). Default 256 MiB.
        '';
      };

      privateMaxEventBytes = mkOption {
        type = types.int;
        default = 131072;
        description = ''
          GRASP-P: serialized-JSON size cap in bytes for private-repo
          events (30640/30641/1059/21059). Default 128 KiB.
        '';
      };

      privateQuotaTenantBytes = mkOption {
        type = types.int;
        default = 1073741824;
        description = ''
          GRASP-P: per hosting-npub total quota in bytes (events + blobs).
          Must be > 0 and <= privateGlobalBudgetBytes. Default 1 GiB.
          policy_fingerprint preimage member.
        '';
      };

      privateQuotaRepoBytes = mkOption {
        type = types.int;
        default = 536870912;
        description = ''
          GRASP-P: per-alias total quota in bytes (events + blobs). Must
          be > 0 and <= privateQuotaTenantBytes. Default 512 MiB.
          policy_fingerprint preimage member.
        '';
      };

      privateGlobalBudgetBytes = mkOption {
        type = types.int;
        default = 53687091200;
        description = ''
          GRASP-P: whole private-subsystem storage cap in bytes. Default
          50 GiB. policy_fingerprint preimage member.
        '';
      };

      privateMaxAliasesPerTenant = mkOption {
        type = types.int;
        default = 64;
        description = ''
          GRASP-P: maximum registrations (aliases) per hosting npub.
        '';
      };

      privateMaxWriteKeysPerAlias = mkOption {
        type = types.int;
        default = 64;
        description = ''
          GRASP-P: maximum `w` + `aux` keys per alias registration.
        '';
      };

      privateStateHistoryEditions = mkOption {
        type = types.int;
        default = 16;
        description = ''
          GRASP-P: kind-30641 edition ring depth kept in the private meta
          store. Must be >= 1.
        '';
      };

      privateGcGraceSecs = mkOption {
        type = types.int;
        default = 86400;
        description = ''
          GRASP-P: grace period in seconds before an unreferenced blob may
          be deleted by GC.
        '';
      };

      privateGcIntervalSecs = mkOption {
        type = types.int;
        default = 3600;
        description = ''
          GRASP-P: interval in seconds between private blob GC passes.
        '';
      };

      privateOffboardRetentionSecs = mkOption {
        type = types.int;
        default = 2592000;
        description = ''
          GRASP-P: tombstoned-alias purge delay in seconds (30 days).
        '';
      };

      privateBlobDataPath = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          GRASP-P: blob store root. Null (default): the relay derives
          <relay_data_path>/blobs (i.e. ''${dataDir}/relay/blobs under
          this module).
        '';
      };

      privateMetaDataPath = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          GRASP-P: private meta store (heed env) root. Null (default): the
          relay derives <relay_data_path>/private-meta.
        '';
      };

      privateMirrorEnable = mkOption {
        type = types.bool;
        default = false;
        description = ''
          GRASP-P Phase 2: blob mirroring between paired nodes.
        '';
      };

      privateMirrorPeerUrls = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = ''
          GRASP-P Phase 2: peer blob-server base URLs for the mirror.
          Empty (default): derive peers from each registration's `server`
          tags (minus this node's own domain).
        '';
      };

      privateMirrorMaxConcurrency = mkOption {
        type = types.int;
        default = 4;
        description = ''
          GRASP-P Phase 2: maximum concurrent blob mirror fetches. Must
          be > 0 when the mirror is enabled.
        '';
      };

      privateMirrorFetchTimeoutSecs = mkOption {
        type = types.int;
        default = 120;
        description = ''
          GRASP-P Phase 2: per-blob mirror fetch timeout in seconds. Must
          be > 0 when the mirror is enabled.
        '';
      };

      privateSyncPeerUrls = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = ''
          GRASP-P Phase 2: operator-approved peer relay URLs for
          private-repo sync. Outbound private-sync WebSocket connections
          are made ONLY to this allowlist — tenant 30640 `relays` tags
          never trigger a connection (SSRF / membership-map-leak guard).
          Empty (default): no private-sync peer connections are initiated
          (bootstrap relays still carry the private filters).
        '';
      };

      privateMirrorAllowPrivateIps = mkOption {
        type = types.bool;
        default = false;
        description = ''
          GRASP-P Phase 2 SSRF guard: when false (default), mirror fetch
          peers resolving to loopback/private/link-local IPs are dropped
          and only https/wss public hosts are contacted. Set true only
          for local testing (e.g. a 127.0.0.1 node pair).
        '';
      };

      privateAcceptDirectInvites = mkOption {
        type = types.bool;
        default = false;
        description = ''
          GRASP-P: accept kind-3313 direct invites for storage (currently
          only false is honored: invites are rejected).
        '';
      };

      privateAcceptLegacyWrapKind = mkOption {
        type = types.bool;
        default = true;
        description = ''
          GRASP-P: also accept the LEGACY stream-wrap kinds 1059/21059
          alongside the dedicated CORD stream-wrap kinds 3359/23359.
          Default true: a node must accept 3359 BEFORE any client emits
          it, and legacy wraps already published (or held for
          out-of-order reprocess) must keep draining. Set false only once
          every client on this node has migrated — the legacy kinds are
          then RETIRED: while private repos are enabled a 1059/21059 is
          refused outright, never reclassified onto the public
          related-event path (which would store an a/e-tagged 1059 from
          any key, uncharged and outside private quota/GC). Nodes with
          private repos disabled are unaffected. Cross-node acceptance
          knob: it feeds the policy_fingerprint (v3), so a node pair MUST
          agree on it.
        '';
      };

      privatePerTenantMetrics = mkOption {
        type = types.bool;
        default = false;
        description = ''
          GRASP-P: opt in to per-tenant metric labels (default: aggregate
          metrics only, to keep label cardinality bounded).
        '';
      };

      privateWriteRateCapacity = mkOption {
        type = types.int;
        default = 120;
        description = ''
          GRASP-P Phase-4b: per-write-key token bucket capacity for
          CLIENT-submitted private writes (kind 30641/1059/21059 events +
          blob PUTs). 0 = unlimited (limiter disabled). Deliberately generous
          by default so legitimate flows (incl. cord-git widen-narrow
          rotations) never trip it; only abuse floods are capped. Only has
          an effect when private repos are enabled (NGIT_GRASP_P_REPOS_ENABLE).
        '';
      };

      privateWriteRateRefillPerMin = mkOption {
        type = types.int;
        default = 60;
        description = ''
          GRASP-P Phase-4b: refill rate (tokens per minute) for the
          per-write-key client write bucket. Must be > 0 when
          privateWriteRateCapacity is non-zero.
        '';
      };

      privateRegistrationReplaceCapacity = mkOption {
        type = types.int;
        default = 8;
        description = ''
          GRASP-P Phase-4b: per-(tenant, alias) token bucket capacity for
          same-tenant kind-30640 REPLACEMENTS. 0 = unlimited. Keep >= 4: a
          revocation rotation is widen-narrow = 2 replacements in quick
          succession plus retries. Rejected replacements are HELD locally
          and retried after bucket refill (the hourly re-issue is the
          backstop healer). Cross-node acceptance knob (part of the
          policy_fingerprint preimage, v3) — paired nodes must run
          identical values.
        '';
      };

      privateRegistrationReplaceRefillPerHour = mkOption {
        type = types.int;
        default = 4;
        description = ''
          GRASP-P Phase-4b: refill rate (replacements per hour) for the
          per-(tenant, alias) replacement bucket — bounds sustained
          replacement floods. Must be > 0 when
          privateRegistrationReplaceCapacity is non-zero.
        '';
      };

      privateFullReissueIntervalSecs = mkOption {
        type = types.int;
        default = 3600;
        description = ''
          GRASP-P Phase-4b B1: interval (seconds) for the periodic since=None
          full re-issue of the private sync filters (Layer-1 kind-30640 +
          the current derived 30641/1059 filters) to every live peer, with
          small jitter to avoid cross-node lockstep. Heals delivery gaps
          that otherwise only a reconnect or daily sync fixes (expired
          rejected-hot-cache entries, negentropy blind spots,
          cadence-limited 30640 rejections). 0 = disabled. Node-local
          recovery knob — NOT part of the policy_fingerprint preimage.
        '';
      };

      privateReissueMinIntervalSecs = mkOption {
        type = types.int;
        default = 30;
        description = ''
          GRASP-P Phase-4b FS-3: minimum interval (seconds) between private
          sync-filter re-issues to the same peer, across BOTH triggers
          (PrivateSyncIndex-change-derived filter pushes and the hourly
          full re-issue). Bounds how often a churning derived-filter set
          can force a full consolidate on a peer. A skipped re-issue is
          retried once the interval lapses (never dropped). 0 = unlimited.
          Node-local recovery knob — NOT part of the policy_fingerprint
          preimage.
        '';
      };

      privateMirrorRetryBaseSecs = mkOption {
        type = types.int;
        default = 60;
        description = ''
          GRASP-P Phase-4b B2: base delay (seconds) for the blob mirror's
          per-blob exponential retry backoff (base * 2^(attempt-1), capped
          at privateMirrorRetryMaxSecs, ±20% jitter). Applies to transient
          failure classes only (transport, peer 5xx, no peer, and
          404-on-all-peers at the max interval); deterministic classes
          (quota, too_large, verify/store/blocked, reserve/sink) keep the
          flat repair-scan cadence. Must be > 0. Node-local recovery knob —
          NOT part of the policy_fingerprint preimage.
        '';
      };

      privateMirrorRetryMaxSecs = mkOption {
        type = types.int;
        default = 3600;
        description = ''
          GRASP-P Phase-4b B2: cap (seconds) for the blob mirror retry
          backoff; also the fixed retry interval for blobs the peers answer
          404 (possible late upload). Must be >= privateMirrorRetryBaseSecs.
        '';
      };

      privateDenylistPath = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          GRASP-P Phase-4b D1: comma-separated list of node-local legal
          takedown denylist files (one blob sha256 hex digest per line).
          Matching blobs are not served (GET/HEAD -> 451), not accepted
          (upload preflight -> 451), not stored (in-flight uploads fail at
          commit), and not mirrored. A missing file is tolerated (warning +
          treated as empty); a present-but-unreadable file is a hard boot
          error. Each file is capped (64 MiB / 1M lines): an over-cap file
          is a hard boot error and keeps its last-known entries on reload.
          Writers MUST update files atomically (write-temp-then-rename) —
          the reload keys off mtime and a torn write is a known staleness
          window. Node-local legal config — deliberately NOT part of the
          policy_fingerprint. Only has an effect when private repos are
          enabled (NGIT_GRASP_P_REPOS_ENABLE).
        '';
      };

      privateDenylistReloadSecs = mkOption {
        type = types.int;
        default = 60;
        description = ''
          GRASP-P Phase-4b D1: interval (seconds) between denylist file
          reloads. Only changed files are re-read; the live set is swapped
          atomically. Hashes newly present after a reload are purged
          immediately (claims freed, ledger charges released, bytes
          unlinked); removed hashes unblock reads, but purged bytes stay
          gone (clients must re-upload). 0 = reload disabled (boot-time
          set kept).
        '';
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
  mkService = name: cfg:
  let
    loadCredentials = optional (cfg.relayOwnerNsecFile != null)
      "${relayOwnerNsecCredential}:${toString cfg.relayOwnerNsecFile}";
  in {
    description = "ngit-grasp GRASP relay (${name})";
    after = [ "network.target" "ngit-grasp-${name}-setup.service" ];
    requires = [ "ngit-grasp-${name}-setup.service" ];
    wantedBy = [ "multi-user.target" ];

    environment = {
      NGIT_DOMAIN = cfg.domain;
      NGIT_BASE_PATH = cfg.basePath;
      NGIT_BIND_ADDRESS = "${cfg.bindAddress}:${toString cfg.port}";
      NGIT_GIT_DATA_PATH = "${cfg.dataDir}/git";
      NGIT_RELAY_DATA_PATH = "${cfg.dataDir}/relay";
      NGIT_RELAY_DESCRIPTION = cfg.relayDescription;
      NGIT_DATABASE_BACKEND = cfg.databaseBackend;
      NGIT_METRICS_CONNECTION_PER_IP_ABUSE_THRESHOLD =
        toString cfg.metricsConnectionPerIpAbuseThreshold;
      NGIT_METRICS_TOP_N_REPOS = toString cfg.metricsTopNRepos;
      NGIT_SYNC_MAX_BACKOFF_SECS = toString cfg.syncMaxBackoffSecs;
      NGIT_SYNC_PLUS_ENABLED = if cfg.syncPlusEnabled then "true" else "false";
      NGIT_SYNC_RECURSIVE_DESCENDANT_LIMIT =
        toString cfg.syncRecursiveDescendantLimit;
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
      NGIT_PRIVATE_MODE = if cfg.privateMode then "true" else "false";
      NGIT_PRIVATE_MEMBERS = concatStringsSep "," cfg.privateMembers;
      NGIT_PRIVATE_PUBLIC_ORIGIN = cfg.privatePublicOrigin;
      NGIT_DELETION_REQUEST_DISRESPECTOR =
        if cfg.deletionRequestDisrespector then "true" else "false";
      NGIT_RELAY_MAX_SUBSCRIPTIONS = toString cfg.relayMaxSubscriptions;
      NGIT_RELAY_MAX_EVENT_SIZE_BYTES = toString cfg.relayMaxEventSizeBytes;
      NGIT_RELAY_FILTER_LIMIT = toString cfg.relayFilterLimit;
      NGIT_USER_INDEX_RELAYS = concatStringsSep "," cfg.userIndexRelays;
      NGIT_SYNC_PLUS_FALLBACK_RELAYS =
        concatStringsSep "," cfg.syncPlusFallbackRelays;
      NGIT_GRASP_P_REPOS_ENABLE =
        if cfg.privateReposEnable then "true" else "false";
      NGIT_GRASP_P_REGISTRATION_MODE = cfg.privateRegistrationMode;
      NGIT_GRASP_P_POW_BITS = toString cfg.privatePowBits;
      NGIT_GRASP_P_TENANT_WHITELIST =
        concatStringsSep "," cfg.privateTenantWhitelist;
      NGIT_GRASP_P_MAX_BLOB_BYTES = toString cfg.privateMaxBlobBytes;
      NGIT_GRASP_P_MAX_EVENT_BYTES = toString cfg.privateMaxEventBytes;
      NGIT_GRASP_P_QUOTA_TENANT_BYTES = toString cfg.privateQuotaTenantBytes;
      NGIT_GRASP_P_QUOTA_REPO_BYTES = toString cfg.privateQuotaRepoBytes;
      NGIT_GRASP_P_GLOBAL_BUDGET_BYTES =
        toString cfg.privateGlobalBudgetBytes;
      NGIT_GRASP_P_MAX_ALIASES_PER_TENANT =
        toString cfg.privateMaxAliasesPerTenant;
      NGIT_GRASP_P_MAX_WRITE_KEYS_PER_ALIAS =
        toString cfg.privateMaxWriteKeysPerAlias;
      NGIT_GRASP_P_STATE_HISTORY_EDITIONS =
        toString cfg.privateStateHistoryEditions;
      NGIT_GRASP_P_GC_GRACE_SECS = toString cfg.privateGcGraceSecs;
      NGIT_GRASP_P_GC_INTERVAL_SECS = toString cfg.privateGcIntervalSecs;
      NGIT_GRASP_P_OFFBOARD_RETENTION_SECS =
        toString cfg.privateOffboardRetentionSecs;
      NGIT_GRASP_P_MIRROR_ENABLE =
        if cfg.privateMirrorEnable then "true" else "false";
      NGIT_GRASP_P_MIRROR_PEER_URLS =
        concatStringsSep "," cfg.privateMirrorPeerUrls;
      NGIT_GRASP_P_MIRROR_MAX_CONCURRENCY =
        toString cfg.privateMirrorMaxConcurrency;
      NGIT_GRASP_P_MIRROR_FETCH_TIMEOUT_SECS =
        toString cfg.privateMirrorFetchTimeoutSecs;
      NGIT_GRASP_P_SYNC_PEER_URLS = concatStringsSep "," cfg.privateSyncPeerUrls;
      NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS =
        if cfg.privateMirrorAllowPrivateIps then "true" else "false";
      NGIT_GRASP_P_ACCEPT_DIRECT_INVITES =
        if cfg.privateAcceptDirectInvites then "true" else "false";
      NGIT_GRASP_P_ACCEPT_LEGACY_WRAP_KIND =
        if cfg.privateAcceptLegacyWrapKind then "true" else "false";
      NGIT_GRASP_P_PER_TENANT_METRICS =
        if cfg.privatePerTenantMetrics then "true" else "false";
      NGIT_GRASP_P_WRITE_RATE_CAPACITY = toString cfg.privateWriteRateCapacity;
      NGIT_GRASP_P_WRITE_RATE_REFILL_PER_MIN =
        toString cfg.privateWriteRateRefillPerMin;
      NGIT_GRASP_P_REGISTRATION_REPLACE_CAPACITY =
        toString cfg.privateRegistrationReplaceCapacity;
      NGIT_GRASP_P_REGISTRATION_REPLACE_REFILL_PER_HOUR =
        toString cfg.privateRegistrationReplaceRefillPerHour;
      NGIT_GRASP_P_FULL_REISSUE_INTERVAL_SECS =
        toString cfg.privateFullReissueIntervalSecs;
      NGIT_GRASP_P_REISSUE_MIN_INTERVAL_SECS =
        toString cfg.privateReissueMinIntervalSecs;
      NGIT_GRASP_P_MIRROR_RETRY_BASE_SECS =
        toString cfg.privateMirrorRetryBaseSecs;
      NGIT_GRASP_P_MIRROR_RETRY_MAX_SECS =
        toString cfg.privateMirrorRetryMaxSecs;
      NGIT_GRASP_P_DENYLIST_RELOAD_SECS =
        toString cfg.privateDenylistReloadSecs;
    } // optionalAttrs (cfg.privateDenylistPath != null) {
      NGIT_GRASP_P_DENYLIST_PATH = cfg.privateDenylistPath;
    } // optionalAttrs (cfg.privateBlobDataPath != null) {
      NGIT_GRASP_P_BLOB_DATA_PATH = cfg.privateBlobDataPath;
    } // optionalAttrs (cfg.privateMetaDataPath != null) {
      NGIT_GRASP_P_META_DATA_PATH = cfg.privateMetaDataPath;
    } // optionalAttrs (cfg.maxConnections != null) {
      NGIT_MAX_CONNECTIONS = toString cfg.maxConnections;
    } // optionalAttrs (cfg.trustedProxyCidrs != [ ]) {
      NGIT_TRUSTED_PROXY_CIDRS = concatStringsSep "," cfg.trustedProxyCidrs;
    } // optionalAttrs (cfg.startupIntegrityIdentifiers != [ ]) {
      NGIT_STARTUP_INTEGRITY_IDENTIFIERS =
        concatStringsSep "," cfg.startupIntegrityIdentifiers;
    } // optionalAttrs (cfg.relayName != null) {
      NGIT_RELAY_NAME = cfg.relayName;
    } // optionalAttrs (cfg.archiveReadOnly != null) {
      NGIT_ARCHIVE_READ_ONLY = if cfg.archiveReadOnly then "true" else "false";
    } // optionalAttrs cfg.metricsEnabled { NGIT_METRICS_ENABLED = "true"; }
      // optionalAttrs (cfg.syncBootstrapRelayUrl != null) {
        NGIT_SYNC_BOOTSTRAP_RELAY_URL = cfg.syncBootstrapRelayUrl;
      } // optionalAttrs cfg.syncDisableNegentropy {
        NGIT_SYNC_DISABLE_NEGENTROPY = "true";
      } // optionalAttrs cfg.syncAllowNonGlobalTargets {
        NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS = "true";
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

      # The binary reads systemd credentials and environment configuration
      # itself, keeping relay-owner secrets out of process arguments.
      ExecStart = "${ngit-grasp}/bin/ngit-grasp";

      # Restart policy
      Restart = "always";
      RestartSec = "10s";
      UMask = "0077";

      # Hardening
      NoNewPrivileges = true;
      PrivateTmp = true;
      ProtectSystem = "strict";
      ProtectHome = true;
      ReadWritePaths = [ cfg.dataDir ];

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
    } // optionalAttrs (loadCredentials != [ ]) {
      LoadCredential = loadCredentials;
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
