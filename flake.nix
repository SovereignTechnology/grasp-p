{
  description = "ngit-grasp - A GRASP implementation in Rust";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    crane.url = "github:ipetkov/crane/2c71e194474d13de031d729b729c968ddbe3507f";
    release-ngit = {
      url = "git+https://relay.ngit.dev/npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/ngit.git?rev=31e48be58ee3fa2e3c56b1df68b6358c385d5e91&allRefs=1";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.rust-overlay.follows = "rust-overlay";
    };
  };

  outputs = { self, nixpkgs, rust-overlay, release-ngit, crane }:
    let
      forAllSystems = nixpkgs.lib.genAttrs [
        "aarch64-linux" "x86_64-linux" "aarch64-darwin" "x86_64-darwin"
      ];
      sourceRevision =
        if self ? rev then self.rev
        else if self ? dirtyRev then self.dirtyRev
        else "unknown";
      ngitGraspVersion =
        (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package.version;
      perSystem = forAllSystems (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
        };
        ci = import ./.ngit/nix/workflows {
          inherit pkgs;
          rustToolchain = pkgs.rust-bin.stable.latest.default;
          craneLib = (crane.mkLib pkgs).overrideToolchain pkgs.rust-bin.stable.latest.default;
          src = self;
          version = ngitGraspVersion;
          ngit = import ./.ngit/nix/workflows/release-ngit.nix {
            inherit pkgs;
            sourcePackage = release-ngit.packages.${system}.default;
          };
        };
      in {
        checks = ci.checks;
        ciCommands = ci.commands;
        devShells.default = pkgs.mkShell {
          # Single dev shell for the whole workspace (ngit-grasp + grasp-audit).
          buildInputs = with pkgs; [ rustToolchain pkg-config openssl git gitlint ];

          RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";

          shellHook = ''
            echo "🚀 ngit-grasp workspace development environment"
            echo "Rust version: $(rustc --version)"
            echo ""
            echo "Quick commands:"
            echo "  cargo build                  - Build the whole workspace"
            echo "  cargo test                   - Run ngit-grasp tests"
            echo "  cargo run                    - Run the relay"
            echo "  cargo build -p grasp-audit   - Build the audit tool"
            echo "  cargo test  -p grasp-audit   - Run grasp-audit unit tests"
            echo ""
          '';
        };

        # Both crates are members of a single workspace sharing one Cargo.lock.
        packages = {
          default = self.packages.${system}.ngit-grasp;
          ci-dependencies = ci.dependencies;
          ci-publisher-tools = ci.publisher-tools;
          ci-container-tools = ci.container-tools;

          ngit-grasp = pkgs.rustPlatform.buildRustPackage {
            pname = "ngit-grasp";
            version = ngitGraspVersion;
            src = ./.;
            NGIT_BUILD_REVISION = sourceRevision;
            cargoLock = {
              lockFile = ./Cargo.lock;
            };

            # Only build/test the ngit-grasp package, not the whole workspace.
            cargoBuildFlags = [ "-p" "ngit-grasp" ];

            nativeBuildInputs = with pkgs; [ pkg-config git ];

            buildInputs = with pkgs; [ openssl ];

            # Run lib tests only; integration tests spawn a live relay and require
            # network access not available in the Nix sandbox.
            doCheck = true;
            cargoTestFlags = [ "-p" "ngit-grasp" "--lib" ];
          };

          grasp-audit = pkgs.rustPlatform.buildRustPackage {
            pname = "grasp-audit";
            version = "0.2.0";
            src = ./.;
            cargoLock = {
              lockFile = ./Cargo.lock;
            };

            cargoBuildFlags = [ "-p" "grasp-audit" ];

            nativeBuildInputs = with pkgs; [ pkg-config git ];

            buildInputs = with pkgs; [ openssl ];

            # Audit tests require a running Nostr relay; skip in the sandbox.
            doCheck = false;
          };
        } // pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          release-archive = pkgs.runCommand "ngit-grasp-release-archive" {
            nativeBuildInputs = [ pkgs.gnutar pkgs.gzip ];
          } ''
            archive="ngit-grasp-${ngitGraspVersion}-${pkgs.pkgsStatic.stdenv.hostPlatform.rust.cargoShortTarget}"
            mkdir -p "$archive" "$out/release"
            cp ${self.packages.${system}.static}/bin/ngit-grasp "$archive/"
            cp ${./LICENSE} "$archive/"
            tar --sort=name --mtime=@1 --owner=0 --group=0 --numeric-owner \
              -czf "$out/release/$archive.tar.gz" "$archive"
          '';
          # Portable release binary used by the tag-triggered release workflow.
          static = pkgs.pkgsStatic.rustPlatform.buildRustPackage {
            pname = "ngit-grasp";
            version = ngitGraspVersion;
            src = ./.;
            NGIT_BUILD_REVISION = sourceRevision;
            cargoLock = {
              lockFile = ./Cargo.lock;
            };

            cargoBuildFlags = [ "-p" "ngit-grasp" ];
            nativeBuildInputs = with pkgs; [ pkg-config ];
            buildInputs = with pkgs.pkgsStatic; [ openssl ];

            doCheck = false;
          };
        };
      });
    in {
        packages = forAllSystems (system: perSystem.${system}.packages);
        checks = forAllSystems (system: perSystem.${system}.checks);
        devShells = forAllSystems (system: perSystem.${system}.devShells);
        ngit-ci.commands = forAllSystems (system: perSystem.${system}.ciCommands);
        # NixOS module for deployment
        nixosModules.default = { ... }: {
          imports = [ ./nix/module.nix ];
          _module.args.ngitGraspSourceRevision = sourceRevision;
        };
        nixosModules.ngit-grasp = self.nixosModules.default;
      };
}
