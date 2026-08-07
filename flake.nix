{
  description = "ngit-grasp - A GRASP implementation in Rust";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils }:
    let
      sourceRevision =
        if self ? rev then self.rev
        else if self ? dirtyRev then self.dirtyRev
        else "unknown";
    in
    (flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };

        rustToolchain = pkgs.rust-bin.stable.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
        };
      in {
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
        packages.default = self.packages.${system}.ngit-grasp;

        packages.ngit-grasp = pkgs.rustPlatform.buildRustPackage {
          pname = "ngit-grasp";
          version = "2.1.0";
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

        packages.grasp-audit = pkgs.rustPlatform.buildRustPackage {
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
      })) // {
        # NixOS module for deployment
        nixosModules.default = { ... }: {
          imports = [ ./nix/module.nix ];
          _module.args.ngitGraspSourceRevision = sourceRevision;
        };
        nixosModules.ngit-grasp = self.nixosModules.default;
      };
}
