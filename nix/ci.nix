{ pkgs, rustToolchain, src, version, sourceRevision }:
let
  rustPlatform = pkgs.makeRustPlatform {
    cargo = rustToolchain;
    rustc = rustToolchain;
  };
  common = {
    inherit src version;
    cargoLock.lockFile = ../Cargo.lock;
    nativeBuildInputs = [ pkgs.pkg-config pkgs.git ];
    buildInputs = [ pkgs.openssl ];
    NGIT_BUILD_REVISION = sourceRevision;
    # Keep full debug builds of the workspace within disposable CI guest limits.
    CARGO_PROFILE_DEV_DEBUG = "0";
    CARGO_PROFILE_TEST_DEBUG = "0";
    buildType = "debug";
    checkType = "debug";
    preBuild = ''
      export HOME="$TMPDIR/ci-home"
      mkdir -p "$HOME"
    '';
  };
in {
  checks = {
    ci-lint = rustPlatform.buildRustPackage (common // {
      pname = "ngit-grasp-ci-lint";
      buildPhase = ''
        runHook preBuild
        cargo fmt --all -- --check
        cargo clippy --offline --locked --workspace --all-targets \
          -j "$NIX_BUILD_CORES" -- -D warnings
        runHook postBuild
      '';
      doCheck = false;
      installPhase = ''
        mkdir -p "$out"
        printf '%s\n' 'fmt: passed' 'clippy: passed' > "$out/lint.txt"
      '';
    });
    ci-tests = rustPlatform.buildRustPackage (common // {
      pname = "ngit-grasp-ci-tests";
      # This fixture generates an executable at runtime, so patchShebangs cannot
      # see it. /usr/bin/env is deliberately absent from the build sandbox.
      postPatch = ''
        substituteInPlace tests/git_response_streaming.rs \
          --replace-fail '#!/usr/bin/env bash' '#!${pkgs.bash}/bin/bash'
      '';
      cargoBuildFlags = [ "--workspace" "--bins" "--tests" ];
      cargoTestFlags = [ "--workspace" "--locked" ];
      # Integration tests bind loopback sockets inside the network namespace.
      # Preserve the hostile ambient Git configuration from the act workflow.
      preCheck = builtins.readFile ./ci-hostile-git.sh;
      postCheck = ''
        mkdir -p "$out/reports"
        printf '%s\n' 'workspace tests and doctests: passed' > "$out/reports/tests.txt"
      '';
      postInstall = ''
        printf '%s\n' '${version}' > "$out/reports/version.txt"
      '';
      postFixup = ''
        mkdir "$out/build"
        mv "$out/bin" "$out/reports" "$out/build/"
        cd "$out/build"
        sha256sum bin/ngit-grasp bin/grasp-audit reports/tests.txt reports/version.txt \
          > SHA256SUMS
      '';
    });
  };
  apps.ci-verify = {
    type = "app";
    program = "${pkgs.writeShellApplication {
      name = "ngit-grasp-ci-verify";
      runtimeInputs = [ pkgs.coreutils pkgs.gnugrep ];
      text = ''
        tests="$NGIT_CI_INPUTS/tests/artifacts/build"
        lint="$NGIT_CI_INPUTS/lint/artifacts/lint/lint.txt"
        grep -Fx 'fmt: passed' "$lint"
        grep -Fx 'clippy: passed' "$lint"
        cd "$tests"
        sha256sum --check SHA256SUMS
        grep -Fx '${version}' reports/version.txt
        grep -Fx 'workspace tests and doctests: passed' reports/tests.txt
        printf '%s\n' 'Rust checks passed; build artifacts verified' \
          > "$NGIT_CI_OUTPUT_DIR/summary.txt"
      '';
    }}/bin/ngit-grasp-ci-verify";
  };
}
