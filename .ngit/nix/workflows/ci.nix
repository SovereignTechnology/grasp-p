{ pkgs, craneLib, rustToolchain, src, version }:
let
  source = craneLib.cleanCargoSource src;
  vendor = craneLib.vendorCargoDeps { src = source; };
  objects = craneLib.buildDepsOnly {
    pname = "ngit-grasp-ci-dependencies";
    version = "0.0.0";
    src = source;
    strictDeps = true;
    nativeBuildInputs = [ pkgs.pkg-config ];
    buildInputs = [ pkgs.openssl ];
    CARGO_PROFILE = "dev";
    CARGO_INCREMENTAL = "0";
    CARGO_PROFILE_DEV_DEBUG = "0";
    cargoExtraArgs = "--workspace --locked";
    installCargoArtifactsMode = "use-zstd";
    doCompressAndInstallFullArchive = true;
  };
  tools = with pkgs; [
    rustToolchain stdenv.cc pkg-config git bash coreutils gnumake
    gnused gnugrep gnutar gzip findutils
  ];
  command = name: script: pkgs.writeShellApplication {
    inherit name;
    runtimeInputs = tools;
    runtimeEnv = {
      CC = if pkgs.stdenv.cc.isClang then "clang" else "gcc";
      PKG_CONFIG = "pkg-config";
      PKG_CONFIG_PATH = "${pkgs.openssl.dev}/lib/pkgconfig";
      SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
    };
    text = script;
  };
  rust = name: script: command name ''
    export AR="ar" CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0
    export NGIT_BUILD_REVISION="''${NGIT_CI_COMMIT_SHA:-$(git rev-parse HEAD)}"
    export CARGO_TARGET_DIR="''${CARGO_TARGET_DIR:-$PWD/target}"
    if [[ ! -e "$CARGO_TARGET_DIR/.rustc_info.json" ]]; then
      mkdir -p "$CARGO_TARGET_DIR"
      ${pkgs.gnutar}/bin/tar --use-compress-program=${pkgs.zstd}/bin/zstd \
        -xf ${objects}/target.tar.zst -C "$CARGO_TARGET_DIR"
    fi
    export CARGO_HOME="$CARGO_TARGET_DIR/ci-cargo-home"
    mkdir -p "$CARGO_HOME"
    cp --remove-destination ${vendor}/config.toml "$CARGO_HOME/config.toml"
    ${script}
  '';
in {
  dependencies = pkgs.linkFarm "ngit-grasp-ci-dependencies" ([
    { name = "objects"; path = objects; }
    { name = "sources"; path = vendor; }
    { name = "openssl"; path = pkgs.openssl.dev; }
  ] ++ map (tool: { name = tool.name; path = tool; }) tools);
  commands = {
    format = command "format" "cargo fmt --all -- --check";
    compile = rust "compile" "cargo test --workspace --locked --offline --no-run";
    lint = rust "lint" "cargo clippy --workspace --all-targets --locked --offline -- -D warnings";
    tests = rust "tests" ''
      # Keep intentionally hostile Git defaults private to this test step.
      export HOME="$CARGO_TARGET_DIR/test-home"
      mkdir -p "$HOME"
      ${builtins.readFile ./ci-hostile-git.sh}
      cargo test --workspace --locked --offline
    '';
  };
  container = import ./ci-container.nix { inherit pkgs version; };
}
