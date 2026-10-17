{ pkgs, rustToolchain, src, version, craneLib, ngit }:
let
  ci = import ./ci.nix { inherit pkgs rustToolchain src version craneLib; };
  release = import ./release.nix { inherit pkgs rustToolchain version ngit; };
in {
  checks = release.checks;
  dependencies = ci.dependencies;
  commands = {
    rust_ci.rust = ci.commands;
    container_deployment.container-deployment = ci.container;
    release = {
      container = release.commands.release-container;
      publish-container = release.commands.publish-container;
      verify-container = release.commands.verify-container;
      publish-release = release.commands.publish-release;
    };
    crates_release.publish = release.commands.publish-crates;
    container_backfill = {
      container = release.commands.backfill-container;
      publish-container = release.commands.publish-container;
      verify-container = release.commands.verify-container;
    };
  };
}
