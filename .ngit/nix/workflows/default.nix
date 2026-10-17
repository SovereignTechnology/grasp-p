{ pkgs, rustToolchain, src, version, craneLib, ngit }:
let
  ci = import ./ci.nix { inherit pkgs rustToolchain src version craneLib; };
  release = import ./release.nix { inherit pkgs rustToolchain version ngit; };
in {
  checks = release.checks;
  dependencies = ci.dependencies;
  publisher-tools = release.tools;
  container-tools = pkgs.linkFarm "ngit-grasp-container-tools" [
    { name = "daemon"; path = ci.container; }
    { name = "release-context"; path = release.tools; }
  ];
  commands = {
    rust_ci.rust = ci.commands;
    container_deployment.container-deployment.test = ci.container;
    release = {
      container.build = release.commands.release-container;
      publish-container.publish = release.commands.publish-container;
      verify-container.verify = release.commands.verify-container;
      publish-release.publish = release.commands.publish-release;
    };
    crates_release.publish.publish = release.commands.publish-crates;
    container_backfill = {
      container.build = release.commands.backfill-container;
      publish-container.publish = release.commands.publish-container;
      verify-container.verify = release.commands.verify-container;
    };
  };
}
