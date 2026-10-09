# Release tooling uses the published static CLI on its supported target.
# v3.0.3 corresponds to source commit 31e48be58ee3fa2e3c56b1df68b6358c385d5e91.
# SHA-256 verified against upstream signed NIP-82 asset:
# a96d55c145a9afc9f2c39d14d7112df7015baa41721b4a816172bb9e3d3e046e
# Other targets retain the exact source-pinned package supplied by the flake.
{ pkgs, sourcePackage }:
if pkgs.stdenv.hostPlatform.system != "x86_64-linux" then sourcePackage else
pkgs.stdenvNoCC.mkDerivation {
  pname = "ngit-release-cli";
  version = "3.0.3";
  src = pkgs.fetchurl {
    urls = [
      "https://blossom.primal.net/d0022122370c8e3982fce0b4c185b060139fc1a74de1637e7c005ffffcaab024"
      "https://github.com/DanConwayDev/ngit-cli/releases/download/v3.0.3/ngit-v3.0.3-x86_64-unknown-linux-musl.tar.gz"
    ];
    sha256 = "d0022122370c8e3982fce0b4c185b060139fc1a74de1637e7c005ffffcaab024";
    name = "ngit-3.0.3.tar.gz";
  };
  sourceRoot = ".";
  dontConfigure = true;
  dontBuild = true;
  dontStrip = true;
  dontPatchELF = true;
  installPhase = ''
    runHook preInstall
    install -Dm755 ngit "$out/bin/ngit"
    install -Dm755 git-remote-nostr "$out/bin/git-remote-nostr"
    runHook postInstall
  '';
  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck
    test "$("$out/bin/ngit" --version)" = 'ngit 3.0.3'
    runHook postInstallCheck
  '';
  meta.platforms = [ "x86_64-linux" ];
}
