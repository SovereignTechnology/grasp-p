{ pkgs, rustToolchain, version, ngit }:
let
  tools = [ pkgs.git pkgs.coreutils pkgs.python3 ngit ];
  context = builtins.readFile ./release-context.sh;
  command = name: inputs: text: pkgs.writeShellApplication {
      inherit name;
      runtimeInputs = tools ++ inputs;
      text = context + text;
  };
  provenance = ''
    python3 - <<'PYTHON'
import json, os
from pathlib import Path
Path(os.environ["NGIT_CI_OUTPUT_DIR"], "provenance.json").write_text(json.dumps({
    "tag": os.environ["NGIT_CI_REF"],
    "version": os.environ["version"],
    "source_commit": os.environ["release_revision"],
    "workflow_commit": os.environ["NGIT_CI_COMMIT_SHA"],
}))
PYTHON
  '';
  containerCommand = name: workload: import ./ci-container.nix {
      inherit pkgs version name;
      extraInputs = tools ++ [ pkgs.gnutar ];
      workload = context + workload;
  };
in {
  tools = pkgs.linkFarm "ngit-grasp-publisher-tools"
    (map (tool: { name = tool.name; path = tool; }) tools);
  commands = {
    release-container = containerCommand "ngit-grasp-release-container" ''
      [[ $NGIT_CI_TRIGGER == push ]] || { echo 'Use container backfill for manual runs' >&2; exit 1; }
      scripts/build-container-layout.sh "$version" "$release_revision" "$NGIT_CI_OUTPUT_DIR/layout"
      ${provenance}
    '';
    backfill-container = containerCommand "ngit-grasp-backfill-container" ''
      [[ $NGIT_CI_TRIGGER == manual ]] || { echo 'Backfill requires a manual run' >&2; exit 1; }
      source_directory=$(mktemp -d "$TMPDIR/backfill-source.XXXXXX")
      git archive "$release_revision" | tar -xf - -C "$source_directory"
      CONTAINER_CONTEXT="$source_directory" CONTAINER_EXACT_ONLY=true \
        scripts/build-container-layout.sh "$version" "$release_revision" "$NGIT_CI_OUTPUT_DIR/layout"
      ${provenance}
    '';
    verify-container = containerCommand "ngit-grasp-verify-container" ''
      scripts/verify-published-container.sh "$version"
    '';
    publish-container = command "ngit-grasp-publish-container" [] (builtins.readFile ./publish-container.sh);
    publish-release = command "ngit-grasp-publish-release" [] (builtins.readFile ./publish-release.sh);
    publish-crates = command "ngit-grasp-publish-crates" [ rustToolchain pkgs.pkg-config pkgs.openssl ] ''
      export PKG_CONFIG_PATH="${pkgs.openssl.dev}/lib/pkgconfig"
      ${builtins.readFile ./publish-crates.sh}
    '';
  };
  checks.release-cli = pkgs.runCommand "ngit-grasp-release-cli-check" {
    nativeBuildInputs = [ ngit ];
  } ''
    ngit release publish --help > release.txt
    for option in --nbunksec-file --manifest --channel --tag --commit --released-at --repo-relay-only; do
      grep -q -- "$option" release.txt
    done
    ngit container publish --help > container.txt
    for option in --nbunksec-file --manifest --defaults --repo-relay-only; do
      grep -q -- "$option" container.txt
    done
    mkdir -p "$out"
    ln -s ${ngit} "$out/ngit"
  '';
  checks.release-scripts = pkgs.runCommand "ngit-grasp-release-script-tests" {
    nativeBuildInputs = [ pkgs.python3 pkgs.bash pkgs.git pkgs.coreutils ];
  } ''
    python3 ${./release-tests.py} ${./.}
    touch "$out"
  '';
}
