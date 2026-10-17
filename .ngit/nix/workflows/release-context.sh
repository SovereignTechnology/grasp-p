# Shared by release apps before any build or publication effect.
case "${NGIT_CI_TRIGGER:-}" in
  push | manual) ;;
  *) echo 'Release jobs require a tag push or manual tag replay' >&2; exit 1 ;;
esac
[[ ${NGIT_CI_REF_TYPE:-} == tag && ${NGIT_CI_REF:-} == refs/tags/v* ]] || {
  echo 'Release jobs require a refs/tags/v* allocation' >&2; exit 1;
}
[[ ${NGIT_CI_COMMIT_SHA:-} =~ ^[0-9a-f]{40}$ ]] || { echo 'Missing allocated commit' >&2; exit 1; }
[[ $(git rev-parse HEAD) == "$NGIT_CI_COMMIT_SHA" ]] || { echo 'Checkout differs from allocation' >&2; exit 1; }
repo=nostr://npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/relay.ngit.dev/ngit-grasp
# Provider checkouts have no ambient remote or tag objects. Fetch only the
# requested tag and reject a moved tag before it can drive a release effect.
timeout 60 git fetch --no-tags --depth=1 "$repo" "$NGIT_CI_REF:$NGIT_CI_REF"
release_revision=$(git rev-parse "$NGIT_CI_REF^{commit}")
[[ $release_revision =~ ^[0-9a-f]{40}$ ]] || { echo 'Invalid release revision' >&2; exit 1; }
if [[ $NGIT_CI_TRIGGER == push ]]; then
  [[ $release_revision == "$NGIT_CI_COMMIT_SHA" ]] || {
    echo 'Release tag differs from allocated commit' >&2; exit 1;
  }
  version=$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["package"]["version"])')
else
  [[ ${NGIT_CI_WORKFLOW_PATH:-} == .ngit/nix/workflows/container_backfill.yaml ]] || {
    echo 'Historical source is allowed only by the container backfill workflow' >&2; exit 1;
  }
  # Backfill deliberately builds historical source using the current reviewed
  # workflow. Only the named tag's data and Dockerfile are taken from it.
  version=$(git show "$release_revision:Cargo.toml" | python3 -c 'import sys,tomllib; print(tomllib.loads(sys.stdin.read())["package"]["version"])')
fi
[[ $NGIT_CI_REF == "refs/tags/v$version" ]] || {
  echo 'Release tag must match Cargo.toml version' >&2; exit 1;
}
released_at=$(git for-each-ref --format='%(creatordate:unix)' "$NGIT_CI_REF")
[[ $released_at =~ ^[0-9]+$ ]] || { echo 'Missing release tag date' >&2; exit 1; }
export version repo released_at release_revision
