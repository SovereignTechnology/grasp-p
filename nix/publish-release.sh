[[ $NGIT_CI_TRIGGER == push ]] || { echo 'NIP-82 publication requires a tag push' >&2; exit 1; }
mkdir -p dist
archive="ngit-grasp-$version-x86_64-unknown-linux-musl.tar.gz"
cp "${NGIT_CI_INPUTS:?}/archive/artifacts/release-archive/$archive" "dist/$archive"
if [[ $version == *-* ]]; then
  prerelease=${version#*-}
  channel=${prerelease%%[.+]*}
else
  channel=main
fi
ngit release publish "$version" --repo "$repo" \
  --manifest .ngit/release.yaml --channel "$channel" \
  --tag "${NGIT_CI_REF#refs/tags/}" --commit "$NGIT_CI_COMMIT_SHA" \
  --released-at "$released_at" \
  --nbunksec-file "${NGIT_CI_SECRETS_DIR:?}/NGIT_PUBLISHER_NBUNKSEC" \
  --defaults --repo-relay-only --json
