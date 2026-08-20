# Release ngit-grasp

This checklist covers publishing an `ngit-grasp` release and rolling it out to
the project-operated services. It deliberately separates release publication
from production deployment: a valid tag and verified artifacts must exist
before any production data is migrated.

For v3, also follow the
[v2-to-v3 Git family storage upgrade guide](upgrade-git-family-storage.md).
That migration is one-way without restoring a snapshot of both Git and relay
data.

## Publication channels

The release owner must account for each channel explicitly:

| Channel | v3 action | Notes |
|---|---|---|
| Canonical Nostr repository | Required | Push `master` and the version tag to `origin`. This is the source of truth. |
| ngit-ci release assets | Required | A `v*` tag automatically builds the x86_64 static archive and `SHA256SUMS` from that tag. |
| GitHub mirror | Required after reconciliation | The public mirror is [`Pleb5/ngit-grasp`](https://github.com/Pleb5/ngit-grasp). It mirrors source and tags; it is not the collaboration authority. |
| crates.io | Decide before tagging | The main [`ngit-grasp` crate](https://crates.io/crates/ngit-grasp) was last published as `1.2.0`. Publish v3 or explicitly announce that the channel is discontinued. Never publish `grasp-audit`. |
| OCI/container registry | No current release action | There is no maintained `ngit-grasp` Dockerfile, image, or container workflow. |
| Production NixOS services | Deploy only after publication | The project-operated services consume the NixOS module from a pinned Git revision, not a container image. |

[`ghcr.io/danconwaydev/ngit-relay`](https://github.com/DanConwayDev/ngit-relay/pkgs/container/ngit-relay)
is the [archived predecessor](https://ngit.dev/relay/). Its last public version
is `v0.0.5`, and the audit suite uses it only as a reference implementation. Do
not publish an `ngit-grasp` release into that package. There is no public
`danconwaydev` repository on Docker Hub and no public
`ghcr.io/danconwaydev/ngit-grasp` package as of 2026-08-20.

If a supported `ngit-grasp` container is wanted, add and test its Dockerfile,
runtime contract, multi-architecture policy, registry ownership, and tag
workflow as a separate change before including it in a release.

## One-time v3 blockers

Resolve these before preparing the release commit:

- [ ] Reconcile the GitHub mirror. On 2026-08-20 its `master` had five commits
  absent from canonical `master`, while canonical `master` had 261 commits
  absent from the mirror. Do not blindly force-push over those five commits.
- [ ] Decide whether the main crate remains a supported crates.io channel.
  `cargo publish -p ngit-grasp --locked --dry-run` currently succeeds, but the
  lockfile reports yanked dependency versions. Review or refresh them before
  choosing to publish v3.
- [ ] Schedule the v3 maintenance window and arrange snapshots for every
  production instance. A production-scale migration has taken about 51
  minutes.
- [ ] Confirm every intended v3 fix is committed and every release-blocking
  ngit proposal is applied or deliberately deferred.

### Reconcile the GitHub mirror

Configure the mirror remote if it is absent, then inspect both sides:

```bash
git remote add github https://github.com/Pleb5/ngit-grasp.git
git fetch github master
git log --oneline master..github/master
git log --oneline github/master..master
```

If the GitHub-only changes are still required, apply them to the canonical
repository and validate them there. If they are already superseded, record
that decision. A normal fast-forward push is preferred. Use
`--force-with-lease` only after the review establishes that canonical
`master` must replace the mirror branch and a fresh `git fetch github master`
confirms nobody updated it meanwhile.

Never use `git push --mirror`: the GitHub repository has its own branch state,
while Nostr proposal refs and other canonical refs do not belong there.

## 1. Freeze the release candidate

Choose the exact semantic version and tag:

```bash
release_version=3.0.0
release_tag="v${release_version}"
```

- [ ] Fetch the canonical repository and confirm the candidate is based on the
  expected `origin/master`.
- [ ] Confirm `git status --short` is empty.
- [ ] Inspect `ngit pr list --json --status open,draft` for release blockers.
- [ ] Review the complete `v2.1.2..HEAD` log and diff.
- [ ] Confirm the tag does not already exist locally or remotely.
- [ ] Freeze dependency and feature changes. Only release corrections proceed
  after this point.

Useful checks:

```bash
git fetch origin
git log --oneline origin/master..HEAD
git diff --stat v2.1.2..HEAD
git tag --list "$release_tag"
git ls-remote --tags origin "refs/tags/${release_tag}"
```

## 2. Prepare release metadata

- [ ] Set `package.version` in `Cargo.toml` to the release version.
- [ ] Refresh the root `Cargo.lock` so its `ngit-grasp` package entry matches.
- [ ] Set the package version in `nix/module.nix` to the same value.
- [ ] Promote `CHANGELOG.md` from `Unreleased` to a dated release section.
- [ ] Add the release comparison link and advance the `unreleased` link to the
  new tag.
- [ ] Keep `grasp-audit` at its independent version; do not publish it.

`flake.nix` derives the `ngit-grasp` version from `Cargo.toml`, so it no longer
needs a second manual version edit. Verify all remaining occurrences:

```bash
nix develop -c cargo check -p ngit-grasp
nix develop -c cargo metadata --locked --no-deps --format-version 1 \
  | jq -r '.packages[] | [.name, .version] | @tsv'
rg -n '2\.1\.2|3\.0\.0' Cargo.toml Cargo.lock flake.nix nix/module.nix CHANGELOG.md
```

Commit the metadata as one independently reviewable release commit. Do not tag
an uncommitted working tree.

## 3. Validate the release commit

Run the same checks as CI plus both distributable Nix builds:

```bash
nix develop -c cargo fmt --all -- --check
nix develop -c cargo clippy --workspace --all-targets -- -D warnings
nix develop -c cargo test --locked
nix develop -c cargo test -p grasp-audit --locked
nix flake check --no-build --no-write-lock-file
nix build .#ngit-grasp --no-link
nix build .#static --out-link result-static
file result-static/bin/ngit-grasp
result-static/bin/ngit-grasp --version
```

- [ ] Confirm the release binary is a static x86_64 ELF and reports the release
  version.
- [ ] Run a full `grasp-audit audit` against a disposable candidate instance.
- [ ] Exercise the v2-to-v3 migration against a representative snapshot and
  inspect the terminal integrity summary.
- [ ] If crates.io remains supported, run the non-publishing validation:

```bash
nix develop -c cargo publish -p ngit-grasp --locked --dry-run
```

Remove only the temporary result link when finished; the Nix store output is
retained independently:

```bash
unlink result-static
```

## 4. Publish canonical `master`

Push the release commit before creating the tag, then wait for the ordinary
Rust CI workflow to pass:

```bash
git push origin master
git ls-remote origin refs/heads/master
```

- [ ] Confirm the remote OID equals the local release commit.
- [ ] Confirm ngit-ci ran the format, lint, and test workflow successfully.
- [ ] Stop if the pushed commit differs from the locally validated commit.

## 5. Create and publish the immutable tag

Check the package/tag invariant, create an annotated tag, and inspect it before
publishing:

```bash
test "$(nix eval --raw .#static.version)" = "$release_version"
git tag -a "$release_tag" -m "Release ${release_tag}"
git show --stat "$release_tag"
git push origin "$release_tag"
git ls-remote --tags origin "refs/tags/${release_tag}" \
  "refs/tags/${release_tag}^{}"
```

Publishing the tag starts both Rust CI and the release-assets workflow. The
release workflow checks that the tag without its `v` prefix exactly matches
the package version. It then builds from the tagged commit and uploads one
`ngit-grasp-release-assets` artifact containing:

- `ngit-grasp-<version>-x86_64-unknown-linux-musl.tar.gz`
- `SHA256SUMS`

Do not move or reuse a published version tag. Fix a release defect with a new
patch version. A transient CI infrastructure failure may be retriggered against
the same immutable commit.

## 6. Verify release assets

- [ ] Confirm both tag-triggered workflows concluded successfully.
- [ ] Confirm the signed ngit-ci results name the release tag's peeled commit.
- [ ] Download the archive and checksum from the ngit-ci result.
- [ ] Verify the checksum and archive contents on a clean x86_64 Linux host.
- [ ] Run the extracted binary and confirm its version.

```bash
sha256sum --check SHA256SUMS
tar -tzf "ngit-grasp-${release_version}-x86_64-unknown-linux-musl.tar.gz"
tar -xzf "ngit-grasp-${release_version}-x86_64-unknown-linux-musl.tar.gz"
./ngit-grasp-${release_version}-x86_64-unknown-linux-musl/ngit-grasp --version
```

The running binary's NIP-11 `version` must be
`<release-version>-<8-character-commit>`, where the commit is the tag's peeled
commit.

## 7. Synchronize secondary publication channels

Only continue after the canonical tag and ngit-ci assets are verified.

### GitHub mirror

After resolving the divergence described above:

```bash
git push github master
git push github --tags
```

- [ ] Verify GitHub shows the canonical release commit and all historical
  release tags, including the new tag.
- [ ] If GitHub Releases remains a supported download surface, create the
  release for the mirrored tag and attach the exact ngit-ci archive and
  `SHA256SUMS`. Do not rebuild different assets on GitHub.
- [ ] Make clear that issues and pull requests remain on ngit/Nostr.

The `.ngit/act/workflows/` files are not GitHub Actions workflows. Merely
pushing the tag to GitHub does not build or upload assets there.

### crates.io

If the project decided to keep this channel supported:

```bash
nix develop -c cargo publish -p ngit-grasp --locked
```

- [ ] Verify crates.io and docs.rs show the new version and canonical repository
  URL.
- [ ] Never publish `grasp-audit`; it is an internal workspace crate for now.

If crates.io is discontinued, state that prominently in the release notes so
users do not mistake `1.2.0` for the current secure release.

## 8. Roll out production

Production currently consumes the NixOS module from a pinned canonical Git
revision. It does not pull an OCI image.

- [ ] Announce the maintenance window.
- [ ] Stop writes and snapshot each instance's Git and relay-data directories
  together.
- [ ] Verify free space using the capacity guidance in the v3 upgrade guide.
- [ ] Update the deployment flake input to the tag's peeled commit and refresh
  its lockfile.
- [ ] Evaluate and build the deployment before activation.
- [ ] Deploy one lower-risk instance first and wait for its migration and
  integrity checks to complete.
- [ ] Deploy the public instances sequentially rather than migrating every
  service at once.
- [ ] Do not run a v2 binary against data once v3 migration has started.

During each migration, wait for the observable terminal log rather than a fixed
delay:

```text
Git identifier-family integrity startup pass completed
```

After each instance begins listening:

```bash
curl --fail --silent --show-error \
  -H 'Accept: application/nostr+json' https://relay.example/ | jq .version
grasp-audit probe --relay wss://relay.example --json --harden-network
```

- [ ] Confirm NIP-11 reports `3.0.0-<tag-commit>`.
- [ ] Confirm the read-only probe passes.
- [ ] Run a controlled write-path probe or full audit with a disposable,
  authorized identity.
- [ ] Check service errors, migration/integrity counts, Git clone/fetch/push,
  WebSocket traffic, and resource metrics.
- [ ] Retain the pre-v3 snapshots for the agreed rollback window.

## 9. Announce and close the release

- [ ] Publish release notes linking the changelog, canonical tag, checksums,
  installation archive, and v3 upgrade guide.
- [ ] Lead with the security fixes, one-way storage migration, expected
  downtime, snapshot requirement, and minimum safe version.
- [ ] Tell remaining `ngit-relay` container users that the GHCR image is an
  archived predecessor and provide a migration path to native `ngit-grasp`.
- [ ] Verify the canonical repository, GitHub mirror, ngit-ci artifacts, and
  chosen crates.io policy all agree on the released version.
- [ ] Record production deployment commits and post-deployment evidence.

## Rollback and failed-release rules

- Never delete and recreate a public tag to hide a release error.
- Prefer a patch release for code or packaging defects discovered after
  publication.
- Before production migration, rollback means redeploying the previous pinned
  release.
- After v3 migration starts, rollback requires stopping v3 and restoring the
  matching pre-upgrade Git and relay-data snapshots together before starting
  v2. Installing a v2 binary alone is unsafe.
