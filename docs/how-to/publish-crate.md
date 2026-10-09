# Publish ngit-grasp to crates.io

The native Nix workflow `.ngit/nix/workflows/crates_release.yaml` publishes
`ngit-grasp` after the existing formatting, lint and test steps pass for a `v*` tag push. The tag must exactly match `v` followed by the
package version in `Cargo.toml`, including any prerelease suffix. Branch pushes
and pull requests do not publish crates. The unpublished `grasp-audit` workspace
member is not selected for publication.

Configure the repository's `CARGO_REGISTRY_TOKEN` secret in ngit-ci with a
crates.io token scoped to publishing `ngit-grasp`. The token is supplied as
`$NGIT_CI_SECRETS_DIR/CARGO_REGISTRY_TOKEN` only to the publication app; Cargo
does not write a login credential file.

Separate pure Nix jobs run the existing workspace lint and test checks before
the publication app starts. The app verifies the fetched tag and checkout
against `NGIT_CI_COMMIT_SHA`.

The workflow runs `cargo publish --locked --registry crates-io --package
ngit-grasp`, including Cargo's package verification. A missing token or an
already-published version fails the step; the workflow does not overwrite or
automatically bump releases.

The workflow must be included in the tagged commit. Adding it does not
backfill existing tags, and crate publication is independent of the existing
archive, NIP-82 and container publication jobs. It requires no GitHub registry
authentication.
