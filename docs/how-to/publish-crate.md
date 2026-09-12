# Publish ngit-grasp to crates.io

Nostr CI publishes `ngit-grasp` after the existing formatting, lint and test
steps pass for a `v*` tag push. The tag must exactly match `v` followed by the
package version in `Cargo.toml`, including any prerelease suffix. Branch pushes
and pull requests do not publish crates. The unpublished `grasp-audit` workspace
member is not selected for publication.

Configure the repository's `CARGO_REGISTRY_TOKEN` secret in ngit-ci with a
crates.io token scoped to publishing `ngit-grasp`. The token is supplied only
to the publication step; Cargo does not write a login credential file.

The workflow runs `cargo publish --locked --registry crates-io --package
ngit-grasp`, including Cargo's package verification. A missing token or an
already-published version fails the step; the workflow does not overwrite or
automatically bump releases.

The workflow must be included in the tagged commit. Adding it does not
backfill existing tags, and crate publication is independent of the existing
archive, NIP-82 and container publication jobs. It requires no GitHub registry
authentication.
