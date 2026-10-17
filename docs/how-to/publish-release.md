# Publish releases with native Nix CI

All CI workflows live in `.ngit/nix/workflows/`. A `v*` tag push runs
`release.yaml`: a pure static-musl archive build and a container layout build,
followed by OCI publication, a pull-and-run verification, and NIP-82 publication.
The publisher copies the exact predecessor archive/layout; it does not rebuild
release products. The container builder preserves the repository Dockerfile
and `scripts/build-container-layout.sh`. Its base-image pulls retain that
Dockerfile's existing update policy.

Release apps pin Git, Python, ngit, Cargo and container tooling in the root
flake. The separate `release-ngit` input must support both release and container
publication; `checks.x86_64-linux.release-cli` verifies its required flags.
Checks and publishers share `.ngit/nix/workflows/release-ngit.nix`: on x86_64 Linux it installs
the SHA-256-pinned static v3.0.3 release archive, avoiding a lengthy LTO rebuild
in every fresh guest. The upstream source package disables its own tests, so
recompiling it added no CLI test coverage. Other platforms retain the pinned
source package. The archive pin trusts the upstream release build; it is not a
claim of locally reproduced binaries. Keep the archive version/hash and source
fallback revision aligned when updating this tooling.
Container build and verification jobs reuse the deployment test's job-owned
Docker daemon. They require a disposable root VM with the kernel facilities
listed in their workflow requirements, and clean up the daemon on exit.

Configure the repository `NGIT_PUBLISHER_NBUNKSEC` secret. Only the OCI and
NIP-82 publisher jobs request it, and pass its private
`$NGIT_CI_SECRETS_DIR/NGIT_PUBLISHER_NBUNKSEC` file directly to ngit. No secret
value enters a Nix derivation, output artifact, or command argument. The
existing `.ngit/release.yaml` and `.ngit/containers.yaml` retain the publication
metadata, relays and Blossom servers. Archive contents are reproducible with
a fixed tar timestamp; the NIP-82 release date comes from the actual Git tag.

Every release app requires an explicit tag context and fetches that tag from
the Nostr repository. Ordinary tag pushes check the Cargo version and both
the checkout and peeled tag against the signed `NGIT_CI_COMMIT_SHA`. A moved tag fails before
publication. Branch or pull-request contexts cannot publish.

## Manual container backfill

Replay `.ngit/nix/workflows/container_backfill.yaml` from a commit containing
this workflow with an explicit `refs/tags/v<version>` context. The current
reviewed app fetches only that historical tag, validates its Cargo version,
and extracts its source into the job's private workspace. It builds and
publishes only the exact OCI version tag, preserving `latest` and prerelease
aliases, then pulls and verifies the image. It does not publish a crate or
NIP-82 release.

This is the deliberate exception to ordinary release source matching: the
signed allocation commit supplies the workflow, tools and publisher while
the named historical tag supplies the Dockerfile and build context. A separate
predecessor provenance artifact records the version, ref, historical source
commit and allocation commit. The publisher refetches the tag and checks that
record before copying the layout and publishing. Historical source never
supplies the credentialed publisher code. Tags are neither moved nor created.

Crates.io publication remains independent; see
[publishing the crate](publish-crate.md). For nonpublishing validation run:

```sh
nix build .#checks.x86_64-linux.release-cli .#checks.x86_64-linux.release-scripts
```

These checks inspect CLI compatibility and exercise release guards, secret
handling and artifact fan-in using fake external commands. They do not publish
or perform a full Docker release run. Providers must allow enough predecessor
artifact bytes for the OCI layout (including extracted archive transport).
