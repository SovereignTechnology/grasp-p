# Reliable test fixtures

## Reproduce the Nix CI checks

Branch pushes and pull requests use `.ngit/nix/workflows/rust_ci.yaml`.
The workflow builds the following root-flake checks independently:

```sh
nix build .#checks.x86_64-linux.ci-lint
nix build .#checks.x86_64-linux.ci-tests
```

`ci-lint` checks formatting and runs Clippy for the whole workspace with
warnings denied. `ci-tests` builds both binaries and runs workspace unit,
integration and documentation tests with offline Cargo dependencies. It retains
the deliberately hostile ambient Git settings used by the previous act CI.
The fixtures bind local sockets; they do not need external relay access.
The Nix sandbox isolates those sockets from the host network. PR execution
adds a Firecracker boundary around the complete provider job.

Each job succeeds when its checks exit successfully. These validation jobs do
not publish artifacts or run a separate artifact-verification job. Providers
may run the checks concurrently on different machines. The same workflow also
runs `release-scripts` and `release-cli` to validate the publication guards
and pinned CLI compatibility without publishing.

The normal packaging outputs (`ngit-grasp`, `grasp-audit`, `static`) remain
unchanged. Tag validation and publication also use native Nix workflows; see
[publishing releases](publish-release.md).

## Reproduce the container deployment check

`.ngit/nix/workflows/container_deployment.yaml` runs the `ci-container-deployment`
app when deployment-relevant files change and on pull requests. When the
provider supplies `NGIT_CI_STEP`, its result reports separate durations for
building the OCI image, importing it, and running deployment tests. Local runs
and older providers execute the same commands without timing instrumentation.

The app owns its container daemon: the flake pins Docker, containerd, runc, iptables and
skopeo, and the app starts `dockerd` with its data, exec root and socket under
`$HOME`, waits for readiness with a deadline, runs
`scripts/test-container-release.sh` and stops the daemon. A Firecracker Nix
provider supplies only a disposable VM with root, cgroup v2 and loadable kernel
modules. On any other provider the app stops before starting the daemon and
names the missing requirement.

The app needs root, so run it only in a disposable VM:

```sh
nix run .#ci-container-deployment
```

It reads `NGIT_CI_COMMIT_SHA` and `NGIT_CI_OUTPUT_DIR`. On a workstation with
an existing Docker daemon, run the script directly instead; it honours
`DOCKER_HOST`:

```sh
nix shell nixpkgs#docker-client nixpkgs#curl nixpkgs#jq nixpkgs#skopeo \
  --command scripts/test-container-release.sh \
  "$(nix eval --raw .#static.version)" "$(git rev-parse HEAD)"
```

Release and manual container backfill jobs use the same daemon wrapper; see
[publishing releases](publish-release.md).

## Fixture rules

Run tests through the repository development shell. Keep parallel checks
enabled: each fixture owns its socket, tasks, subprocesses and temporary data.

## Socket ownership

Allocate loopback port zero and transfer the bound listener into the server.
Do not bind, inspect the port, drop the socket and bind that port again.
Subprocess fixtures pass `NGIT_TEST_LISTENER_FD` with `NGIT_TEST=1` on Unix.
The binary advertises this private protocol through
`--internal-test-listener-support`; it is not deployment configuration and is
not exposed through the NixOS module or example service environment.

`TestRelay` retains a parent copy across same-address restarts. Offline relay
scenarios use `UnavailableEndpoint`, which accepts and closes connections
while retaining the socket, then transfers that socket to the recovered
server. This prevents another parallel test from taking the offline address.

## Observable readiness and shutdown

Wait for HTTP readiness, connected-state metrics, or the expected event with
a bounded deadline. A successful TCP connection, a connection attempt counter,
and an arbitrary grace period do not prove that a server is ready.

Connection tasks belong to their fixture's accept loop. Stopping the fixture
cancels and joins them; dropping it cancels the owner. Git fixture subprocesses
are cancelled with their request, and all three pipes are driven concurrently.

## Shared repository identity

`setup_announcement_on_relay` returns an announcement and a `RepositoryFixture`.
Prepare it once for each logical repository, then call `fixture.install(&relay)`
for every other relay. It reuses the signed announcement, signed state event,
and Git commit. Repeating setup independently can create competing replaceable
events at the same owner/identifier and different Git histories.

List all participating domains when preparing the fixture. If historic tests
must seed a source before starting the syncing relay, reserve the target's
listener first and transfer it into the target after seeding. Do not use sleeps
or fabricated future timestamps to order copies of the same fixture. Tests of
actual repository revisions should construct those revisions explicitly.

The sync regression `reinstalling_shared_repository_preserves_event_ids_and_git_refs`
checks exact announcement/state IDs and remote Git refs across installation and
reinstallation on two relays.

## Replacement ordering

Ordinary revisions must explicitly advance beyond their predecessor. Use
`common::event_ordering::timestamp_after(previous.created_at)` when building
an event, or `event_after(event, keys, previous.created_at)` to re-sign a
fabricated event while retaining its payload and audit tags. Advancement is
checked for overflow and follows future-dated predecessors too; it does not
use a global counter or wait for the wall clock. For re-announcements after a
coordinate deletion, advance beyond the signed deletion's cutoff. Subsequent
revisions advance beyond the last revision, not the original event.

Keep explicit timestamps for deliberate historical, cutoff and conflict tests.
To exercise equal-timestamp ID ordering, build two distinct candidates for the
same coordinate and timestamp, sort by ID, and submit the larger ID before the
smaller one. Do not mine against a random predecessor: even a large bounded
search can fail for a sufficiently low ID. Nonce tags can be present on both
candidates when their compatibility is part of the scenario.

## Time and streaming assertions

Age private cache timestamps explicitly and bracket wall-clock timestamps
before and after the operation. Streaming tests coordinate fake Git with an
owned loopback gate, collect bytes independently of HTTP frame boundaries,
and retain assertions about terminal flush and post-push promotion ordering.
Fixed sleeps remain appropriate only when elapsed time is itself under test;
polling an observable condition must always have a bounded deadline.

For maintenance batching, seed all due inputs before explicitly invoking the
manager pass and inspect the emitted query. Sequential network publications can
straddle timer ticks and acquire different retry deadlines; waiting longer does
not guarantee they will ever share a batch. Keep separate integration coverage
for admission and eventual recovery through the public protocol.

Targeted regressions include `fixture_lifecycle`, `relay_identity`,
`git_response_streaming`, and the shared Git-server tests in `sync`.
Full package validation remains necessary after these scoped checks.
