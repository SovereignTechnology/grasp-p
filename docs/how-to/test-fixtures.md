# Reliable test fixtures

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
