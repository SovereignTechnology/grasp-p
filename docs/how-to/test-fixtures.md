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

## Time and streaming assertions

Age private cache timestamps explicitly and bracket wall-clock timestamps
before and after the operation. Streaming tests coordinate fake Git with an
owned loopback gate, collect bytes independently of HTTP frame boundaries,
and retain assertions about terminal flush and post-push promotion ordering.
Fixed sleeps remain appropriate only when elapsed time is itself under test;
polling an observable condition must always have a bounded deadline.

Targeted regressions include `fixture_lifecycle`, `relay_identity`,
`git_response_streaming`, and the shared Git-server tests in `sync`.
Full package validation remains necessary after these scoped checks.
