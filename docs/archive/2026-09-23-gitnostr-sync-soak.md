# gitnostr.com sync startup soak — 2026-09-23

Deployed ngit-grasp `56889bfc1df28282e1edfa229ee0029584fc9353` to
nixos-fi1's gitnostr.com instance with `deploy . --remote-build --skip-checks`.
Activation was confirmed at 15:21:50 UTC. The deployment pin is nixos-fi1
commit `44f3c21`. Other GRASP instances retained their original start times.

## Observations

The final sample at 15:37:24 UTC covered 15 minutes 34 seconds:

- 126 connected relays after 49 seconds; 176 at approximately 14 minutes.
  Final sample: 168 connected / 305 tracked, with 137 fully caught up,
  26 syncing history, and 5 connected with historic-sync failures.
- No service restarts, panics, nonzero persistence-error windows, or
  `[PARSE_FAIL]` messages. Public NIP-11 and WebSocket repository reads passed.
- 26 transient watchdog expirations and 66 incomplete-batch retirements.
  Timeout cleanup appeared promptly in the actor while other relays continued
  syncing. Not every watchdog needs a batch-retirement log: a batch may already
  have been removed by another terminal or disconnect.
- 173,153 hydration deliveries, predominantly duplicates; 85 invalid outcomes
  and no retryable rejection or persistence-error outcomes in the sampled
  hydration metrics.
- Service cgroup memory grew from 1.90 GiB at 49 seconds to 3.03 GiB at the
  final sample. Discovery was still active. This soak does not establish a
  long-term memory plateau or demonstrate a leak.
- Startup integrity reported the same 60 unique PR references requiring manual
  inspection as the previous deployment; no new references appeared.

## Remaining issues

1. Forty `filter item too large` refusals across nos.lol, relay.damus.io,
   and strfry.bonsai.com. The refusal classifier does not recognize this
   deterministic filter incompatibility, so incomplete-batch retirement allows
   unchanged work to be retried. Add classification/cooldown coverage before
   considering the soak completely clean.
2. nos.lol twice failed complete live extension because it needed 20 and then
   22 slots against 18 usable slots. Investigate budget-aware regrouping or
   fallback; a connected transport alone does not prove complete coverage.
3. Continue observing memory beyond startup and the existing integrity findings.

The global startup stall is substantially improved, and timeout/invalid-PR
behavior matches the intended fixes. The deployment remains active. No further
application changes were made during this soak.

Raw local evidence is under `work/soak-56889bf/` (gitignored): timestamped
metrics/state snapshots, current and previous startup journals, and read probes.
