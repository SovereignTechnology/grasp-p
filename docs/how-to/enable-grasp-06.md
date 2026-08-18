# How to enable GRASP-06 contributor PR submission

GRASP-06 adds an opt-in endpoint at `/prs/<npub>/<identifier>.git` that any contributor can push PR (kind 1618) and PR Update (kind 1619) `refs/nostr/<event-id>` refs to, even when this relay has no accepted announcement for the target repository. The endpoint is unauthenticated at the HTTP level — validity is established by the signed PR event.

This page covers the operator-facing steps to turn it on and verify it.

All paths below are relative to `NGIT_BASE_PATH`. For a relay mounted at
`/grasp`, use `/grasp`, `/grasp/prs/...`, and matching path-prefixed `clone`
tags in the examples.

## 1. Flip the feature flag

Set `NGIT_GRASP06_ENABLE=true` for the relay process. The flag is off by default; everything below is a no-op without it.

**Environment file** (`.env`):

```env
NGIT_GRASP06_ENABLE=true
```

**CLI flag**:

```bash
ngit-grasp --grasp06-enable ...
```

**NixOS module**:

```nix
services.ngit-grasp.instances.<name>.grasp06Enable = true;
```

Restart the relay after the change.

## 2. Verify NIP-11 advertises GRASP-06

NIP-11 is served from `/` with the `Accept: application/nostr+json` header:

```bash
curl -s -H 'Accept: application/nostr+json' https://your-relay.example/ | jq '.supported_grasps'
```

The output must include `"GRASP-06"`. If it does not, the flag did not take effect — re-check the env var name and that the relay actually restarted.

## 3. Verify `/prs/` is reachable

Pick any well-formed npub and any identifier. A non-existent contributor + repo combination is fine — the endpoint synthesises an empty bare repo for fetches against paths that don't yet exist:

```bash
git clone https://your-relay.example/prs/npub1.../any-identifier.git /tmp/probe
```

You should get a successful clone of an empty repository (zero refs). No directory is created on the server for this probe.

To verify a contributor push round-trip, publish a kind 1618 PR event whose `clone` tag names this relay's `/prs/<signer-npub>/<d>.git` URL, then:

```bash
git push https://your-relay.example/prs/<signer-npub>/<d>.git \
    <commit-sha>:refs/nostr/<event-id>
```

The push succeeds, the relay creates `<git_data_path>/prs/<signer-hex>/<d>.git` on demand, and the ref is locked into the repo. Pushes to anything other than `refs/nostr/<64-lowercase-hex>` are rejected with an `ERR` pkt-line.

## Storage cost

One bare repo per `(submitter, identifier)` combination under `<git_data_path>/prs/<submitter-hex>/<identifier>.git`. Repos are garbage-collected inline at the three runtime sites that can leave one empty, plus a startup scan that recovers anything left behind by a previous run — there is no separate periodic sweep over `<git_data_path>/prs/`:

- After receive-pack, the repo is removed immediately if it has zero refs left (probe pushes that produced no valid state).
- When a PR event arrives that fails validation against a scoped `/prs/` placeholder, the corresponding `refs/nostr/<event-id>` ref is deleted; if that leaves the repo with zero refs the directory is removed in the same step.
- When a scoped placeholder expires from purgatory without a matching PR event (default 30 minutes), the standard purgatory sweep deletes the dangling ref and, if it leaves the repo zero-ref, the bare repo itself.
- On startup, before the HTTP server accepts requests, the `/prs/` subtree is scanned once and any zero-ref bare repos (left by a crash mid-push, crash mid-cleanup, or shutdown with in-memory state lost) are removed.

All three sites coordinate through a per-`(submitter, identifier)` mutex and an `in_flight` counter; cleanup paths only `rm -rf` the bare repo while `in_flight == 0`, so an in-flight push cannot have its repo deleted out from under it. The mutex is held only briefly at each site — pack uploads and per-ref validation run lock-free, so concurrent pushes by multiple agents using the same identity do not serialise behind each other.

There is no quota in this release. Disk consumption is bounded only by the rate at which contributors push valid PR refs.

## Abuse controls

The current release relies entirely on:

- the signed PR / PR Update event (no NIP-98 or other HTTP auth on push),
- the requirement that the event's `clone` tag names this relay's `/prs/<signer>/<d>.git` endpoint,
- the standard 30-minute purgatory TTL, and
- the inline zero-ref cleanups described under "Storage cost".

The following knobs are **future** additions and are not yet wired:

- per-submitter allowlist,
- per-submitter or per-event disk quotas,
- per-ref pack size cap,
- NIP-98 authenticated push,
- PoW gating.

If you need any of these today, leave `NGIT_GRASP06_ENABLE=false`.

## Spec

[GRASP-06 spec (draft)](https://github.com/DanConwayDev/grasp/blob/main/06.md). Design notes: [docs/explanation/grasp-06-contributor-pr-submission.md](../explanation/grasp-06-contributor-pr-submission.md).
