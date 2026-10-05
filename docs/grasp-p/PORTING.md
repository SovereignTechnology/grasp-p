# Porting GRASP-P onto ngit-grasp v3

Working notes for the port from the v1.2.0-based line (`legacy/v1.2-grasp-p`) to
upstream v3.0.7. Delete this file when the port is merged.

## Done mechanically (this branch's first commit)

- Every file that existed only in the legacy line is carried over unchanged, except:
  - `src/private/*` now lives in `src/grasp_p/*`. Upstream owns `src/private/` for GRASP-08.
  - `crate::private` and `ngit_grasp::private` are `...::grasp_p`.
  - Settings `NGIT_PRIVATE_*` are `NGIT_GRASP_P_*` (upstream uses `NGIT_PRIVATE_MODE`,
    `NGIT_PRIVATE_MEMBERS`, `NGIT_PRIVATE_PUBLIC_ORIGIN` for GRASP-08).

This does not compile yet: the seams below are not wired.

## Carried by three-way apply (second commit)

The legacy change to each of these applied onto v3.0.7 with the renames above; where both
sides had added lines at the same place, both were kept.

`src/config.rs`, `src/lib.rs`, `src/metrics/mod.rs`, `src/http/nip11.rs`,
`src/nostr/lifecycle/deletion/service.rs`, `src/sync/filters.rs`,
`src/sync/relay_connection.rs`, `Cargo.toml` (watchdog bin, `url`, `heed`; **not** the
`rustls` switch), `nix/module.nix`, `.env.example`, `docs/reference/configuration.md`,
`docs/how-to/prometheus-setup.md`.

None of this has been compiled. `Cargo.lock` is untouched and must be regenerated.

## Still to do

These five conflicted too heavily and are still upstream's v3.0.7 versions. Port each by
hand with the compiler; the legacy change is `git diff cbf6f1d legacy/v1.2-grasp-p -- <file>`.

| File | Legacy change | Conflicts | Note |
|---|---|---|---|
| `src/server.rs` | +28 | 3 | construct the service, thread it beside upstream's `private_access` |
| `src/http/mod.rs` | +93 | 9 | blob routes; make them base-path aware (`strip_base_path`); rename the `private` field |
| `src/nostr/builder.rs` | +234 | 4 | the admission arm in `Nip34WritePolicy::admit_event` |
| `src/sync/mod.rs` | +715 | 12 | **rewrite** against upstream's grouped subscriptions |
| `tests/common/relay.rs` | +85 | 5 | the two `TestRelay` constructors, on `PortReservation` |

Also: config validation for the GRASP-08 exclusion, `grasp-audit/Cargo.toml` stays upstream's.

API moves since nostr 0.45.0-alpha.3:

- `nostr_relay_builder::prelude::*` is gone; use `nostr_sdk::local_relay`.
- `nostr::hashes` is no longer re-exported; use `bitcoin_hashes`.

Design changes to make during the port:

- GRASP-P and GRASP-08 (`NGIT_PRIVATE_MODE`) are mutually exclusive at config validation.
- The blob mirror goes through upstream's `src/outbound.rs` policy.
- Do not switch `reqwest` to `rustls`: that pulled a second crypto provider and made the
  legacy binary panic on its first TLS connection.
