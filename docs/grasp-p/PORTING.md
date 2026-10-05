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

## Still to do

Seams in upstream files (legacy diff: `git diff cbf6f1d legacy/v1.2-grasp-p -- <file>`):

| File | Legacy change | Note |
|---|---|---|
| `src/lib.rs` | `pub mod private` | now `pub mod grasp_p` |
| `src/config.rs` | +794 | all settings, renamed; add the GRASP-08 mutual-exclusion check |
| `src/server.rs` | +28 | construct the service, thread it through |
| `src/http/mod.rs` | +93 | blob routes; make them base-path aware (`strip_base_path`) |
| `src/http/nip11.rs` | +9 | `private_repos` advert |
| `src/nostr/builder.rs` | +234 | the admission arm in `Nip34WritePolicy::admit_event` |
| `src/nostr/lifecycle/deletion/service.rs` | +6 | claim freeing on kind 5 / 62 |
| `src/metrics/mod.rs` | +365 | additive |
| `src/sync/filters.rs` | +157 | derived filters |
| `src/sync/mod.rs` | +715 | **rewrite** against upstream's grouped subscriptions |
| `src/sync/relay_connection.rs` | +28 | **rewrite**, small |
| `tests/common/relay.rs` | +85 | the two `TestRelay` constructors, on `PortReservation` |
| `nix/module.nix`, `.env.example`, `docs/reference/configuration.md` | | the four-source config rule |
| `Cargo.toml` | | the watchdog bin; keep upstream's `native-tls` |

API moves since nostr 0.45.0-alpha.3:

- `nostr_relay_builder::prelude::*` is gone; use `nostr_sdk::local_relay`.
- `nostr::hashes` is no longer re-exported; use `bitcoin_hashes`.

Design changes to make during the port:

- GRASP-P and GRASP-08 (`NGIT_PRIVATE_MODE`) are mutually exclusive at config validation.
- The blob mirror goes through upstream's `src/outbound.rs` policy.
- Do not switch `reqwest` to `rustls`: that pulled a second crypto provider and made the
  legacy binary panic on its first TLS connection.
