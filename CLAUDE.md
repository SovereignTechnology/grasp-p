# CLAUDE.md

This repository is SovTech's fork of **ngit-grasp** (a GRASP server: Nostr relay plus git smart
HTTP) carrying **GRASP-P**, an extension for private repositories where the server stores only
ciphertext. Upstream's own agent guide is `AGENTS.md`; read it for code patterns and the
four-source configuration rule. Where the two disagree, this file wins.

## Start here

1. `docs/grasp-p/CLOUD-HANDOFF.md` - current state and the next task.
2. `docs/grasp-p/SEAMS.md` - where GRASP-P touches upstream's files, what changed with v3,
   and what the server needs at run time. Read it before an upstream sync.
3. `docs/grasp-p/PLAN.md` - the whole plan and every product decision already taken.
4. `docs/grasp-p/OVERVIEW.md` - how the system works, in one page.

## Branches

| Branch | What it is | Rule |
|---|---|---|
| `main` | Upstream v3.0.7 plus GRASP-P and the GitLab pipeline, merged by merge request | Never push to it |
| `legacy/v1.2-grasp-p` | The complete GRASP-P server on upstream v1.2.0, before the port | Read-only reference |

Do new work on a branch cut from `main`.

## Rules

- **Commit identity:** `git -c user.name=sovtech -c user.email=git@sovtech.pro commit ...`.
  Pass it on every commit; do not rely on ambient git config.
- **No AI attribution anywhere:** no `Co-Authored-By`, no "Generated with", no session links, in
  commits, pull requests or files.
- Commit subjects start with `sovtech:`. Never squash, never rebase or amend a pushed commit;
  fix forward.
- Run `git status` immediately before every `git commit`.
- Stage files by path. Never `git add -A` or `git add .`: tests and tools write key files and
  keystores into the working directory.
- **Overlay discipline:** GRASP-P code lives in `src/grasp_p/` and other files of its own. Changes
  to upstream's files are thin seams. Upstream owns `src/private/` (its GRASP-08 mode); never put
  GRASP-P code there. Settings are `NGIT_GRASP_P_*`; `NGIT_PRIVATE_*` belongs to upstream.
- Do not switch `reqwest` to `rustls`. It links a second crypto provider and every `wss://`
  dial then panics.
- **Never commit secrets.** The server writes `.relay-owner.nsec` into its working directory;
  run test servers from a temporary directory. Test keys must be generated at run time or be
  obvious throwaway constants inside test code.
- Never print a secret key, token or password into output, logs or commit messages.

## Building and testing

- `rust-toolchain.toml` pins Rust 1.96.0, the release upstream builds and lints with. Where
  rustup is present it installs that version by itself; a newer clippy rejects upstream code.
- In a cloud sandbox use plain `cargo` (there is no nix there, whatever `AGENTS.md` says):
  `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --locked -- -D warnings`,
  `cargo test --locked`, `cargo test -p grasp-audit --locked`.
- The test suite needs `git` 2.42 or newer on `PATH` (Debian 12's 2.39.5 fails it; see
  `docs/grasp-p/SEAMS.md`) and spawns the built server on loopback ports.
- A cold build is slow. Run long builds and test runs in the background and poll them.
- Builds and tests belong in the cloud sandbox or in CI. Never run them on a SovTech host.

## Out of scope for a cloud session

Deployment, the GitLab project, CI runners and anything on SovTech hosts. The canonical repository
is on Nostr (`nostr://npub1s0vtech…/git.sovit.xyz/grasp-p`, the `origin` remote on the
maintainer's machine); GitLab (`gitlab`) runs CI and GitHub is a public read-only mirror. Push
branches here, and they are carried to the other remotes from the maintainer's machine.
