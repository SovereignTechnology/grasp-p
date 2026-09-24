# Nix Flakes - Learnings and Gotchas

**Purpose:** Document Nix flake patterns, gotchas, and best practices learned during ngit-grasp development  
**Last Updated:** November 4, 2025

---

## Critical Gotchas

### Always Use `nix develop`, Not `nix-shell`

**Problem:** We use `flake.nix`, not `shell.nix`. Using `nix-shell` will fail or use the wrong environment.

```bash
# ✅ Correct - for flake.nix
cd grasp-audit
nix develop
nix develop -c cargo build

# ❌ Wrong - for shell.nix (we don't use this)
nix-shell
nix-shell --run "cargo build"
```

**Why:** 
- `nix-shell` looks for `shell.nix` or `default.nix`
- `nix develop` looks for `flake.nix`
- We migrated from `shell.nix` to `flake.nix` on November 4, 2025

---

## Flake Structure

### Our Standard Flake Pattern

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        manifest = pkgs.lib.importTOML ./Cargo.toml;
      in with pkgs; {
        # Development shell
        devShells.default = mkShell {
          nativeBuildInputs = [
            rust-bin.stable.latest.default
            pkg-config
            gitlint
          ];
          buildInputs = [
            openssl
          ];
          shellHook = ''
            echo "🦀 Development environment loaded"
            export RUST_SRC_PATH=${pkgs.rustPlatform.rustLibSrc}
          '';
        };
        
        # Package output
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = manifest.package.name;
          version = manifest.package.version;
          src = ./.;
          cargoLock = { lockFile = ./Cargo.lock; };
          buildInputs = [ openssl ];
          nativeBuildInputs = [ pkg-config ];
          doCheck = false;  # Run tests separately
        };
      });
}
```

### Key Components

1. **rust-overlay**: Provides latest stable Rust toolchain
2. **flake-utils**: Cross-platform support helper
3. **manifest**: Auto-read version from Cargo.toml
4. **devShells.default**: Development environment
5. **packages.default**: Buildable package

---

## Common Flake Commands

### Essential Commands

```bash
# Enter development shell
nix develop

# Run command in dev shell (one-off)
nix develop -c cargo build

# Show flake outputs
nix flake show

# Check flake validity
nix flake check

# Update flake inputs (like updating dependencies)
nix flake update

# Build the package directly
nix build

# Run without installing
nix run

# Show flake metadata
nix flake metadata
```

### Debugging Commands

```bash
# Show detailed evaluation trace
nix develop --show-trace

# Print flake evaluation
nix eval .#devShells.x86_64-linux.default

# Check what's in the store
nix path-info .#packages.x86_64-linux.default
```

---

## Subproject Flakes

### grasp-audit Has Its Own Flake

**Important:** `grasp-audit/` is a subproject with its own `flake.nix` and `Cargo.toml`.

```bash
# ✅ Correct - enter grasp-audit environment
cd grasp-audit
nix develop
cargo build

# ❌ Wrong - can't build from root
cd ngit-grasp
cargo build  # This won't find grasp-audit dependencies
```

**Why:**
- Each Rust workspace needs its own Nix environment
- Dependencies are project-specific
- Flake inputs are locked per-project

---

## Migration from shell.nix to flake.nix

### What Changed

**Before (shell.nix):**
```nix
{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = with pkgs; [
    rustc
    cargo
    openssl
    pkg-config
  ];
}
```

**After (flake.nix):**
- Locked inputs (reproducible)
- Multi-output (dev shell + package)
- Cross-platform by default
- Better tooling integration

### Migration Steps

1. Create `flake.nix` with standard structure
2. Run `nix flake check` to validate
3. Update all documentation: `nix-shell` → `nix develop`
4. Test that build works: `nix develop -c cargo build`
5. Remove `shell.nix`
6. Commit changes

---

## Benefits of Flakes

### Reproducibility

**Locked inputs** ensure everyone gets the same environment:

```bash
# flake.lock contains exact commits
$ cat flake.lock
{
  "nodes": {
    "nixpkgs": {
      "locked": {
        "lastModified": 1698611440,
        "narHash": "sha256-jPjHjrerhYDy3q9+s5EAsuhyhuknNfowY6yt6pjn9pc=",
        "rev": "23e89e0c8c5e2d9cf5b5e7c3e8e8e8e8e8e8e8e8"
      }
    }
  }
}
```

Everyone running `nix develop` gets **exactly** this version of nixpkgs.

### Multi-Output

Single flake provides:
- **devShells.default**: Development environment
- **packages.default**: Buildable package
- **apps.default**: Runnable application (optional)

### Composability

Flakes can use other flakes as inputs:

```nix
{
  inputs = {
    grasp-audit.url = "path:./grasp-audit";
  };
}
```

---

## Common Issues

### Issue: "error: getting status of '/nix/store/...': No such file or directory"

**Cause:** Flake inputs need to be updated or fetched

**Solution:**
```bash
nix flake update
nix develop
```

### Issue: "error: experimental feature 'nix-command' is not enabled"

**Cause:** Nix flakes are experimental and need to be enabled

**Solution:**
Add to `~/.config/nix/nix.conf`:
```
experimental-features = nix-command flakes
```

### Issue: Changes to flake.nix not taking effect

**Cause:** Flake evaluation is cached

**Solution:**
```bash
# Clear evaluation cache
nix flake update
# Or force re-evaluation
nix develop --refresh
```

### Issue: "error: cannot find flake 'flake:self' in the flake registries"

**Cause:** Not in a git repository or flake.nix not committed

**Solution:**
```bash
git add flake.nix flake.lock
git commit -m "Add flake"
```

**Note:** Flakes require git. Uncommitted files are ignored by default.

---

## Best Practices

### 1. Always Commit flake.lock

```bash
git add flake.lock
git commit -m "Update flake inputs"
```

**Why:** Ensures reproducibility across machines and CI/CD

### 2. Use Specific Rust Versions When Needed

```nix
# Latest stable (default)
rust-bin.stable.latest.default

# Specific version
rust-bin.stable."1.75.0".default

# Nightly
rust-bin.nightly."2024-01-01".default
```

### 3. Include Helpful Shell Hooks

```nix
shellHook = ''
  echo "🦀 GRASP Audit development environment"
  echo ""
  echo "Common commands:"
  echo "  cargo build       - Build project"
  echo "  cargo test        - Run tests"
  echo "  cargo run         - Run binary"
  echo ""
  export RUST_SRC_PATH=${pkgs.rustPlatform.rustLibSrc}
'';
```

### 4. Separate Build and Runtime Dependencies

```nix
# Build-time only
nativeBuildInputs = [
  pkg-config
  rustc
  cargo
];

# Runtime needed
buildInputs = [
  openssl
];
```

### 5. Disable Tests in Package Build

```nix
packages.default = pkgs.rustPlatform.buildRustPackage {
  # ...
  doCheck = false;  # Run tests separately with cargo test
};
```

**Why:** Faster builds, tests run via `cargo test` in dev shell

---

## Workflow Examples

### Daily Development

```bash
# Start work
cd grasp-audit
nix develop

# Inside nix shell
cargo build
cargo test
cargo run -- --help

# Exit shell
exit
```

### CI/CD

```bash
# One-off commands (no interactive shell)
nix develop -c cargo build
nix develop -c cargo test --lib
nix develop -c cargo test -- --ignored
```

### Building Release

```bash
# Build package directly
nix build

# Result is in ./result/bin/
./result/bin/grasp-audit --version
```

---

## References

- **Nix Flakes Manual**: https://nixos.org/manual/nix/stable/command-ref/new-cli/nix3-flake.html
- **rust-overlay**: https://github.com/oxalica/rust-overlay
- **flake-utils**: https://github.com/numtide/flake-utils

---

## Quick Reference

| Task | Command |
|------|---------|
| Enter dev shell | `nix develop` |
| Run one command | `nix develop -c <command>` |
| Show outputs | `nix flake show` |
| Validate flake | `nix flake check` |
| Update inputs | `nix flake update` |
| Build package | `nix build` |
| Run package | `nix run` |

---

*Last updated: November 4, 2025*  
*Status: Living document - update as we learn more*
