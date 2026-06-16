# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Project Structure

**Single Cargo Workspace with Two Crates:**

- Root: `ngit-grasp` (main GRASP relay implementation)
- `grasp-audit/`: Audit/compliance tool crate, a member of the same workspace

Both crates share **one** `Cargo.lock`, **one** `flake.nix`, and **one** `target/`
directory at the repo root. There is no separate lockfile or flake inside
`grasp-audit/`. You can build either crate from anywhere in the workspace; cargo
resolves the workspace root automatically.

```bash
# Build everything
nix develop -c cargo build

# Build / test just the audit crate (from the repo root)
nix develop -c cargo build -p grasp-audit
nix develop -c cargo test  -p grasp-audit
```

> grasp-audit has no dependency on ngit-grasp; the coupling is one-directional
> (ngit-grasp's dev-dependencies use grasp-audit). It is co-located only because
> the audit suite's release cadence is currently driven by ngit-grasp features.
> It is structured to be split into its own crate/repo if an external consumer
> ever starts driving its roadmap. Do **not** publish to crates.io yet.

## Build & Test

### Nix Flakes (Non-Standard)

**CRITICAL:** Use `nix develop`, NOT `nix-shell` (we use flake.nix, not shell.nix)

The single root flake exposes both packages and one dev shell:

```bash
# ✅ Correct (one dev shell for the whole workspace)
nix develop -c cargo build
nix develop -c cargo build -p grasp-audit

# Build either crate as a Nix package
nix build .#ngit-grasp
nix build .#grasp-audit

# ❌ Wrong
nix-shell
nix-shell --run "cargo build"
```

### Testing ngit-grasp (Main Project)

**ngit-grasp integration tests use the [`TestRelay`](tests/common/relay.rs:14) fixture:**

The `TestRelay` fixture automatically starts an instance of ngit-grasp itself and manages its lifecycle:

```bash
# Run all ngit-grasp tests (from project root)
cargo test

# Run integration tests only
cargo test --test '*'

# Run specific test file
cargo test --test nip01_compliance
```

**How TestRelay works:**

- Spawns `ngit-grasp` binary on a random available port
- Creates temporary directories for git and relay data
- Provides `url()` and `domain()` methods for test clients
- Automatically cleans up on drop

**Example test pattern:**

```rust
use common::TestRelay;

#[tokio::test]
async fn test_something() {
    let relay = TestRelay::start().await;
    // relay.url() returns "ws://127.0.0.1:{port}"
    // ... run test against ngit-grasp ...
    relay.stop().await;
}
```

### Summary: Which Test Command for What

| What you're testing         | Command                                                                |
| --------------------------- | ---------------------------------------------------------------------- |
| ngit-grasp (this project)   | `cargo test` from project root                                         |
| ngit-relay (reference impl) | `cd grasp-audit && nix develop -c bash test-ngit-relay.sh --mode test` |
| grasp-audit unit tests      | `nix develop -c cargo test -p grasp-audit --lib`                       |

### Running Single Test

```bash
# ngit-grasp test (from project root)
cargo test --test nip01_compliance test_websocket_connection -- --nocapture

# grasp-audit test (from anywhere in the workspace)
nix develop -c cargo test -p grasp-audit --lib specific_test_name -- --nocapture
```

### Troubleshooting

**Buffer Size Errors:**
If you see mpsc channel buffer size panics on first test run, this is usually transient. Simply run the tests again.

**Port Conflicts:**
Both `TestRelay` and `test-ngit-relay.sh` use random ports to avoid conflicts. If you see port errors, ensure no stale processes are running.

## Code Patterns

### nostr-sdk 0.43 Breaking Changes (vs 0.35)

**Field access, not method calls:**

```rust
// ❌ WRONG (0.35 API)
event.id()
event.tags()
for tag in &event.tags { }

// ✅ CORRECT (0.43 API)
event.id          // Direct field access
event.tags        // Direct field access
event.tags.iter() // Iterator method
```

**Tag API changed:**

```rust
// ❌ WRONG (0.35)
Tag::Generic(TagKind::Custom("clone".into()), vec![...])

// ✅ CORRECT (0.43)
Tag::custom(TagKind::custom("clone"), vec![...])
```

**EventBuilder signature changed:**

```rust
// ❌ WRONG (0.35)
EventBuilder::new(kind, content, &[tags])

// ✅ CORRECT (0.43)
EventBuilder::new(kind, content).tags(tags)
```

### Audit Event Tagging (grasp-audit)

**All audit events automatically include cleanup tags:**

The grasp-audit system automatically adds three tags to every event for production cleanup and test isolation. These tags are added transparently via [`AuditEventBuilder::build()`](grasp-audit/src/audit.rs:120-129) with 100% coverage through [`AuditClient::event_builder()`](grasp-audit/src/client.rs:107-138).

**Automatic Tags (no manual intervention needed):**

```rust
// These tags are automatically added to EVERY audit event:
["t", "grasp-audit-test-event"]              // Identifies all audit test events
["t", "audit-{run_id}"]                      // Unique ID for this audit run (correlates events)
["t", "audit-cleanup-after-{unix_timestamp}"] // Unix timestamp for cleanup scheduling
```

**Tag Format Details:**

- Uses standard NIP-01 `"t"` (hashtag) tags for maximum compatibility
- Unix timestamps (not ISO 8601) for easier database queries
- All tags added automatically when calling `client.event_builder().build()`
- No manual tag management required

**Verifying Tags in Tests:**

```rust
// Test that verifies automatic tag addition:
// See: grasp-audit/src/client.rs:273-302
#[test]
fn test_audit_tags_automatically_added() {
    // Creates event and verifies all three tags are present
}
```

**Testing Implications:**

- All audit events are tagged for easy cleanup
- Use `run_id` tag to correlate events from same audit run
- Tags enable production relay cleanup scripts
- No special handling needed in test code - tags are automatic

## Configuration Management

**⚠️ CRITICAL: Keep Configuration in Sync Across All Four Sources**

Configuration options must be consistent across four locations:

1. **Source code** (`src/config.rs`) - Defines actual config structs, env vars, and defaults
2. **Documentation** (`docs/reference/configuration.md`) - User-facing reference for all options
3. **NixOS module** (`nix/module.nix`) - NixOS deployment configuration
4. **Example env file** (`.env.example`) - Template for development and Docker deployments

**When adding/modifying ANY configuration option:**

1. **Update `src/config.rs`** - Add/modify the field with proper env var name
2. **Update `docs/reference/configuration.md`** - Document the option with examples and defaults
3. **Update `nix/module.nix`** - Add/modify the NixOS option in `instanceOptions`
4. **Update `.env.example`** - Add the option with comments explaining usage and defaults
5. **Verify consistency** - Check env var names, defaults, and descriptions match exactly

**Critical consistency checks:**

- Environment variable names must match: `NGIT_*` in code, docs, module, and .env.example
- Default values must match across all four sources
- Option names should be consistent (snake_case in code, camelCase in NixOS)
- Descriptions should be similar (can be more detailed in docs)

**Example: Adding a new config option**

```rust
// 1. src/config.rs
#[arg(long, env = "NGIT_NEW_OPTION", default_value_t = 42)]
pub new_option: u32,
```

```markdown
<!-- 2. docs/reference/configuration.md -->
#### `NGIT_NEW_OPTION`
**Description:** What this option does
**Type:** Integer
**Default:** `42`
**Required:** No
```

```nix
# 3. nix/module.nix (in instanceOptions)
newOption = mkOption {
  type = types.int;
  default = 42;
  description = "What this option does";
};

# Also add to environment mapping in mkService:
environment = {
  # ...
  NGIT_NEW_OPTION = toString cfg.newOption;
};
```

```bash
# 4. .env.example
# What this option does
# CLI: --new-option <value>
# Default: 42
# NGIT_NEW_OPTION=42
```

## Documentation

**⚠️ CRITICAL: Keep Architecture Docs Updated**

Architecture and design documents are LIVING DOCUMENTS. When implementation diverges from the documented plan:

1. **Update the doc IMMEDIATELY** - Don't wait until "later"
2. **Document what was actually built**, not what was originally planned
3. **Note why decisions changed** - Future readers need this context
4. **Files to watch:** `docs/explanation/architecture.md`, `docs/explanation/decisions.md`

This was a key learning from GRASP-01: docs described plans, not implementation, causing confusion.

**Diátaxis Framework Used:**

- `docs/tutorials/` - Learning-oriented
- `docs/how-to/` - Task-oriented
- `docs/reference/` - Information-oriented
- `docs/explanation/` - Understanding-oriented

**Session files go in `work/` (gitignored except README.md)**

- Archive valuable content to `docs/archive/YYYY-MM-DD-*.md` at session end
- Delete temporary files
- Keep root clean (only README.md, AGENTS.md)

## Critical Gotchas

1. **Single workspace:** One `Cargo.lock` and one `flake.nix` at the root cover both crates. Build the audit crate with `cargo build -p grasp-audit` (no `cd` needed).
2. **Nix environment:** Must use `nix develop`, not `nix-shell`
3. **nostr-sdk API:** Fields not methods in 0.43
4. **Test isolation:** Integration tests use `TestRelay` (ngit-grasp) or `test-ngit-relay.sh` (ngit-relay)
5. **Work directory:** All session docs go in `work/`, NOT root
6. **Archive naming:** Use `YYYY-MM-DD-description.md` format
7. **test-ngit-relay.sh tests ngit-relay**: This script tests the reference implementation, NOT ngit-grasp
8. **Configuration sync:** Config changes MUST be updated in all four places: `src/config.rs`, `docs/reference/configuration.md`, `nix/module.nix`, AND `.env.example`
9. **Git dependencies:** When updating `Cargo.toml` or `Cargo.lock` with ANY git dependency (not crates.io), you MUST update hashes in BOTH `flake.nix` and `nix/module.nix`. See [docs/how-to/update-git-dependencies.md](docs/how-to/update-git-dependencies.md) - this is MANDATORY and builds will fail if skipped

## File Restrictions by Mode

Code mode can only edit files matching specific patterns (enforced by system):

- Example: Architect mode restricted to `\.md$` files only
- Attempting to edit restricted files causes FileRestrictionError
- Check mode configuration if edit attempts fail unexpectedly

## Quick Reference

```bash
# Test ngit-grasp (main project)
cargo test

# Build grasp-audit
nix develop -c cargo build -p grasp-audit

# Run grasp-audit unit tests
nix develop -c cargo test -p grasp-audit --lib

# Check session files
ls work/  # Should only have README.md when clean
```
