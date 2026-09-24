# GRASP Audit Tool - Patterns and Learnings

**Purpose:** Document grasp-audit architecture, patterns, and lessons learned  
**Last Updated:** December 4, 2025

---

## Overview

`grasp-audit` is a **fully implemented** compliance testing tool for GRASP (Git Relays Authorized via Signed-Nostr Proofs) protocol implementations. It tests both Nostr relay compliance (NIP-01) and GRASP-specific functionality.

---

## Architecture Decisions

### Separate Crate Strategy

**Decision:** Build `grasp-audit` as a separate crate from `ngit-grasp`

**Why:**

1. **Parallel Development**: Can build tests before implementation
2. **Isolated Testing**: Tests run in isolation (CI/CD safe)
3. **Production Auditing**: Can audit live production services
4. **Reusability**: Other GRASP implementations can use it

**Location:** `grasp-audit/` subdirectory with own `Cargo.toml` and `flake.nix`

---

### Audit Event Tagging Strategy

**Problem:** Test events pollute the relay and need cleanup without deletion events.

**Solution:** Use special tags to mark audit events (implemented in [`grasp-audit/src/audit.rs`](grasp-audit/src/audit.rs)):

```rust
// Every audit event includes these tags (added automatically)
[
    ["t", "grasp-audit-test-event"],           // Marker
    ["t", "audit-{run-id}"],                   // Run isolation
    ["t", "audit-cleanup-after-{timestamp}"]   // Cleanup time
]
```

**Benefits:**

- ✅ **Queryable**: Can find all audit events via tag filter
- ✅ **Isolated**: Each test run has unique run ID
- ✅ **Self-cleaning**: Cleanup timestamp indicates when to delete
- ✅ **No deletion events**: Direct database cleanup, no KIND 5 events
- ✅ **Production safe**: Won't interfere with real events

---

### Standard "t" Tags vs Custom Tags

**Evolution:**

1. **Original**: Custom single-letter tags (`g`, `r`, `c`)
2. **Current**: Standard NIP-01 "t" tags with prefixed values

**Why we changed:**

- ❌ Custom tags could conflict with other systems
- ✅ "t" tag is standard for categorization/topics
- ✅ Multiple "t" tags are expected and supported
- ✅ Self-documenting values (`audit-{run-id}` vs just `{run-id}`)
- ✅ Better namespacing with prefixes

**Migration:** Completed November 4, 2025

---

## Code Patterns

### Audit Configuration

From [`grasp-audit/src/audit.rs`](grasp-audit/src/audit.rs):

```rust
use grasp_audit::audit::AuditConfig;

// CI mode - isolated test runs
let config = AuditConfig::isolated();
// Generates UUID run ID: "ci-{uuid}"
// Cleanup after 1 hour

// Production mode - persistent run ID
let config = AuditConfig::shared();
// Uses provided run ID
// Cleanup after 24 hours
```

**When to use:**

- **CI mode**: Automated testing, parallel runs, temporary
- **Production mode**: Manual audits, monitoring, persistent

---

### Creating Audit Events

From [`grasp-audit/src/client.rs`](grasp-audit/src/client.rs):

```rust
use grasp_audit::client::AuditClient;
use grasp_audit::audit::AuditConfig;

let config = AuditConfig::isolated();
let client = AuditClient::new("ws://localhost:7334", config).await?;

// Create and send an event - cleanup tags are added automatically
let event = client.event_builder()
    .kind(Kind::TextNote)
    .content("test content")
    .build(&keys)?;

client.send_event(event).await?;
```

---

### Test Suites

From [`grasp-audit/src/specs/grasp01/mod.rs`](grasp-audit/src/specs/grasp01/mod.rs):

```
grasp-audit/src/specs/grasp01/
├── mod.rs                    # Module exports
├── nip01_smoke.rs            # NIP-01 basic functionality
├── nip11_document.rs         # NIP-11 document tests
├── event_acceptance_policy.rs # GRASP-01 event rules
├── cors.rs                   # CORS header tests
├── git_clone.rs              # Git clone operations
├── push_authorization.rs     # Push validation tests
├── repository_creation.rs    # Repository lifecycle
└── spec_requirements.rs      # Requirement definitions
```

### Unit vs Integration Tests

**Unit Tests** (no relay required):

```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_audit_config() {
        let config = AuditConfig::isolated();
        assert!(config.run_id.starts_with("ci-"));
    }
}
```

**Integration Tests** (relay required):

```rust
#[cfg(test)]
mod tests {
    #[tokio::test]
    #[ignore]  // Requires relay
    async fn test_smoke_tests_against_relay() {
        // Test against real relay
    }
}
```

**Running tests:**

```bash
# Unit tests (fast, no dependencies)
cd grasp-audit && nix develop -c cargo test --lib

# Integration tests (requires relay via test-ngit-relay.sh)
cd grasp-audit && nix develop -c bash test-ngit-relay.sh --mode test
```

---

### Test Result Reporting

From [`grasp-audit/src/result.rs`](grasp-audit/src/result.rs):

```rust
use grasp_audit::result::AuditResult;

// Run tests
let results = vec![
    AuditResult::pass("websocket_connection", "Connected successfully"),
    AuditResult::fail("invalid_event", "Expected rejection, got acceptance"),
];

// Report
for result in &results {
    println!("{}", result);
}

// Summary
let passed = results.iter().filter(|r| r.passed).count();
let total = results.len();
println!("Results: {}/{} passed ({:.1}%)",
    passed, total, (passed as f64 / total as f64) * 100.0);
```

---

## CLI Design

### Command Structure

```bash
grasp-audit audit [OPTIONS]

Options:
  --relay <URL>        Relay to test (required)
  --mode <MODE>        ci or production (default: ci)
  --run-id <ID>        Custom run ID (production mode only)
  --spec <SPEC>        Test spec to run (default: all)
  --verbose            Detailed output
```

### Usage Examples

```bash
# CI mode - quick smoke test
grasp-audit audit \
  --relay ws://localhost:7000 \
  --mode ci \
  --spec nip01-smoke

# Production mode - full compliance audit
grasp-audit audit \
  --relay wss://relay.example.com \
  --mode production \
  --run-id "audit-2025-12-04" \
  --verbose

# Test all specs
grasp-audit audit --relay ws://localhost:7000
```

---

## Lessons Learned

### 1. Tag Migration is Breaking

**Lesson:** Changing tag structure breaks event queries.

**Impact:** Events created with old tags won't be found by new queries.

**Mitigation:**

- ✅ Accept breaking changes in alpha stage
- ✅ Document migration clearly
- ✅ Old events auto-expire via cleanup
- ✅ No production deployments affected

---

### 2. Test Data Lifecycle Matters

**Lesson:** Test events accumulate and pollute relay.

**Solution:** Built-in cleanup strategy from day one.

**Implementation:**

- Every event has cleanup timestamp
- Relay can cleanup expired events
- No deletion event pollution (direct DB cleanup)

---

### 3. Isolation Enables Parallel Testing

**Lesson:** Unique run IDs enable parallel test execution.

**Benefit:** CI/CD can run multiple test suites simultaneously.

**Pattern:**

```rust
// Each CI run gets unique ID
let config = AuditConfig::isolated();
// run_id = "ci-{uuid}"

// Tests isolated by run ID
let events = client.query().await?;
// Only returns events for this run
```

---

### 4. Standards Compliance Reduces Friction

**Lesson:** Using standard NIP-01 "t" tags instead of custom tags.

**Benefits:**

- ✅ No conflicts with other systems
- ✅ Standard relay filtering works
- ✅ Better interoperability
- ✅ Self-documenting

---

## What's Implemented

### Completed Features

- ✅ **GRASP-01 Test Suites**: All NIP-01, NIP-11, CORS, event acceptance tests
- ✅ **Spec Requirements Database**: Machine-readable requirements in [`spec_requirements.rs`](grasp-audit/src/specs/grasp01/spec_requirements.rs)
- ✅ **Automatic Cleanup Tags**: Production-safe event tagging
- ✅ **Test Isolation**: UUID run IDs for parallel execution
- ✅ **AuditClient**: Nostr client wrapper with audit features
- ✅ **Fixture Helpers**: Event creation helpers in [`fixtures.rs`](grasp-audit/src/fixtures.rs)

### Future Enhancements

- [ ] **GRASP-02 Test Suite**: Proactive sync tests
- [ ] **HTML Report Generation**: Rich CI/CD reports
- [ ] **Performance Benchmarks**: Measure relay performance
- [ ] **Relay Comparison**: Side-by-side compliance comparison

---

## Common Issues

### Issue: Integration Tests Fail

**Symptoms:** Tests timeout or fail to connect

**Causes:**

1. No relay running
2. Wrong relay URL
3. Firewall blocking connection

**Solution:**

```bash
# Use test-ngit-relay.sh for automated relay management
cd grasp-audit && nix develop -c bash test-ngit-relay.sh --mode test

# Or manually:
docker run --rm -p 18081:8081 ghcr.io/danconwaydev/ngit-relay:latest
RELAY_URL="ws://localhost:18081" nix develop -c cargo test --lib -- --ignored
```

---

### Issue: Events Not Found in Query

**Symptoms:** Query returns empty even though events were sent

**Causes:**

1. Wrong run ID (querying different run)
2. Connection timing (query before event propagated)
3. Tag mismatch (uppercase vs lowercase)

**Solution:**

```rust
// Use same config for send and query
let config = AuditConfig::isolated();

// Wait for event to propagate
tokio::time::sleep(Duration::from_millis(500)).await;

// Verify tags match exactly
let t_tag = SingleLetterTag::lowercase(Alphabet::T);  // Lowercase!
```

---

### Issue: Build Fails in CI

**Symptoms:** `cargo build` fails with dependency errors

**Cause:** Not in Nix dev environment

**Solution:**

```bash
# Enter Nix environment first
cd grasp-audit
nix develop

# Then build
cargo build
```

---

## Quick Reference

### Configuration

```rust
// CI mode
let config = AuditConfig::isolated();

// Production mode
let config = AuditConfig::shared();
```

### Client Usage

```rust
let client = AuditClient::new("ws://localhost:7000", config).await?;
assert!(client.is_connected().await);
```

### Running Tests

```bash
# Unit tests (from grasp-audit/)
nix develop -c cargo test --lib

# Integration tests with ngit-relay
nix develop -c bash test-ngit-relay.sh --mode test

# CLI audit
nix develop -c cargo run -- audit --relay ws://localhost:7000
```

### Key Files

| File | Purpose |
|------|---------|
| [`grasp-audit/src/lib.rs`](grasp-audit/src/lib.rs) | Public API |
| [`grasp-audit/src/client.rs`](grasp-audit/src/client.rs) | AuditClient implementation |
| [`grasp-audit/src/audit.rs`](grasp-audit/src/audit.rs) | AuditConfig, cleanup tags |
| [`grasp-audit/src/specs/grasp01/mod.rs`](grasp-audit/src/specs/grasp01/mod.rs) | Test suite registry |
| [`grasp-audit/src/specs/grasp01/spec_requirements.rs`](grasp-audit/src/specs/grasp01/spec_requirements.rs) | Requirement database |

---

## Related Documentation

- [Test Strategy](../reference/test-strategy.md) - Overall testing approach
- [GRASP-01 Implementation](grasp-01-implementation.md) - Main project learnings