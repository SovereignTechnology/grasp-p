# Reference

**Information-oriented documentation** - Technical details and specifications.

---

## What Is Reference Documentation?

Reference documentation provides **factual, technical information** that you look up when needed.

**Characteristics:**
- ✅ Information-oriented (facts and data)
- ✅ Comprehensive and accurate
- ✅ Structured for lookup
- ✅ Dry and to-the-point
- ✅ Maintained as code changes

**Not reference:**
- ❌ Learning materials (those are Tutorials)
- ❌ Problem-solving guides (those are How-To)
- ❌ Conceptual explanations (those are Explanation)

---

## Available Reference Documentation

### [Deployment Contract](deployment-contract.md)

Shared process, endpoint, persistence, identity, backup, single-writer, health,
and upgrade requirements for every supported hosting environment.

---

### [Configuration](configuration.md)
**Complete reference for all configuration options**

**Contents:**
- Environment variables
- Configuration file format
- Validation rules
- Examples for development/production/testing

**Use when:** You need to know what a config option does or what values are valid

---

### [Git Protocol](git-protocol.md)
**Git Smart HTTP protocol specification**

**Contents:**
- Protocol overview
- Pkt-line format
- Request/response structure
- Reference updates format
- Parsing examples

**Use when:** You need to understand Git HTTP internals

---

### [Test Strategy](test-strategy.md)
**Testing approach and compliance framework**

**Contents:**
- Test categories (unit, integration, compliance)
- GRASP compliance requirements
- Test isolation strategy
- Running tests
- Coverage requirements

**Use when:** You're writing tests or need to understand test structure

---

## Planned Reference Documentation

### GRASP Protocol
**Status:** 🔜 Planned

**Contents:**
- GRASP-01 requirements
- GRASP-02 (Proactive Sync)
- GRASP-05 (Archive)
- Event formats
- Validation rules

---

### API Reference
**Status:** 🔜 Planned (waiting for main server)

**Contents:**
- HTTP endpoints
- Request/response formats
- Error codes
- Authentication
- Rate limiting

---

### nostr-sdk Upgrade Guide
**Status:** 🔜 Planned

**Contents:**
- Version compatibility matrix
- Breaking changes by version
- Migration examples
- Common patterns

---

### Event Formats
**Status:** 🔜 Planned

**Contents:**
- NIP-34 repository announcements (kind 30317)
- NIP-34 state events (kind 30318)
- Custom tags
- Validation rules

---

### CLI Reference
**Status:** 🔜 Planned

**Contents:**
- Command-line arguments
- Subcommands
- Environment variables
- Exit codes

---

## How to Use Reference Documentation

1. **Know what you're looking for** - Reference is for lookup, not learning
2. **Use search or table of contents** - Find the specific detail you need
3. **Check version** - Ensure docs match your version
4. **Verify with code** - Reference should match implementation

**Not sure if this is what you need?**
- New to the topic? → [Tutorials](../tutorials/)
- Trying to solve a problem? → [How-To Guides](../how-to/)
- Want to understand concepts? → [Explanation](../explanation/)

---

## Contributing Reference Documentation

When writing reference documentation:

**DO:**
- ✅ Be accurate and complete
- ✅ Use consistent structure
- ✅ Include all options/parameters
- ✅ Provide examples
- ✅ Update when code changes
- ✅ Use tables for structured data

**DON'T:**
- ❌ Explain concepts (link to Explanation)
- ❌ Provide tutorials (link to Tutorials)
- ❌ Solve problems (link to How-To)
- ❌ Include opinions or recommendations

**Template:**
```markdown
# Reference: [Topic]

**Purpose:** [What this reference covers]  
**Audience:** [Who needs this information]

---

## Overview

[Brief description of what's being documented]

---

## [Section 1]

### [Item]

**Description:** [What it is/does]  
**Type:** [Data type]  
**Default:** [Default value]  
**Required:** [Yes/No]

**Examples:**
\`\`\`
[Example usage]
\`\`\`

**Notes:**
- [Important details]

---

## Related Documentation
- [Links to relevant docs]
```

See [Diátaxis: Reference](https://diataxis.fr/reference/) for detailed guidance.

---

*Part of the [ngit-grasp documentation](../README.md) using the [Diátaxis](https://diataxis.fr/) framework.*
