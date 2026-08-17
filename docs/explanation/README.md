# Explanation

**Understanding-oriented documentation** - Concepts, design decisions, and the "why" behind ngit-grasp.

---

## What Is Explanation?

Explanation documentation helps you **understand concepts** and design decisions, providing context and discussing alternatives.

**Characteristics:**
- ✅ Understanding-oriented (clarify concepts)
- ✅ Theoretical (ideas and design)
- ✅ Discuss alternatives
- ✅ Provide context and background
- ✅ Answer "why" questions

**Not explanation:**
- ❌ Step-by-step lessons (those are Tutorials)
- ❌ Problem-solving recipes (those are How-To)
- ❌ Technical specifications (those are Reference)

---

## Available Explanation Documentation

### [Architecture Overview](architecture.md)
**Understand the system design and component interaction**

**Topics:**
- Overall architecture
- Component responsibilities
- Data flows
- Technology choices
- Design patterns

**Read when:** You want to understand how ngit-grasp works as a system

---

### [Inline Authorization](inline-authorization.md)
**Why we validate pushes inline instead of using Git hooks**

**Topics:**
- The authorization problem
- Git hooks approach
- Inline approach
- Comparison and trade-offs
- Implementation details

**Read when:** You want to understand the core architectural decision

---

### [Design Decisions](decisions.md)
**Key architectural choices and their rationale**

**Topics:**
- Inline authorization vs hooks
- Technology stack choices
- Storage design
- API design
- Performance considerations

**Read when:** You want to know why things are the way they are

---

### [Comparison with ngit-relay](comparison.md)
**How ngit-grasp differs from the reference implementation**

**Topics:**
- Architecture comparison
- Component differences
- Trade-offs
- Migration path
- Compatibility

**Read when:** You're familiar with ngit-relay and want to understand differences

---

### [Purgatory Design](purgatory-design.md)
**In-memory holding area for events awaiting git data**

**Topics:**
- The "which arrives first?" problem
- Separate storage for state vs PR events
- Late binding for state events
- Bidirectional waiting for PR events
- Authorization during push

**Read when:** You want to understand how ngit-grasp handles out-of-order event/git data arrival

---

### [GRASP-02 Proactive Sync](grasp-02-proactive-sync.md)
**Relay-to-relay synchronization for repository discovery**

**Topics:**
- Negentropy-based event sync
- Repository announcement discovery
- Relay management and reconnection
- Layer 2 filtering
- Bootstrap and dynamic relay discovery

**Read when:** You want to understand how ngit-grasp discovers and syncs repositories across relays

---

### [GRASP-03 Proactive Sync Plus](grasp-03-proactive-sync-plus.md)
**NIP-65 inbox/outbox discovery for accepted repository conversations**

**Read when:** You want to understand how accepted conversations are recovered from participant mailboxes

---

### [Sync Scaling Constraints and Budgets](sync-scaling-constraints.md)
**Relay-imposed limits and how sync spends them at scale**

**Topics:**
- Verified relay limits (strfry, live NIP-11, our embedded relay)
- Per-connection budget ledger (live vs historic vs fallback)
- Byte-budgeted filter chunking and REQ packing
- Bounded negentropy concurrency
- Multi-connection escalation and serving-side obligations

**Read when:** You're changing filter construction, subscription management, or sync concurrency, and need the constraint justification

---

### [GRASP-02 Purgatory Git Data Fetching](grasp-02-proactive-sync-purgatory-git-data.md)
**Proactive git data fetching from remote servers**

**Topics:**
- Identifier-based batching
- Exponential backoff with fresh start
- Domain throttling (5 concurrent, 30/min)
- Debounced delays (3min user, 500ms sync)
- 30-minute expiry
- Mock-based testability

**Read when:** You want to understand how purgatory automatically fetches missing git data

---

### [Unified Git Data Sync](unify-git-data-sync.md)
**Shared processing for git push and purgatory sync paths**

**Topics:**
- Why unify push and sync processing
- OID syncing to owner repos
- Ref alignment logic
- Event release from purgatory
- WebSocket notification

**Read when:** You want to understand how git data is processed consistently regardless of arrival method

---

### [Monitoring Overview](monitoring.md)
**Prometheus metrics and observability**

**Topics:**
- Metrics philosophy
- Connection tracking
- Git operation metrics
- Nostr event metrics
- Privacy considerations

**Read when:** You want to understand how to monitor ngit-grasp in production

---

### [Defensive Measures & Rate Limiting](defensive-measures.md)
**Protection against abuse, spam, and denial-of-service attacks**

**Topics:**
- Connection and subscription management
- Event publishing rate limits
- Content filtering (blacklists/whitelists)
- Event validation plugin system (WritePolicy/QueryPolicy)
- Relay health management (naughty list, exponential backoff)
- Privacy-preserving IP tracking
- Future enhancements (per-IP rate limiting)

**Read when:** You want to understand how ngit-grasp protects against abuse and what defensive features are available

---

### [GRASP-05 Archive Mode](grasp-05-archive.md)
**Read-only mirroring of repositories**

**Topics:**
- Archive whitelist configuration
- Archive-all mode
- Read-only mode defaults
- Use cases for backup/mirror relays

**Read when:** You want to understand how to run an archive/backup relay

---

### [GRASP-08 Private Service Authentication](grasp-08-private-service.md)
**Service-wide NIP-42/NIP-98 authentication for private repositories**

**Topics:**
- Fail-closed private mode and indistinguishable 401 responses
- The GRASP-08 repository-scoped NIP-98 profile vs generic NIP-98
- NIP-42 authentication outside the embedded relay
- Service-wide membership and dynamic accepted-relay-owner admission
- Trust model and follow-up scope

**Read when:** You want to understand how a private GRASP instance authenticates clients and peers

---

### [Repository Lifecycle](repository-lifecycle.md)
**Handling repository removal, holding, archive, recovery, and purgatory**

**Topics:**
- Repository lifecycle architecture
- Delete disrespector concept
- Preventing left-pad scenarios
- Archival policies
- Holding, recovery, purgatory, and operator curation flows

**Read when:** You want to understand how ngit-grasp keeps nostr state and git data aligned across deletion, vanish, moderation, recovery, and purgatory flows

---

### [Identifier-family Git Object Storage](git-family-object-storage.md)
**Deduplicating Git objects across related owner and contributor views**

**Topics:**
- Identifier-scoped object families and thin repository views
- Anonymous receive-pack negotiation through Git alternates
- Local-first storage with an opt-in S3 backend and bounded cache
- No-GC rollback preservation
- Crash-safe launch-time migration from legacy bare repositories

**Read when:** You are changing Git storage, `/prs/` delivery, rollback retention, or server startup migration

---

## Planned Explanation Documentation

### GRASP Protocol Design
**Status:** 🔜 Planned

**Topics:**
- Why Nostr for Git?
- Authorization model
- Trust and verification
- Decentralization benefits

---

### Testing Philosophy
**Status:** 🔜 Planned

**Topics:**
- Why test isolation?
- Integration vs unit tests
- Compliance testing approach
- Test-driven development

---

### Performance Considerations
**Status:** 🔜 Planned

**Topics:**
- Async architecture
- Caching strategy
- Database choices
- Bottlenecks and solutions

---

## How to Use Explanation Documentation

1. **Read to understand** - Not to accomplish a task
2. **Follow your curiosity** - Read what interests you
3. **Connect concepts** - Link ideas together
4. **Question and explore** - Think critically

**Not sure if this is what you need?**
- Want to learn by doing? → [Tutorials](../tutorials/)
- Need to solve a problem? → [How-To Guides](../how-to/)
- Looking for technical details? → [Reference](../reference/)

---

## Contributing Explanation Documentation

When writing explanation:

**DO:**
- ✅ Discuss concepts and ideas
- ✅ Provide context and background
- ✅ Explain alternatives
- ✅ Use analogies and examples
- ✅ Connect to broader context
- ✅ Answer "why" questions

**DON'T:**
- ❌ Provide step-by-step instructions (link to Tutorials/How-To)
- ❌ List technical details (link to Reference)
- ❌ Assume you must be comprehensive
- ❌ Avoid opinions (explanation can be opinionated)

**Template:**
```markdown
# Explanation: [Topic]

**Purpose:** [What concept/decision this explains]  
**Audience:** [Who wants to understand this]

---

## The Problem/Question

[What are we trying to understand?]

---

## Background

[Context and history]

---

## Our Approach

[How we address it]

### Why This Works

[Explanation of benefits]

### Trade-offs

[What we gain and lose]

---

## Alternatives Considered

### [Alternative 1]

**Pros:**
- [Benefits]

**Cons:**
- [Drawbacks]

**Why we didn't choose it:**
[Reasoning]

---

## Conclusion

[Summary of understanding]

---

## Related Documentation
- [Links to relevant docs]
```

See [Diátaxis: Explanation](https://diataxis.fr/explanation/) for detailed guidance.

---

*Part of the [ngit-grasp documentation](../README.md) using the [Diátaxis](https://diataxis.fr/) framework.*
