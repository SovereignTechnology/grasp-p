# ngit-grasp Documentation

Welcome to the **ngit-grasp** documentation! We use the [Diátaxis](https://diataxis.fr/) framework to organize our documentation into four types, each serving a different purpose.

```
                    PRACTICAL          THEORETICAL
                    ─────────          ───────────
                    
LEARNING      │   Tutorials    │    Explanation   │
              │                │                  │
              │  Getting       │   Architecture   │
              │  Started       │   Decisions      │
              │                │                  │
              ├────────────────┼──────────────────┤
              │                │                  │
WORKING       │  How-To        │    Reference     │
              │  Guides        │                  │
              │                │   API Docs       │
              │  Deployment    │   Protocols      │
              │  Testing       │                  │
              │                │                  │
```

## 📚 Documentation Types

### 🎓 [Tutorials](tutorials/) - *Learning by Doing*
**Purpose:** Learn the basics through practical steps  
**For:** Newcomers getting started  
**Style:** Step-by-step lessons with guaranteed outcomes

- **[Getting Started](tutorials/getting-started.md)** - Your first ngit-grasp setup
- **[Running Your First Audit](tutorials/first-audit.md)** - Using grasp-audit tool

### 🔧 [How-To Guides](how-to/) - *Solving Problems*
**Purpose:** Accomplish specific tasks  
**For:** Users with basic knowledge solving real problems  
**Style:** Practical recipes and solutions

- **[Deploy ngit-grasp](how-to/deploy.md)** - Production deployment guide
- **[Configure Nix Flakes](how-to/nix-flakes.md)** - Nix development environment
- **[Run Compliance Tests](how-to/test-compliance.md)** - GRASP compliance testing
- **[Upgrade nostr-sdk](how-to/upgrade-nostr-sdk.md)** - Handling SDK upgrades

### 📖 [Reference](reference/) - *Technical Information*
**Purpose:** Look up technical details  
**For:** Users who know what they're looking for  
**Style:** Dry, factual, comprehensive

- **[Git Protocol](reference/git-protocol.md)** - Git Smart HTTP protocol details
- **[GRASP Protocol](reference/grasp-protocol.md)** - GRASP specification details
- **[Configuration](reference/configuration.md)** - All config options
- **[API Reference](reference/api.md)** - Internal API documentation

### 💡 [Explanation](explanation/) - *Understanding Concepts*
**Purpose:** Understand the "why" and design decisions  
**For:** Users wanting deeper understanding  
**Style:** Discussion, context, alternatives

- **[Architecture Overview](explanation/architecture.md)** - System design and components
- **[Inline Authorization](explanation/inline-authorization.md)** - Why we chose this approach
- **[Administration Vision](explanation/administration-vision.md)** -
  Nostr-authenticated management, embedded UI, and runtime configuration
- **[Comparison with ngit-relay](explanation/comparison.md)** - How we differ from reference
- **[Design Decisions](explanation/decisions.md)** - Key architectural choices

---

## 🚀 Quick Start Paths

### I'm brand new to ngit-grasp
1. Read [README.md](../README.md) for project overview
2. Follow [Getting Started Tutorial](tutorials/getting-started.md)
3. Understand [Architecture Overview](explanation/architecture.md)

### I want to deploy ngit-grasp
1. Review [Configuration Reference](reference/configuration.md)
2. Follow [Deployment How-To](how-to/deploy.md)
3. Set up monitoring and backups

### I want to develop on ngit-grasp
1. Follow [Getting Started Tutorial](tutorials/getting-started.md)
2. Read [Architecture Overview](explanation/architecture.md)
3. Check [Nix Flakes How-To](how-to/nix-flakes.md)
4. Review [Test Strategy](how-to/test-compliance.md)

### I want to understand the design
1. Read [Inline Authorization Explanation](explanation/inline-authorization.md)
2. Review [Design Decisions](explanation/decisions.md)
3. Compare with [ngit-relay Comparison](explanation/comparison.md)

### I'm looking for specific information
- **Protocol details?** → [Reference](reference/)
- **Configuration options?** → [Configuration Reference](reference/configuration.md)
- **Git protocol?** → [Git Protocol Reference](reference/git-protocol.md)

---

## 📂 Additional Resources

### [Archive](archive/)
Historical session notes and completed work. Useful for understanding project evolution but not required reading.

### [Learnings](learnings/)
**DEPRECATED** - Being migrated to Diátaxis structure:
- Gotchas → How-To Guides
- Patterns → Reference or Explanation
- Notes → Appropriate category

---

## 🤝 Contributing to Documentation

When adding documentation, ask yourself:

**Is it a tutorial?**
- Does it teach a beginner?
- Is it a complete lesson with guaranteed outcome?
- → Add to `tutorials/`

**Is it a how-to guide?**
- Does it solve a specific problem?
- Is it a recipe for accomplishing a task?
- → Add to `how-to/`

**Is it reference material?**
- Is it technical information?
- Will people look it up when needed?
- → Add to `reference/`

**Is it explanation?**
- Does it explain "why"?
- Does it discuss alternatives or design?
- → Add to `explanation/`

See [Diátaxis documentation](https://diataxis.fr/) for more guidance.

---

## 📊 Project Status

**ALPHA** - Under active development. Core functionality working, API may change.

### Completed
- ✅ grasp-audit compliance testing tool
- ✅ Nix flake development environment
- ✅ nostr-sdk 0.43 upgrade
- ✅ Documentation restructure (Diátaxis)

### In Progress
- 🔄 Core ngit-grasp server implementation
- 🔄 GRASP-01 compliance

### Planned
- 🔜 GRASP-02 (Proactive Sync)
- 🔜 GRASP-05 (Archive)

---

## 🔗 External Links

- [GRASP Protocol Specification](https://gitworkshop.dev/danconwaydev.com/grasp)
- [NIP-34 (Git Stuff)](https://nips.nostr.com/34)
- [Diátaxis Framework](https://diataxis.fr/)
- [rust-nostr Documentation](https://docs.rs/nostr-sdk/)

---

*Documentation structure based on [Diátaxis](https://diataxis.fr/)*  
*Last updated: November 4, 2025*
