# How-To Guides

**Task-oriented documentation** - Practical solutions to common problems.

---

## What Are How-To Guides?

How-to guides are **recipes** that show you how to solve specific problems or accomplish particular tasks.

**Characteristics:**
- ✅ Task-oriented (solve a problem)
- ✅ Practical (actionable steps)
- ✅ Assume basic knowledge
- ✅ Focus on results
- ✅ Can be followed in any order

**Not how-to guides:**
- ❌ Complete lessons for beginners (those are Tutorials)
- ❌ Technical specifications (those are Reference)
- ❌ Conceptual discussions (those are Explanation)

---

## Available How-To Guides

### [Release ngit-grasp](release.md)

**Problem:** Publish and deploy a versioned release across every supported channel
**Difficulty:** Advanced

**You'll learn:**

- Prepare and validate release metadata
- Publish immutable Nostr tags and verify ngit-ci artifacts
- Reconcile the GitHub mirror and decide the crates.io policy
- Avoid confusing ngit-grasp with the archived ngit-relay container
- Roll out the one-way v3 migration safely

---

### [Upgrade from v2 to v3 Git family storage](upgrade-git-family-storage.md)

**Problem:** Perform the one-way identifier-family storage migration safely
**Difficulty:** Advanced

**You'll learn:**

- Prepare capacity and a snapshot-based rollback point
- Run the automatic crash-safe v3 launch migration
- Interpret migration and integrity summary logs
- Restore v2 safely when a release rollback is required

---

### [Configure Nix Flakes](nix-flakes.md)
**Problem:** Set up reproducible development environment  
**Difficulty:** Intermediate

**You'll learn:**
- Enable Nix flakes
- Enter development environment
- Work with subprojects
- Troubleshoot common issues

---

### [Test Sync Against Production Data](production-sync-testing.md)
**Problem:** Debug and improve sync using real-world data  
**Difficulty:** Intermediate

**You'll learn:**
- Run sync against production relays
- Sanitize logs for LLM analysis
- Identify common issues and patterns
- Iteratively improve sync behavior

---

## Planned How-To Guides

### Deploy ngit-grasp
**Status:** 🔜 Planned (waiting for main server)

**Problem:** Deploy to production  
**You'll learn:**
- Server requirements
- Reverse proxy setup (nginx/Caddy)
- SSL/TLS configuration
- Monitoring and logging

---

### Run Compliance Tests
**Status:** 🔜 Planned

**Problem:** Test GRASP compliance  
**You'll learn:**
- Set up test relay
- Run integration tests
- Interpret results
- Add custom tests

---

### Upgrade nostr-sdk
**Status:** 🔜 Planned

**Problem:** Handle breaking changes in nostr-sdk  
**You'll learn:**
- Check for breaking changes
- Update dependencies
- Fix compilation errors
- Test after upgrade

---

### Configure Authentication
**Status:** 🔜 Planned (feature not yet implemented)

**Problem:** Secure your relay  
**You'll learn:**
- Enable authentication
- Configure allowed users
- Set up rate limiting
- Monitor access

---

### Backup and Restore
**Status:** 🔜 Planned

**Problem:** Protect your data  
**You'll learn:**
- Backup Git repositories
- Backup Nostr events
- Restore from backup
- Automate backups

---

## How to Use How-To Guides

1. **Find your problem** - Browse or search for what you need
2. **Check prerequisites** - Make sure you have required knowledge
3. **Follow the steps** - Adapt to your specific situation
4. **Solve and move on** - No need to read everything

**Not sure if this is what you need?**
- New to ngit-grasp? → [Tutorials](../tutorials/)
- Looking for technical details? → [Reference](../reference/)
- Want to understand why? → [Explanation](../explanation/)

---

## Contributing How-To Guides

When writing a how-to guide:

**DO:**
- ✅ Start with the problem/goal
- ✅ List prerequisites clearly
- ✅ Provide concrete steps
- ✅ Include troubleshooting
- ✅ Show examples
- ✅ Link to related docs

**DON'T:**
- ❌ Teach basics (link to Tutorials)
- ❌ Explain every concept (link to Explanation)
- ❌ List all options (link to Reference)
- ❌ Make it a tutorial (stay focused on the task)

**Template:**
```markdown
# How-To: [Task/Problem]

**Problem:** [What you're trying to accomplish]  
**Difficulty:** [Beginner/Intermediate/Advanced]  
**Time:** [Estimated time]

## Prerequisites
- [Required knowledge/tools]

## Solution

### Step 1: [Action]
[Instructions]

### Step 2: [Action]
[Instructions]

## Troubleshooting

### [Common problem]
**Solution:** [How to fix]

## Related Documentation
- [Links to relevant docs]
```

See [Diátaxis: How-To Guides](https://diataxis.fr/how-to-guides/) for detailed guidance.

---

*Part of the [ngit-grasp documentation](../README.md) using the [Diátaxis](https://diataxis.fr/) framework.*
