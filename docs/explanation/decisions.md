# Architecture Decision Summary

## Question: Pre-receive Hook vs. Inline Authorization?

After investigating the `git-http-backend` Rust crate and the reference implementation, we have determined that **inline authorization is both pragmatic and superior**.

## Investigation Findings

### git-http-backend Crate Analysis

The `git-http-backend` crate (v0.1.3) provides:

1. **Low-level Git protocol handling** via actix-web handlers
2. **Process spawning** of `git-receive-pack` and `git-upload-pack`
3. **Stream-based I/O** between HTTP and Git processes
4. **Flexible path rewriting** through the `GitConfig` trait

**Key Finding**: The crate spawns Git as a subprocess in `git_receive_pack.rs`. We can intercept **before** this spawn happens.

### Reference Implementation (ngit-relay) Analysis

The Go-based reference uses:

1. **nginx** as HTTP frontend
2. **git-http-backend** (C binary) for Git protocol
3. **Pre-receive hook** (Go binary) for authorization
4. **Khatru** (Go) for Nostr relay
5. **supervisord** for process management
6. **Docker** for packaging

The pre-receive hook:
- Reads ref updates from stdin
- Queries local Nostr relay via WebSocket
- Validates each ref against state events
- Exits with 0 (accept) or 1 (reject)
- Errors printed to stderr appear as `remote:` messages in git client

## Decision: Inline Authorization ✅

### Why This Is Pragmatic

1. **The crate supports it**: We can implement a custom `git_receive_pack` handler that validates before spawning Git
2. **Better error handling**: Direct HTTP responses vs. parsing hook stderr
3. **Simpler deployment**: Single binary, no hook management
4. **Easier testing**: Pure Rust unit tests, no shell scripts
5. **Performance**: Avoid spawning Git for invalid pushes
6. **Type safety**: Share types between Git and Nostr modules

### Implementation Approach

```rust
// Instead of using git-http-backend's handler as-is:
pub async fn git_receive_pack(
    req: HttpRequest,
    body: web::Payload,
    state: web::Data<AppState>,
) -> Result<HttpResponse> {
    // 1. Parse repository path from URL
    let (npub, identifier) = parse_repo_path(&req)?;
    
    // 2. Buffer enough of the request to parse ref updates
    let ref_updates = parse_ref_updates(&body).await?;
    
    // 3. VALIDATE AGAINST NOSTR STATE
    let validator = PushValidator::new(&state.nostr_client);
    match validator.validate_push(&npub, &identifier, &ref_updates).await {
        Ok(_) => {
            // 4. Valid! Spawn git-receive-pack and stream
            spawn_git_receive_pack(req, body, state).await
        }
        Err(e) => {
            // 5. Invalid! Return HTTP error
            Ok(HttpResponse::Forbidden()
                .body(format!("Push rejected: {}", e)))
        }
    }
}
```

### Advantages Over Hooks

| Aspect | Pre-receive Hook | Inline Authorization |
|--------|------------------|---------------------|
| Error messages | Via stderr, prefixed with `remote:` | Direct HTTP response body |
| Testing | Requires Git repo setup | Pure Rust unit tests |
| Debugging | Hook logs separate from server | Unified logging |
| Deployment | Symlinks, permissions, hook scripts | Single binary |
| Performance | Always spawn Git | Skip Git for invalid pushes |
| State sharing | IPC or network | Direct memory access |
| Type safety | Separate binaries | Shared Rust types |

### Potential Concerns & Mitigations

**Concern**: "What if we need to validate the actual pack data, not just refs?"

**Mitigation**: We can still do this inline! Parse the pack stream before forwarding to Git. The `git-http-backend` crate already buffers the request body.

**Concern**: "Doesn't Git expect hooks for certain operations?"

**Mitigation**: We're not eliminating hooks entirely. Post-receive hooks might still be useful for notifications. We're just moving *authorization* out of hooks.

**Concern**: "What about compatibility with standard Git setups?"

**Mitigation**: The Git Smart HTTP protocol is standardized. Our inline validation is transparent to clients. We're still using real Git repositories and spawning real `git-receive-pack`.

## Comparison with Reference Implementation

### Reference (ngit-relay)
```
Client → nginx → git-http-backend → Git → pre-receive hook → validate → accept/reject
                                              ↓
                                    Query Nostr relay (WebSocket)
```

### Our Approach (ngit-grasp)
```
Client → actix-web → validate → Git → accept
                        ↓
                Query Nostr relay (in-process)
                        ↓
                     reject ← return HTTP error
```

## Implementation Complexity

### Hook-based (if we went that route)
- ✅ Simpler: Follow reference implementation
- ❌ More components: Hook binaries, symlinks
- ❌ More complex testing: Need Git repos, shell scripts
- ❌ More complex deployment: Hook installation, permissions

### Inline (our choice)
- ❌ More complex: Custom Git protocol handling
- ✅ Fewer components: Single binary
- ✅ Simpler testing: Pure Rust
- ✅ Simpler deployment: Just run the binary

**Verdict**: Slightly more complex initially, but much simpler long-term.

## Code Reuse from Reference

We can still reuse the **logic** from the reference implementation:

- Maintainer recursion algorithm
- State validation logic
- Event filtering policies
- Repository provisioning workflow

We're just implementing it in Rust within our HTTP handlers rather than in Git hooks.

## Conclusion

**Inline authorization is both pragmatic and superior for a Rust implementation.**

The `git-http-backend` crate provides sufficient flexibility through its handler architecture. By intercepting at the HTTP layer, we gain:

1. Better error handling and user experience
2. Simpler deployment and operations
3. Easier testing and debugging
4. Better performance characteristics
5. Tighter integration between components

The additional complexity of parsing the Git protocol is minimal compared to the benefits, and we're still using the standard Git binaries for the actual repository operations.

## Next Steps

1. ✅ Document architecture (this file + ARCHITECTURE.md)
2. ⏭️ Set up project structure with Cargo workspace
3. ⏭️ Implement core types (RefUpdate, RepositoryState, etc.)
4. ⏭️ Implement Git protocol parsing
5. ⏭️ Implement Nostr relay with policies
6. ⏭️ Implement push validation logic
7. ⏭️ Integration tests
8. ⏭️ GRASP-01 compliance testing

## Purgatory Implementation (2025-12-23)

Implemented according to design specification in [`purgatory-design.md`](purgatory-design.md). No significant deviations from original design.

**Implementation approach:**
- Phases 1-7 completed sequentially as planned
- All data structures match design specifications
- Integration points implemented as designed

**Key technical choices:**

1. **Optional Purgatory in Git Handlers**: Used `Option<Arc<Purgatory>>` in git handler signatures for backward compatibility. This allows git handlers to function even when no purgatory is provided (e.g., in minimal test setups).

2. **Cleanup Interval**: Background cleanup task runs every 60 seconds as designed, removing expired entries from both state and PR stores.

3. **Thread-Safe Storage**: Used `Arc<DashMap>` for lock-free concurrent access, enabling safe sharing between HTTP handlers, WebSocket handlers, and background tasks.

4. **Late Binding Implementation**: Ref extraction logic in [`helpers.rs`](../../src/purgatory/helpers.rs) extracts refs at git push time, not event arrival time, as specified in the design.

**Test integration:**
- Existing test code in `grasp-audit` was uncommented (Phases 7)
- No new integration tests added (as instructed)
- Test verification enabled in [`grasp-audit/src/client.rs`](../../grasp-audit/src/client.rs) and [`grasp-audit/src/specs/grasp01/push_authorization.rs`](../../grasp-audit/src/specs/grasp01/push_authorization.rs)

**Related Documentation:**
- Design: [`purgatory-design.md`](purgatory-design.md)
- Architecture: [`architecture.md`](architecture.md#5-purgatory-system-srcpurgatory)
- Implementation Plan: [`../purgatory-implementation-plan.md`](../purgatory-implementation-plan.md)

---

## Question: Who may publish authoritative repository state?

**Decision (2026-08): maintainer membership is reciprocal** (following the
NIP-34 maintainers model refined in nips commit `781590b`).

### The model

- A pubkey listed as a maintainer in an announcement is only **invited**
  until its own announcement for the same identifier lists back an existing
  confirmed maintainer.
- Only confirmed maintainers publish authoritative repository state.
- The owner is always a confirmed maintainer of their own repository:
  announcing a repository in their namespace is what creates it on this
  service.

### Implementation choices

1. **State events from invited maintainers are rejected** as unauthorized
   (previously any pubkey listed in a `maintainers` tag was authorized
   recursively without reciprocity). The rejected-events index and purgatory
   re-evaluation recover them automatically once the acceptance announcement
   arrives.
2. **Invited maintainers' announcements are still fetched, accepted and
   synced** (maintainer exception, discovery author sets, dependency
   walkers): the reciprocal announcement is precisely how the relay learns
   an invitation was accepted.
3. **Acceptance triggers reconciliation.** When an acceptance announcement is
   stored via the maintainer exception, stored state events are re-applied
   (`reapply_stored`) so a newly confirmed maintainer's latest state
   re-points the owner's repository without another push.

### Indexed role tags (`M`/`m`)

- `M` (lead) and `m` (co-maintainer) tags are the primary maintainer
  listing (per the model clarified in nips commit `986edd1`); when present
  the deprecated `maintainers` tag is ignored per NIP-34 (and parsed as
  empty). The role distinction carries no meaning for this service: both
  collapse into one maintainer set.
- Role tags may record history as alternating start/end timestamps; a tag
  is currently active when it has fewer than four elements or an odd number
  of elements. Ended entries are ignored entirely: role history is only
  used to conclude that a pubkey is *no longer* a maintainer, never to
  grant time-scoped retroactive authority over historic events. The
  NIP's owner-first precedence for conflicting past-role records is
  therefore unused.
- A pubkey may appear in multiple role tags: one of each letter records a
  role transition per the NIP, and out-of-spec duplicates under the same
  letter are consolidated rather than rejected - rejecting them would drop
  otherwise-valid membership data over a formatting slip. Since only
  current activity matters here, consolidation reduces to: a pubkey is a
  maintainer while any of its `M`/`m` entries is active.
- An announcement using role tags acknowledges its author via an active
  self-entry, or implicitly: an author who appears in no role tag is a
  maintainer for the repository's entire history. Only an ended self-entry
  means the member left, which takes precedence over assignments in other
  announcements.
- A `u` (subordinate fork) tag has no effect on maintainership: the author
  of a role-less announcement asserts maintainership with or without it.

### Moderator role (`o`) grants no maintainership

NIP-34 also defines an `o` (moderator) tag whose members are empowered to
have their status events (kinds 1630-1633) treated as authoritative. This
relay does not reject status events from non-maintainers/non-moderators -
status resolution is left to clients - so the role's own authority needs
no enforcement here. Moderators never publish authoritative repository
state, and `o` listings do not create maintainer invitations.

The tag still participates in announcement parsing (per nips commit
`986edd1`): its presence suppresses the deprecated `maintainers` fallback,
and a self-`o` entry is a self-role, so a moderator-only author is not
implicitly a maintainer and their state events are not authorized. Like
`M`/`m`, duplicate `o` tags for one pubkey are consolidated rather than
rejected.

Deliberately deferred: announcements from moderators are not walked for
the `M`/`m` assignments they might carry (the NIP says role combinations
beyond self-plus-lead SHOULD be avoided unless the author is `M`), and
moderator membership gets no reciprocal-confirmation treatment. Both only
matter if status-event authority is ever enforced.

