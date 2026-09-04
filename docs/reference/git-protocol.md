# Git Smart HTTP Protocol Reference

## Overview

This document explains the Git Smart HTTP protocol as it relates to our inline authorization implementation.

## Required Git Capabilities

### GRASP-01 Requirements (MUST)

Per the [GRASP-01 specification](https://gitworkshop.dev/danconwaydev.com/grasp/tree/master/01.md), implementations **MUST** advertise and support the following git capabilities:

- **`allow-reachable-sha1-in-want`**: Allows clients to request commits reachable from any ref
- **`allow-tip-sha1-in-want`**: Allows clients to request specific commit SHAs directly
- **`uploadpack.allowFilter`**: Enables partial clone/fetch with `--filter` options

These are essential for supporting `refs/nostr/<event-id>` (PR refs) and bandwidth-efficient partial clones.

**Implementation:** `src/git/subprocess.rs:36-42`

### How Capabilities are Advertised

Git capabilities are advertised during the initial `GET /info/refs?service=git-upload-pack` request. The server spawns `git upload-pack --advertise-refs` with configuration flags:

```bash
git -c uploadpack.allowReachableSHA1InWant=true \
    -c uploadpack.allowTipSHA1InWant=true \
    -c uploadpack.allowFilter=true \
    upload-pack --advertise-refs --stateless-rpc /path/to/repo.git
```

Clients parse the capability list from the response and only use features the server advertises.

**Verification:** Test with `git ls-remote`:

```bash
GIT_TRACE_PACKET=1 git ls-remote https://ngit.danconwaydev.com/npub.../repo.git 2>&1 | grep -E "allow-|filter"
```

Expected output should include:
```
pkt-line: ... allow-tip-sha1-in-want allow-reachable-sha1-in-want filter ...
```

## Protocol Flow

### Clone/Fetch (Upload Pack)

```
1. Client → GET /repo.git/info/refs?service=git-upload-pack
   Server → 200 OK with pack advertisement
   
2. Client → POST /repo.git/git-upload-pack
   Body: want/have negotiation
   Server → 200 OK with pack stream
```

**Authorization**: Not needed for public repositories. For GRASP-01, all repos are public.

### Push (Receive Pack)

```
1. Client → GET /repo.git/info/refs?service=git-receive-pack
   Server → 200 OK with ref advertisement
   
2. Client → POST /repo.git/git-receive-pack
   Body: ref updates + pack data
   Server → 200 OK with status
```

**Authorization**: THIS IS WHERE WE VALIDATE! Step 2 is where inline auth happens.

## Receive Pack Request Format

The POST body to `git-receive-pack` has this structure:

```
[ref-updates]
[pack-data]
```

### Ref Updates Format

Each ref update is in **pkt-line** format:

```
<4-byte-length><old-oid> <new-oid> <ref-name>\0<capabilities>\n
<4-byte-length><old-oid> <new-oid> <ref-name>\n
...
0000
```

**Example** (hex representation):

```
00a20000000000000000000000000000000000000000 a1b2c3d4e5f6... refs/heads/main\0 report-status side-band-64k
003f0000000000000000000000000000000000000000 f6e5d4c3b2a1... refs/heads/dev\n
0000
```

### Pkt-line Format

A pkt-line is:
- 4 hex digits: length of entire line (including the 4 digits)
- Payload data
- `0000` = flush packet (end of section)

**Length calculation**:
```
length = 4 (for length itself) + payload.len()
```

**Examples**:
```
"0006a\n"     → length=6, payload="a\n"
"0000"        → flush packet
"000bfoobar\n" → length=11, payload="foobar\n"
```

### Parsing Ref Updates

```rust
pub struct RefUpdate {
    pub old_oid: String,  // 40 hex chars
    pub new_oid: String,  // 40 hex chars
    pub ref_name: String, // e.g., "refs/heads/main"
}

pub fn parse_ref_updates(body: &[u8]) -> Result<Vec<RefUpdate>> {
    let mut updates = Vec::new();
    let mut offset = 0;
    
    loop {
        // Read pkt-line length
        if offset + 4 > body.len() {
            break;
        }
        
        let length_str = std::str::from_utf8(&body[offset..offset+4])?;
        let length = u16::from_str_radix(length_str, 16)? as usize;
        
        // Check for flush packet
        if length == 0 {
            break;
        }
        
        // Extract payload
        let payload_end = offset + length;
        if payload_end > body.len() {
            return Err(Error::InvalidPktLine);
        }
        
        let payload = &body[offset+4..payload_end];
        
        // Parse ref update from payload
        // Format: "<old-oid> <new-oid> <ref-name>[\0<capabilities>]\n"
        let payload_str = std::str::from_utf8(payload)?;
        
        // Remove trailing newline
        let line = payload_str.trim_end_matches('\n');
        
        // Split on null byte (first line has capabilities)
        let parts: Vec<&str> = line.split('\0').collect();
        let ref_line = parts[0];
        
        // Parse old-oid, new-oid, ref-name
        let tokens: Vec<&str> = ref_line.split_whitespace().collect();
        if tokens.len() != 3 {
            return Err(Error::InvalidRefUpdate);
        }
        
        updates.push(RefUpdate {
            old_oid: tokens[0].to_string(),
            new_oid: tokens[1].to_string(),
            ref_name: tokens[2].to_string(),
        });
        
        offset = payload_end;
    }
    
    Ok(updates)
}
```

## Special OID Values

- `0000000000000000000000000000000000000000` (40 zeros) = ref creation
- When `old_oid` is all zeros: creating a new ref
- When `new_oid` is all zeros: deleting a ref

## Validation Requirements

For GRASP-01, we must validate:

### 1. Regular Branches/Tags

```rust
fn validate_regular_ref(
    state: &RepositoryState,
    update: &RefUpdate,
) -> Result<()> {
    // Extract branch/tag name
    let (ref_type, name) = if update.ref_name.starts_with("refs/heads/") {
        ("branch", &update.ref_name[11..])
    } else if update.ref_name.starts_with("refs/tags/") {
        ("tag", &update.ref_name[10..])
    } else {
        return Err(Error::InvalidRefName);
    };
    
    // Check against state
    let expected = if ref_type == "branch" {
        state.branches.get(name)
    } else {
        state.tags.get(name)
    };
    
    match expected {
        Some(oid) if oid == &update.new_oid => Ok(()),
        Some(oid) => Err(Error::StateMismatch {
            ref_name: update.ref_name.clone(),
            expected: oid.clone(),
            got: update.new_oid.clone(),
        }),
        None => Err(Error::RefNotInState(update.ref_name.clone())),
    }
}
```

### 2. PR Refs (refs/nostr/<event-id>)

```rust
fn validate_pr_ref(update: &RefUpdate) -> Result<()> {
    // Extract event ID
    let event_id = &update.ref_name[11..]; // Skip "refs/nostr/"
    
    // Validate it's a valid 32-byte hex
    if event_id.len() != 64 {
        return Err(Error::InvalidEventId);
    }
    
    if !event_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::InvalidEventId);
    }
    
    // TODO: Could optionally verify event exists on relay
    // TODO: Could verify event references this repository
    
    Ok(())
}
```

### 3. Reject pr/* Branches

```rust
fn reject_pr_branches(update: &RefUpdate) -> Result<()> {
    if update.ref_name.starts_with("refs/heads/pr/") {
        return Err(Error::InvalidRef(
            "pr/* branches must use refs/nostr/<event-id>".into()
        ));
    }
    Ok(())
}
```

## Complete Validation Flow

```rust
pub async fn validate_push(
    &self,
    npub: &str,
    identifier: &str,
    ref_updates: Vec<RefUpdate>,
) -> Result<()> {
    // 1. Fetch events from local relay
    let events = self.fetch_events(identifier).await?;
    
    // 2. Get pubkey from npub
    let pubkey = decode_npub(npub)?;
    
    // 3. Resolve this selected coordinate's current authority
    let maintainers = resolve_current_maintainers(&events, &pubkey, identifier);
    if maintainers.is_empty() {
        return Err(Error::NoResolvedAuthority);
    }
    
    // 4. Get latest state from maintainers
    let state = get_state_from_maintainers(&events, &maintainers)?;
    
    // 5. Validate each ref update
    for update in ref_updates {
        // Check for pr/* branches (reject)
        reject_pr_branches(&update)?;
        
        // Handle refs/nostr/* (allow)
        if update.ref_name.starts_with("refs/nostr/") {
            validate_pr_ref(&update)?;
            continue;
        }
        
        // Validate against state
        validate_regular_ref(&state, &update)?;
    }
    
    Ok(())
}
```

## Integration with actix-web

```rust
pub async fn git_receive_pack(
    req: HttpRequest,
    mut payload: web::Payload,
    state: web::Data<AppState>,
) -> Result<HttpResponse> {
    // 1. Extract repo info from path
    let path = req.path();
    let (npub, identifier) = parse_repo_path(path)?;
    
    // 2. Check repository exists
    if !state.repo_manager.exists(&npub, &identifier).await {
        return Ok(HttpResponse::NotFound().body("Repository not found"));
    }
    
    // 3. Read request body (need to buffer for parsing)
    let mut body = web::BytesMut::new();
    while let Some(chunk) = payload.next().await {
        body.extend_from_slice(&chunk?);
    }
    
    // 4. Parse ref updates from body
    let ref_updates = parse_ref_updates(&body)?;
    
    // 5. VALIDATE!
    let validator = PushValidator::new(state.nostr_client.clone());
    if let Err(e) = validator.validate_push(&npub, &identifier, ref_updates).await {
        return Ok(HttpResponse::Forbidden()
            .content_type("text/plain")
            .body(format!("error: {}\n", e)));
    }
    
    // 6. Valid! Spawn git-receive-pack
    let repo_path = state.repo_manager.get_path(&npub, &identifier);
    let mut cmd = Command::new("git");
    cmd.arg("receive-pack")
       .arg("--stateless-rpc")
       .arg(&repo_path)
       .stdin(Stdio::piped())
       .stdout(Stdio::piped())
       .stderr(Stdio::piped());
    
    let mut child = cmd.spawn()?;
    
    // 7. Write body to git stdin
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&body).await?;
    drop(stdin);
    
    // 8. Stream git stdout back to client
    let stdout = child.stdout.take().unwrap();
    let stream = FramedRead::new(stdout, BytesCodec::new());
    
    Ok(HttpResponse::Ok()
        .content_type("application/x-git-receive-pack-result")
        .streaming(stream))
}
```

## Error Responses

Git clients expect specific error formats:

### Success
```
HTTP/1.1 200 OK
Content-Type: application/x-git-receive-pack-result

[git output stream]
```

### Validation Failure
```
HTTP/1.1 403 Forbidden
Content-Type: text/plain

error: cannot push refs/heads/main to a1b2c3d as nostr state event is at f6e5d4c
```

The `error:` prefix makes it display nicely in git clients.

## Testing

```rust
#[test]
fn test_parse_ref_updates() {
    let body = b"00820000000000000000000000000000000000000000 \
                  a1b2c3d4e5f6789012345678901234567890abcd \
                  refs/heads/main\0 report-status\n\
                  0000";
    
    let updates = parse_ref_updates(body).unwrap();
    assert_eq!(updates.len(), 1);
    assert_eq!(updates[0].old_oid, "0000000000000000000000000000000000000000");
    assert_eq!(updates[0].new_oid, "a1b2c3d4e5f6789012345678901234567890abcd");
    assert_eq!(updates[0].ref_name, "refs/heads/main");
}

#[tokio::test]
async fn test_validate_matching_state() {
    let state = RepositoryState {
        branches: HashMap::from([
            ("main".into(), "a1b2c3d4...".into()),
        ]),
        tags: HashMap::new(),
    };
    
    let update = RefUpdate {
        old_oid: "0000...".into(),
        new_oid: "a1b2c3d4...".into(),
        ref_name: "refs/heads/main".into(),
    };
    
    assert!(validate_regular_ref(&state, &update).is_ok());
}
```

## Performance Considerations

1. **Buffering**: We must buffer the entire request body to parse ref updates. For large pushes, this could be memory-intensive.

   **Mitigation**: Limit max request size (e.g., 100MB)

2. **Pack Data**: After ref updates, the body contains pack data. We don't need to parse this, just forward it to Git.

   **Optimization**: Could use a streaming parser that only extracts ref updates, then streams the rest

3. **Validation Speed**: State lookup and validation should be fast.

   **Optimization**: Cache state events with TTL

## Future Enhancements

### Streaming Parser

Instead of buffering entire body:

```rust
// Read pkt-lines until flush packet
let ref_updates = parse_ref_updates_streaming(&mut payload).await?;

// Now payload is positioned at pack data
// Stream directly to git without buffering
spawn_git_and_stream(payload, repo_path).await?;
```

### Pack Inspection

For advanced validation (future):

```rust
// Parse pack header to get object count
let (ref_updates, pack_header) = parse_receive_pack_header(&body)?;

// Could validate pack contents before accepting
validate_pack_contents(&pack_header)?;
```

## References

- [Git HTTP Protocol Docs](https://git-scm.com/docs/http-protocol)
- [Git Pack Protocol](https://git-scm.com/docs/pack-protocol)
- [Pkt-line Format](https://git-scm.com/docs/protocol-common#_pkt_line_format)
