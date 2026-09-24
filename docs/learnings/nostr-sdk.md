# nostr-sdk - Learnings and Patterns

**Purpose:** Document nostr-sdk usage patterns, upgrade notes, and gotchas  
**Last Updated:** November 4, 2025

---

## Current Version

**We use nostr-sdk 0.43.x (latest stable)**

```toml
[dependencies]
nostr-sdk = "0.43"
```

**Upgraded from:** 0.35.0 on November 4, 2025

---

## Critical Breaking Changes (0.35 → 0.43)

### 1. EventBuilder API Changed

**Before (0.35):**
```rust
let event = EventBuilder::new(kind, content, tags)
    .to_event(keys)?;
```

**After (0.43):**
```rust
let event = EventBuilder::new(kind, content)
    .tags(tags)
    .sign_with_keys(keys)?;
```

**Changes:**
- ❌ Removed `tags` parameter from constructor
- ✅ Use `.tags()` builder method instead
- ❌ Removed `.to_event()` method
- ✅ Use `.sign_with_keys()` instead (more descriptive)

---

### 2. Client Ownership of Keys

**Before (0.35):**
```rust
let keys = Keys::generate();
let client = Client::new(&keys);  // Reference
// keys still available
```

**After (0.43):**
```rust
let keys = Keys::generate();
let client = Client::new(keys.clone());  // Ownership
// Need to clone if we want to keep keys
```

**Why:** Allows Client to own the signer, enabling more flexible signer types.

---

### 3. Relay Status Check No Longer Async

**Before (0.35):**
```rust
if relay.is_connected().await {
    // ...
}
```

**After (0.43):**
```rust
if relay.is_connected() {  // No await!
    // ...
}
```

**Why:** Status check doesn't require async operation.

---

### 4. Query API Redesigned

**Before (0.35):**
```rust
let events = client
    .get_events_of(vec![filter], EventSource::relays(Some(timeout)))
    .await?;
// Returns Vec<Event>
```

**After (0.43):**
```rust
let events = client
    .fetch_events(filter, timeout)
    .await?;
// Returns Events (iterable collection)

// Convert to Vec if needed
let vec: Vec<Event> = events.into_iter().collect();
```

**Changes:**
- ❌ Removed `get_events_of()` method
- ✅ Use `fetch_events()` instead
- ❌ Removed `EventSource` parameter (confusing)
- ✅ Direct timeout parameter
- ❌ Single filter instead of `Vec<Filter>`
- ✅ Returns `Events` type instead of `Vec<Event>`

---

### 5. Filter Custom Tags Simplified

**Before (0.35):**
```rust
filter.custom_tag(tag, ["value"])
filter.custom_tag(tag, [&string_ref])
```

**After (0.43):**
```rust
filter.custom_tag(tag, "value")
filter.custom_tag(tag, &string_ref)
```

**Why:** Simplified API for the common case of single tag value.

---

### 6. Send Event Takes Reference

**Before (0.35):**
```rust
let event_id = client.send_event(event).await?;
```

**After (0.43):**
```rust
let output = client.send_event(&event).await?;
let event_id = *output.id();
```

**Changes:**
- Takes `&Event` instead of `Event` (can reuse events)
- Returns `SendEventOutput` instead of `EventId`
- Need to call `.id()` to get the event ID

---

## Common Patterns

### Creating and Signing Events

```rust
use nostr_sdk::prelude::*;

// Generate keys
let keys = Keys::generate();

// Create event
let event = EventBuilder::new(Kind::TextNote, "Hello Nostr!")
    .tags(vec![
        Tag::custom(TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::T)), 
                    vec!["nostr"]),
    ])
    .sign_with_keys(&keys)?;

// Send event
let output = client.send_event(&event).await?;
println!("Event ID: {}", output.id());
```

---

### Creating Custom Tags

```rust
use nostr_sdk::prelude::*;

// Single letter tag (like "t" for topics)
let t_tag = SingleLetterTag::lowercase(Alphabet::T);
let tag = Tag::custom(
    TagKind::SingleLetter(t_tag),
    vec!["my-topic"]
);

// Custom multi-letter tag
let tag = Tag::custom(
    TagKind::Custom("custom-tag".to_string()),
    vec!["value1", "value2"]
);

// Hashtag (convenience method)
let tag = Tag::hashtag("nostr");  // Creates ["t", "nostr"]
```

---

### Querying Events

```rust
use nostr_sdk::prelude::*;

// Build filter
let filter = Filter::new()
    .kind(Kind::TextNote)
    .custom_tag(
        SingleLetterTag::lowercase(Alphabet::T),
        "my-topic"
    )
    .since(Timestamp::now() - Duration::from_secs(3600));  // Last hour

// Query events
let timeout = Duration::from_secs(10);
let events = client.fetch_events(filter, timeout).await?;

// Process events
for event in events.into_iter() {
    println!("Event: {}", event.id());
}
```

---

### Multiple Filters

Since `fetch_events()` takes a single filter, combine multiple queries:

```rust
// Option 1: Fetch separately and combine
let mut all_events = Vec::new();
for filter in filters {
    let events = client.fetch_events(filter, timeout).await?;
    all_events.extend(events.into_iter());
}

// Option 2: Use subscription (more efficient)
let subscription_id = SubscriptionId::new("my-sub");
client.subscribe(filters, None).await?;

// Handle events via notification handler
let mut notifications = client.notifications();
while let Ok(notification) = notifications.recv().await {
    if let RelayPoolNotification::Event { event, .. } = notification {
        println!("Event: {}", event.id());
    }
}
```

---

### Client Setup with Relay

```rust
use nostr_sdk::prelude::*;

// Create keys
let keys = Keys::generate();

// Create client
let client = Client::new(keys.clone());

// Add relay
client.add_relay("wss://relay.example.com").await?;

// Connect
client.connect().await;

// Wait for connection
tokio::time::sleep(Duration::from_secs(2)).await;

// Check connection
if client.relay("wss://relay.example.com")
    .await?
    .is_connected() 
{
    println!("Connected!");
}
```

---

## Testing Patterns

### Unit Tests (No Relay Required)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::prelude::*;

    #[test]
    fn test_event_creation() {
        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::TextNote, "test")
            .sign_with_keys(&keys)
            .unwrap();
        
        assert_eq!(event.kind(), Kind::TextNote);
        assert_eq!(event.content(), "test");
    }

    #[test]
    fn test_tag_creation() {
        let t_tag = SingleLetterTag::lowercase(Alphabet::T);
        let tag = Tag::custom(
            TagKind::SingleLetter(t_tag),
            vec!["test-topic"]
        );
        
        // Verify tag structure
        assert_eq!(tag.as_vec()[0], "t");
        assert_eq!(tag.as_vec()[1], "test-topic");
    }
}
```

---

### Integration Tests (Relay Required)

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::prelude::*;

    #[tokio::test]
    #[ignore]  // Requires running relay
    async fn test_send_and_receive() -> Result<()> {
        // Setup
        let keys = Keys::generate();
        let client = Client::new(keys.clone());
        client.add_relay("ws://localhost:7000").await?;
        client.connect().await;
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Send event
        let event = EventBuilder::new(Kind::TextNote, "test")
            .sign_with_keys(&keys)?;
        let output = client.send_event(&event).await?;
        
        // Query it back
        let filter = Filter::new()
            .id(*output.id());
        let events = client.fetch_events(filter, Duration::from_secs(5)).await?;
        
        assert_eq!(events.len(), 1);
        Ok(())
    }
}
```

**Running integration tests:**
```bash
# Start relay first
docker run --rm -p 7000:7000 scsibug/nostr-rs-relay

# Run tests
cargo test -- --ignored
```

---

## Common Gotchas

### 1. Event Validation Failures

**Problem:** Events fail validation with cryptic errors

**Common Causes:**
- Invalid signature (wrong keys used)
- Invalid event ID (content/tags changed after signing)
- Invalid timestamp (too far in future/past)

**Solution:**
```rust
// Always sign AFTER setting all fields
let event = EventBuilder::new(kind, content)
    .tags(tags)  // Set tags first
    .sign_with_keys(&keys)?;  // Sign last

// Don't modify event after signing!
```

---

### 2. Filter Not Matching Events

**Problem:** Query returns no events even though they exist

**Common Causes:**
- Tag kind mismatch (uppercase vs lowercase)
- Wrong filter field (using `.author()` when you need `.authors()`)
- Timeout too short

**Solution:**
```rust
// Be explicit about tag kinds
let t_tag = SingleLetterTag::lowercase(Alphabet::T);  // Lowercase!

// Use correct filter methods
let filter = Filter::new()
    .authors(vec![keys.public_key()])  // Note: plural
    .kinds(vec![Kind::TextNote]);      // Note: plural

// Increase timeout for slow relays
let timeout = Duration::from_secs(10);
```

---

### 3. Connection Timing Issues

**Problem:** Events fail to send or queries return empty

**Cause:** Client not fully connected to relay

**Solution:**
```rust
// Connect
client.connect().await;

// Wait for connection to establish
tokio::time::sleep(Duration::from_secs(2)).await;

// Verify connection
let relay = client.relay("wss://relay.example.com").await?;
if !relay.is_connected() {
    return Err("Not connected".into());
}

// Now safe to send/query
```

---

### 4. Clone Keys When Creating Client

**Problem:** Can't use keys after creating client

**Cause:** Client takes ownership in 0.43+

**Solution:**
```rust
// Clone keys if you need them later
let keys = Keys::generate();
let client = Client::new(keys.clone());  // Clone!

// Now can still use keys
let pubkey = keys.public_key();
```

---

## Performance Tips

### 1. Reuse Clients

```rust
// ✅ Good - single client
let client = Client::new(keys);
client.add_relay("wss://relay1.com").await?;
client.add_relay("wss://relay2.com").await?;
client.connect().await;

// ❌ Bad - multiple clients
for relay in relays {
    let client = Client::new(keys.clone());  // Wasteful!
    client.add_relay(relay).await?;
}
```

---

### 2. Use Subscriptions for Live Updates

```rust
// ✅ Good for live updates - subscription
let filters = vec![Filter::new().kind(Kind::TextNote)];
client.subscribe(filters, None).await?;

let mut notifications = client.notifications();
while let Ok(notification) = notifications.recv().await {
    // Handle events as they arrive
}

// ❌ Bad for live updates - polling
loop {
    let events = client.fetch_events(filter, timeout).await?;
    tokio::time::sleep(Duration::from_secs(1)).await;
}
```

---

### 3. Batch Event Creation

```rust
// ✅ Good - reuse keys
let keys = Keys::generate();
let events: Vec<Event> = (0..100)
    .map(|i| {
        EventBuilder::new(Kind::TextNote, format!("Message {}", i))
            .sign_with_keys(&keys)
            .unwrap()
    })
    .collect();

// ❌ Bad - regenerate keys
let events: Vec<Event> = (0..100)
    .map(|i| {
        let keys = Keys::generate();  // Wasteful!
        EventBuilder::new(Kind::TextNote, format!("Message {}", i))
            .sign_with_keys(&keys)
            .unwrap()
    })
    .collect();
```

---

## Migration Checklist (0.35 → 0.43)

When upgrading from 0.35 to 0.43:

- [ ] Update `Cargo.toml`: `nostr-sdk = "0.43"`
- [ ] Fix `EventBuilder::new()` - remove tags parameter
- [ ] Fix `EventBuilder::to_event()` → `sign_with_keys()`
- [ ] Fix `Client::new()` - clone keys instead of reference
- [ ] Fix `Relay::is_connected()` - remove `.await`
- [ ] Fix `Client::get_events_of()` → `fetch_events()`
- [ ] Remove `EventSource::relays()` usage
- [ ] Fix `Filter::custom_tag()` - single value instead of array
- [ ] Fix `Client::send_event()` - pass reference, handle `SendEventOutput`
- [ ] Update tests
- [ ] Verify all builds pass
- [ ] Run integration tests

---

## Useful Resources

- **nostr-sdk docs**: https://docs.rs/nostr-sdk/0.43.0
- **rust-nostr GitHub**: https://github.com/rust-nostr/nostr
- **NIPs**: https://github.com/nostr-protocol/nips
- **NIP-01 (Events)**: https://github.com/nostr-protocol/nips/blob/master/01.md
- **NIP-34 (Git)**: https://github.com/nostr-protocol/nips/blob/master/34.md

---

## Quick Reference

| Task | Code |
|------|------|
| Create event | `EventBuilder::new(kind, content).sign_with_keys(&keys)?` |
| Add tags | `.tags(vec![tag1, tag2])` |
| Custom tag | `Tag::custom(TagKind::SingleLetter(t), vec!["value"])` |
| Create client | `Client::new(keys.clone())` |
| Add relay | `client.add_relay("wss://...").await?` |
| Connect | `client.connect().await` |
| Send event | `client.send_event(&event).await?` |
| Query events | `client.fetch_events(filter, timeout).await?` |
| Subscribe | `client.subscribe(filters, None).await?` |

---

*Last updated: November 4, 2025*  
*Status: Living document - update as nostr-sdk evolves*
