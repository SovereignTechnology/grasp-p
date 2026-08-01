/// Related Event Policy - Forward/backward reference checking
///
/// Handles validation of events that reference accepted repositories or events
/// (backward references) and events that are referenced by accepted events
/// (forward references).
use nostr_sdk::prelude::{Alphabet, Event, EventId, Filter, Kind, PublicKey, SingleLetterTag};

use super::PolicyContext;

/// Result of reference checking
#[derive(Debug)]
pub enum ReferenceResult {
    /// Event references an accepted repository (addressable ref found)
    ReferencesRepository(String),
    /// Event references an accepted event (event ID found)
    ReferencesEvent(EventId),
    /// Event is referenced by an accepted event (forward reference)
    ReferencedByAccepted,
    /// No valid references found - event is an orphan
    Orphan,
}

/// Policy for checking event references (backward and forward)
#[derive(Clone)]
pub struct RelatedEventPolicy {
    ctx: PolicyContext,
}

impl RelatedEventPolicy {
    pub fn new(ctx: PolicyContext) -> Self {
        Self { ctx }
    }

    /// Check all reference types for an event
    ///
    /// Returns the first valid reference found, or `Orphan` if none found.
    pub async fn check_references(&self, event: &Event) -> Result<ReferenceResult, String> {
        // Extract all reference tags from event
        let (addressable_refs, event_refs) = Self::extract_reference_tags(event);

        // Check 1: Does this event reference an accepted repository?
        if let Some(addr_ref) = self.find_accepted_repository(&addressable_refs).await? {
            return Ok(ReferenceResult::ReferencesRepository(addr_ref));
        }

        // Check 2: Does this event reference an accepted event?
        if let Some(event_ref) = self.find_accepted_event(&event_refs).await? {
            return Ok(ReferenceResult::ReferencesEvent(event_ref));
        }

        // Check 3: Is this event referenced by an accepted event?
        if self.is_referenced_by_accepted(event).await? {
            return Ok(ReferenceResult::ReferencedByAccepted);
        }

        // No valid references found
        Ok(ReferenceResult::Orphan)
    }

    /// Extract all reference tags from an event (a, A, q, e, E)
    /// Returns (addressable_refs, event_refs)
    pub fn extract_reference_tags(event: &Event) -> (Vec<String>, Vec<EventId>) {
        let mut addressable_refs = Vec::new();
        let mut event_refs = Vec::new();

        for tag in event.tags.iter() {
            let tag_vec = tag.clone().to_vec();
            if tag_vec.is_empty() {
                continue;
            }

            match tag_vec[0].as_str() {
                // Addressable event references (a, A, q with kind:pubkey:identifier format)
                "a" | "A" | "q" if tag_vec.len() > 1 && tag_vec[1].contains(':') => {
                    addressable_refs.push(tag_vec[1].clone());
                }
                // Event ID references (e, E, q with event ID format)
                "e" | "E" if tag_vec.len() > 1 => {
                    if let Ok(event_id) = EventId::from_hex(&tag_vec[1]) {
                        event_refs.push(event_id);
                    }
                }
                "q" if tag_vec.len() > 1 && !tag_vec[1].contains(':') => {
                    if let Ok(event_id) = EventId::from_hex(&tag_vec[1]) {
                        event_refs.push(event_id);
                    }
                }
                _ => {}
            }
        }

        (addressable_refs, event_refs)
    }

    /// Check if any addressable events (repositories) exist in database
    /// Returns the first matching addressable reference found, or None if none match
    async fn find_accepted_repository(
        &self,
        addressables: &[String],
    ) -> Result<Option<String>, String> {
        if addressables.is_empty() {
            return Ok(None);
        }

        // Parse all addressable references
        let mut parsed_refs = Vec::new();
        for addr in addressables {
            let parts: Vec<&str> = addr.split(':').collect();
            if parts.len() < 3 {
                continue; // Skip invalid format
            }

            let kind = match parts[0].parse::<u16>() {
                Ok(k) => k,
                Err(_) => continue, // Skip invalid kind
            };
            let pubkey = match PublicKey::from_hex(parts[1]) {
                Ok(pk) => pk,
                Err(_) => continue, // Skip invalid pubkey
            };
            let identifier = parts[2].to_string();

            parsed_refs.push((addr.clone(), kind, pubkey, identifier));
        }

        if parsed_refs.is_empty() {
            return Ok(None);
        }

        // Group by kind to reduce queries
        use std::collections::HashMap;
        let mut by_kind: HashMap<u16, Vec<_>> = HashMap::new();
        for (addr, kind, pubkey, identifier) in parsed_refs {
            by_kind
                .entry(kind)
                .or_default()
                .push((addr, pubkey, identifier));
        }

        // NOTE: Intentionally only checks the database (promoted announcements), not purgatory.
        // Related events should only be accepted once the repository announcement has been
        // validated (promoted via git data). Events referencing purgatory-only repositories
        // are correctly rejected as orphans and can be re-submitted after promotion.

        // Query each kind group
        for (kind, refs) in by_kind {
            let authors: Vec<PublicKey> = refs.iter().map(|(_, pk, _)| *pk).collect();

            let filter = Filter::new().kind(Kind::from(kind)).authors(authors);

            match self.ctx.database.query(filter).await {
                Ok(events) => {
                    // Check if any event matches our identifier requirements
                    for event in events {
                        for (addr, _pubkey, identifier) in &refs {
                            // Match identifier tag
                            if event.tags.iter().any(|tag| {
                                let tag_vec = tag.clone().to_vec();
                                tag_vec.len() >= 2 && tag_vec[0] == "d" && tag_vec[1] == *identifier
                            }) {
                                return Ok(Some(addr.clone()));
                            }
                        }
                    }
                }
                Err(e) => return Err(format!("Database query failed: {}", e)),
            }
        }

        Ok(None)
    }

    /// Check if any events exist in database
    /// Returns the first matching event ID found, or None if none match
    async fn find_accepted_event(&self, event_ids: &[EventId]) -> Result<Option<EventId>, String> {
        if event_ids.is_empty() {
            return Ok(None);
        }

        // Single query for all event IDs
        let filter = Filter::new().ids(event_ids.iter().copied());

        match self.ctx.database.query(filter).await {
            Ok(events) => {
                // Get first event from the iterator
                Ok(events.into_iter().next().map(|e| e.id))
            }
            Err(e) => Err(format!("Database query failed: {}", e)),
        }
    }

    /// Check if any accepted event references this event (forward reference)
    ///
    /// For regular replaceable events (10000-19999): Checks addressable tags with kind:pubkey format
    /// For parameterized replaceable (30000-39999): Checks addressable tags with kind:pubkey:d-identifier format
    /// For regular events: Only checks event ID reference tags (e, E, q)
    async fn is_referenced_by_accepted(&self, event: &Event) -> Result<bool, String> {
        let kind_u16 = event.kind.as_u16();

        // Check if this is any kind of replaceable event
        let is_regular_replaceable = (10000..20000).contains(&kind_u16);
        let is_parameterized_replaceable = (30000..40000).contains(&kind_u16);

        if is_regular_replaceable || is_parameterized_replaceable {
            // Build the appropriate address format based on event type
            let address = if is_parameterized_replaceable {
                // For parameterized replaceable: kind:pubkey:d-identifier format (2 colons)
                let identifier = event
                    .tags
                    .iter()
                    .find_map(|tag| {
                        let tag_vec = tag.clone().to_vec();
                        if tag_vec.len() >= 2 && tag_vec[0] == "d" {
                            Some(tag_vec[1].clone())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_default(); // Empty string if no 'd' tag
                format!(
                    "{}:{}:{}",
                    event.kind.as_u16(),
                    event.pubkey.to_hex(),
                    identifier
                )
            } else {
                // For regular replaceable: kind:pubkey format (1 colon)
                format!("{}:{}", event.kind.as_u16(), event.pubkey.to_hex())
            };

            // Check addressable reference tags: a, A, q (with address format)
            let addressable_tags = [
                SingleLetterTag::lowercase(Alphabet::A), // 'a' - addressable event reference
                SingleLetterTag::uppercase(Alphabet::A), // 'A' - uppercase addressable reference
                SingleLetterTag::lowercase(Alphabet::Q), // 'q' - quote (can be address or ID)
            ];

            for tag_type in &addressable_tags {
                let filter = Filter::new().custom_tag(*tag_type, address.clone());

                match self.ctx.database.query(filter).await {
                    Ok(events) => {
                        if !events.is_empty() {
                            return Ok(true);
                        }
                    }
                    Err(e) => return Err(format!("Database query failed: {}", e)),
                }
            }
        } else {
            // For regular events, check event ID reference tags: e, E, q (with hex ID)
            let event_id_hex = event.id.to_hex();

            let event_id_tags = [
                SingleLetterTag::lowercase(Alphabet::E), // 'e' - standard event reference
                SingleLetterTag::uppercase(Alphabet::E), // 'E' - NIP-22 root event reference
                SingleLetterTag::lowercase(Alphabet::Q), // 'q' - quote reference
            ];

            for tag_type in &event_id_tags {
                let filter = Filter::new().custom_tag(*tag_type, event_id_hex.clone());

                match self.ctx.database.query(filter).await {
                    Ok(events) => {
                        if !events.is_empty() {
                            return Ok(true);
                        }
                    }
                    Err(e) => return Err(format!("Database query failed: {}", e)),
                }
            }
        }

        Ok(false)
    }
}
