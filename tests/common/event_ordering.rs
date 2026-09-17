//! Explicit timestamps for replacement fixtures; no wall-clock waits or ID mining.

use nostr_sdk::prelude::*;

/// Advance beyond a predecessor or deletion cutoff, including future timestamps.
/// The caller supplies the relevant predecessor; unrelated event coordinates do
/// not share a global clock.
pub fn timestamp_after(predecessor: Timestamp) -> Timestamp {
    Timestamp::from_secs(
        predecessor
            .as_secs()
            .checked_add(1)
            .expect("fixture timestamp overflow"),
    )
}

/// Re-sign a fabricated event after its predecessor, retaining its payload and
/// audit tags. Use explicit timestamps instead for historical/conflict cases.
pub fn event_after(event: Event, keys: &Keys, predecessor: Timestamp) -> Event {
    assert_eq!(event.pubkey, keys.public_key(), "fixture signer changed");
    EventBuilder::new(event.kind, event.content)
        .tags(event.tags.to_vec())
        .custom_created_at(timestamp_after(predecessor))
        .finalize(keys)
        .expect("sign ordered fixture event")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_follows_future_predecessor_and_preserves_payload() {
        let keys = Keys::generate();
        let original = EventBuilder::new(Kind::RepoState, "state")
            .tags([Tag::identifier("repo"), Tag::custom("t", ["audit-fixture"])])
            .finalize(&keys)
            .unwrap();
        let future = Timestamp::from_secs(Timestamp::now().as_secs() + 100);
        let replacement = event_after(original.clone(), &keys, future);
        assert_eq!(replacement.created_at.as_secs(), future.as_secs() + 1);
        assert_eq!(replacement.kind, original.kind);
        assert_eq!(replacement.content, original.content);
        assert_eq!(replacement.tags, original.tags);
        replacement.verify().unwrap();
    }

    #[test]
    #[should_panic(expected = "fixture timestamp overflow")]
    fn timestamp_overflow_is_explicit() {
        timestamp_after(Timestamp::from_secs(u64::MAX));
    }
}
