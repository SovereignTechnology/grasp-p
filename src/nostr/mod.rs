pub mod builder;
pub mod deletion;
pub mod events;
pub mod history;
pub mod holding;
pub mod policy;
pub mod tombstones;

/// Shared database type used across nostr modules.
pub type SharedDatabase = std::sync::Arc<dyn nostr_relay_builder::prelude::NostrDatabase>;
