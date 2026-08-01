pub mod builder;
pub mod events;
pub mod lifecycle;
pub mod persistence;
pub mod policy;

/// Shared database type used across nostr modules.
pub type SharedDatabase = std::sync::Arc<dyn nostr_sdk::prelude::NostrDatabase>;
