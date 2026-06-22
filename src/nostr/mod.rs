pub mod builder;
pub mod events;
pub mod lifecycle;
pub mod persistence;
pub mod policy;
pub mod promotion_hooks;

/// Shared database type used across nostr modules.
pub type SharedDatabase = std::sync::Arc<dyn nostr_relay_builder::prelude::NostrDatabase>;
