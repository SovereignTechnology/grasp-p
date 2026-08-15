//! GRASP-08 private-service authentication.
//!
//! Private mode adds a service-wide member list used by both the Nostr
//! WebSocket relay (NIP-42) and Git Smart HTTP (the GRASP-08 NIP-98 profile).

pub mod access;
pub mod nip98;
pub mod ws_auth;

pub use access::PrivateAccess;
