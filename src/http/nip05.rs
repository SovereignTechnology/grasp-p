//! NIP-05 root-identifier document.
//!
//! A relay operator can use `_@domain` as the domain's root Nostr identity.
//! The well-known response maps that identifier to the same public key used
//! by the relay for NIP-11 and NIP-42.

use std::collections::BTreeMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::config::Config;

/// NIP-05 mapping served from `/.well-known/nostr.json`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Nip05Document {
    pub names: BTreeMap<String, String>,
}

impl Nip05Document {
    /// Build the `_@domain` mapping from the configured relay identity.
    pub fn from_config(config: &Config) -> Result<Self> {
        Ok(Self {
            names: BTreeMap::from([("_".to_string(), config.relay_owner_pubkey_hex()?)]),
        })
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_identifier_uses_relay_owner_pubkey() {
        let config = Config::for_testing();
        let expected = config.relay_owner_pubkey_hex().unwrap();

        let document = Nip05Document::from_config(&config).unwrap();

        assert_eq!(document.names.len(), 1);
        assert_eq!(document.names.get("_"), Some(&expected));
        assert_eq!(expected.len(), 64);
        assert!(expected
            .chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character)));
    }
}
