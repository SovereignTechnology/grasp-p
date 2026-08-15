//! Registry of GRASP-08 private-service peers learned from NIP-11.
//!
//! A private instance attaches its outbound NIP-98 credential only to Git
//! fetches from hosts it has confirmed to be GRASP-08 private services, so
//! the credential is never presented to an ordinary public server.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};

/// Shared set of confirmed GRASP-08 peers, keyed by canonical `host:port`.
///
/// The sync manager writes entries when a relay's NIP-11 advertises (or stops
/// advertising) GRASP-08; the purgatory Git fetch path reads them. Keys always
/// carry an explicit port - tests run several services on one loopback host,
/// so the host alone would collide.
#[derive(Clone, Debug, Default)]
pub struct Grasp08Peers {
    inner: Arc<RwLock<HashSet<String>>>,
}

impl Grasp08Peers {
    /// Record `key` as a confirmed GRASP-08 peer. Returns true when new.
    pub fn insert(&self, key: String) -> bool {
        self.inner
            .write()
            .expect("GRASP-08 peer set poisoned")
            .insert(key)
    }

    /// Forget `key`. Returns true when it was present.
    pub fn remove(&self, key: &str) -> bool {
        self.inner
            .write()
            .expect("GRASP-08 peer set poisoned")
            .remove(key)
    }

    /// Whether `key` is a confirmed GRASP-08 peer.
    pub fn contains(&self, key: &str) -> bool {
        self.inner
            .read()
            .expect("GRASP-08 peer set poisoned")
            .contains(key)
    }

    /// Canonical `host:port` registry key for a ws/wss/http/https URL.
    ///
    /// The same service is reached over WebSocket (relay URL) and HTTP
    /// (clone URL); scheme-default ports are made explicit so both spellings
    /// map to one key.
    pub fn peer_key(url: &str) -> Option<String> {
        let parsed = reqwest::Url::parse(url).ok()?;
        let host = parsed.host_str()?.to_ascii_lowercase();
        let port = parsed.port_or_known_default()?;
        Some(format!("{host}:{port}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ws_and_http_urls_for_one_service_share_a_key() {
        let key = Grasp08Peers::peer_key("ws://127.0.0.1:7334").expect("ws key");
        assert_eq!(key, "127.0.0.1:7334");
        assert_eq!(
            Grasp08Peers::peer_key("http://127.0.0.1:7334/npub/repo.git").as_deref(),
            Some("127.0.0.1:7334")
        );
        // Scheme-default ports become explicit for both transports.
        assert_eq!(
            Grasp08Peers::peer_key("wss://Relay.Example").as_deref(),
            Some("relay.example:443")
        );
        assert_eq!(
            Grasp08Peers::peer_key("https://relay.example/x.git").as_deref(),
            Some("relay.example:443")
        );
        assert_eq!(Grasp08Peers::peer_key("not a url"), None);
    }

    #[test]
    fn registry_tracks_insert_and_remove() {
        let peers = Grasp08Peers::default();
        assert!(!peers.contains("relay.example:443"));
        assert!(peers.insert("relay.example:443".into()));
        assert!(!peers.insert("relay.example:443".into()));
        assert!(peers.contains("relay.example:443"));
        assert!(peers.remove("relay.example:443"));
        assert!(!peers.contains("relay.example:443"));
    }
}
