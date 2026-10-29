//! Which relays a node that hosts private repositories dials over plaintext
//! `ws://`.
//!
//! Such a node also serves public repositories and runs upstream's public
//! sync (GRASP-02 and GRASP-03) in the same process, so it dials relays that
//! anyone's events name: the relays of a public repository's announcement,
//! purgatory's dependency relays, the relays in a participant's NIP-65 list,
//! and a relay registered again after its session ended. Upstream registers
//! all of them as event-directed and dials them over `ws://` or `wss://`
//! alike. None of them is sent anything private (the private filters go to
//! configured peers alone), but over `ws://` anyone on the path reads and
//! alters what the node pulls from them, and an answer that changes between
//! the address check and the dial (the dial resolves the name again) hands an
//! internal address an HTTP request whose path and host a stranger chose,
//! where over `wss://` it gets a TLS ClientHello only. So on such a node an
//! event-directed relay is dialled over `wss://` only
//! ([`DialSettings::event_relay_allowed`], called from upstream's
//! `register_relay`, where the refusal takes upstream's own refusal branch:
//! its warn-once line and its memo of refused targets).
//!
//! What keeps its scheme:
//!
//! - the operator's own targets: the bootstrap relay, which upstream
//!   registers as operator-configured and does not vet, and which keeps its
//!   scheme when upstream registers it again as event-directed once its
//!   session has ended; and the publishing of the relay's identity, a client
//!   of its own on `NGIT_USER_INDEX_RELAYS`;
//! - a configured sync peer, but only on a link the operator has declared
//!   private (`NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS`), the setting that
//!   already gives that one connection a dial policy of its own;
//! - everything, under `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS=true`, which
//!   already lifts upstream's address checks for tests and closed networks.
//!
//! A configured peer is sent every alias and key the node holds. When it is
//! also the bootstrap relay it is registered as operator-configured, so
//! neither the rule above nor the peer's own address check ever sees its
//! scheme. Config validation therefore refuses a `ws://` peer unless one of
//! the two settings above is on, and warns about a `ws://` bootstrap relay
//! and about `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS` ([`check_dial_settings`]).
//!
//! With `NGIT_GRASP_P_REPOS_ENABLE` off nothing here refuses or warns.

use crate::config::Config;

/// What a refused relay's line in the log gives as the reason. Upstream
/// registers the operator's index and fallback relays as event-directed
/// too, so the reason names them: an operator whose own entry is refused
/// would otherwise look for an event.
pub(crate) const PLAINTEXT_RELAY_REFUSED: &str =
    "a node that hosts private repositories dials event-directed relays over wss:// only \
     (relays that events name, and the entries of NGIT_USER_INDEX_RELAYS and \
     NGIT_SYNC_PLUS_FALLBACK_RELAYS)";

/// The settings the dial rule reads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct DialSettings {
    /// `NGIT_GRASP_P_REPOS_ENABLE`.
    pub grasp_p_node: bool,
    /// `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS`.
    pub allow_non_global: bool,
    /// `NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS`: the operator's statement
    /// that the pair's link is private.
    pub private_link: bool,
}

impl DialSettings {
    pub(crate) fn from_config(config: &Config) -> Self {
        Self {
            grasp_p_node: config.private_repos_enable,
            allow_non_global: config.sync_allow_non_global_targets,
            private_link: config.private_mirror_allow_private_ips,
        }
    }

    /// Whether `relay_url` may be registered as an event-directed relay:
    /// always on a node without private repositories, and on one with them
    /// over `wss://`, or over `ws://` for a configured peer (`is_peer`) on a
    /// link declared private, or for any relay under
    /// `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS`.
    ///
    /// The scheme is read as upstream's relay client reads it, so a spelling
    /// it would dial over TLS passes and every other spelling is refused.
    pub(crate) fn event_relay_allowed(&self, relay_url: &str, is_peer: bool) -> Result<(), String> {
        if !self.grasp_p_node
            || self.allow_non_global
            || (is_peer && self.private_link)
            || dials_over_tls(relay_url)
        {
            return Ok(());
        }
        Err(PLAINTEXT_RELAY_REFUSED.to_string())
    }
}

/// Whether a dial of `relay_url` would use TLS. The URL is parsed with the
/// parser the relay client uses, which reads the scheme in any case and
/// drops surrounding spaces, so no spelling of `ws://` passes as `wss://`.
/// A URL that does not parse is not dialled at all, and does not pass.
fn dials_over_tls(relay_url: &str) -> bool {
    url::Url::parse(relay_url).is_ok_and(|url| url.scheme() == "wss")
}

/// [`check_dial_settings`] for `Config::validate`: logs each warning, and
/// turns a refusal into the error that stops the node.
pub(crate) fn validate_dial_settings(config: &Config) -> anyhow::Result<()> {
    for warning in check_dial_settings(config).map_err(anyhow::Error::msg)? {
        tracing::warn!("{warning}");
    }
    Ok(())
}

/// What config validation says about the dial settings of a node: `Err`
/// stops it from starting, and each entry of `Ok` is a warning to log.
///
/// - Every configured sync peer (the entries of
///   `NGIT_GRASP_P_SYNC_PEER_URLS` that do not name this node, an
///   `http://` entry read as `ws://`) must be `wss://`, unless the pair's
///   link is declared private or `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS` is on.
///   A peer is sent every alias and key the node holds, and a peer that is
///   also the bootstrap relay is dialled as written, with no check at dial
///   time to stop a plaintext one.
/// - A `ws://` bootstrap relay keeps its scheme (it is the operator's own
///   choice, and carries public sync only unless it is also a peer), with a
///   warning.
/// - `NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS=true` lifts every outbound address
///   check and the `wss://` rule for what strangers' events name, with a
///   warning.
pub(crate) fn check_dial_settings(config: &Config) -> Result<Vec<String>, String> {
    let settings = DialSettings::from_config(config);
    if !settings.grasp_p_node {
        return Ok(Vec::new());
    }

    if !(settings.private_link || settings.allow_non_global) {
        let peers = crate::sync::private_index::configured_peer_relay_keys(
            &config.private_sync_peer_url_entries(),
            &config.service_address(),
        );
        if let Some(peer) = peers.iter().find(|peer| !dials_over_tls(peer)) {
            return Err(format!(
                "NGIT_GRASP_P_SYNC_PEER_URLS lists {peer}, a plaintext ws:// peer, and a peer \
                 is sent every alias and key this node holds: list it over wss://, or set \
                 NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS=true if the pair's link is private \
                 (an http:// entry is read as ws://)"
            ));
        }
    }

    let mut warnings = Vec::new();
    if let Some(bootstrap) = config
        .sync_bootstrap_relay_url
        .as_deref()
        .and_then(|url| crate::sync::canonical_relay_key(url).ok())
        .filter(|url| !dials_over_tls(url))
    {
        warnings.push(format!(
            "NGIT_SYNC_BOOTSTRAP_RELAY_URL is {bootstrap}, a plaintext ws:// relay: the \
             bootstrap relay keeps the scheme it is given, so anyone on its path reads and \
             can alter the sync it carries. Use wss:// unless the link is private"
        ));
    }
    if settings.allow_non_global {
        warnings.push(
            "NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS=true on a node that hosts private \
             repositories: relays and clone URLs that anyone's events name may point at \
             loopback and private addresses, and such relays are dialled over plaintext \
             ws:// too. It is meant for tests and closed networks; a pair on a private link \
             needs only NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS=true"
                .to_string(),
        );
    }
    Ok(warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PLAIN: &str = "ws://relay.example.com";
    const TLS: &str = "wss://relay.example.com";

    fn node(grasp_p_node: bool, allow_non_global: bool, private_link: bool) -> DialSettings {
        DialSettings {
            grasp_p_node,
            allow_non_global,
            private_link,
        }
    }

    /// Every branch of the rule, for a relay an event names and for a
    /// configured peer.
    #[test]
    fn an_event_named_relay_is_dialled_over_wss_only_on_a_grasp_p_node() {
        // (GRASP-P, non-global targets allowed, private link) -> may a
        // ws:// relay be registered, for a stranger and for a peer.
        for (grasp_p, allow_non_global, private_link, stranger, peer) in [
            // Without private repositories the rule is not there.
            (false, false, false, true, true),
            (false, false, true, true, true),
            // The rule itself, and a peer whose link is not declared private.
            (true, false, false, false, false),
            // A peer on a link declared private keeps ws://; a stranger does not.
            (true, false, true, false, true),
            // Tests and closed networks lift it for everyone.
            (true, true, false, true, true),
            (true, true, true, true, true),
        ] {
            let settings = node(grasp_p, allow_non_global, private_link);
            let case = format!("{settings:?}");
            assert_eq!(
                settings.event_relay_allowed(PLAIN, false).is_ok(),
                stranger,
                "{case}"
            );
            assert_eq!(
                settings.event_relay_allowed(PLAIN, true).is_ok(),
                peer,
                "{case}"
            );
            // wss:// passes in every case, for anyone.
            assert!(settings.event_relay_allowed(TLS, false).is_ok(), "{case}");
            assert!(settings.event_relay_allowed(TLS, true).is_ok(), "{case}");
        }

        let refusal = node(true, false, false)
            .event_relay_allowed(PLAIN, false)
            .expect_err("a ws:// relay an event names is refused");
        assert_eq!(refusal, PLAINTEXT_RELAY_REFUSED);
    }

    /// The scheme is the one upstream's relay client would dial: however it
    /// is spelled, `wss` passes and `ws` does not, and a URL the client
    /// cannot parse does not pass either.
    #[test]
    fn the_scheme_is_read_as_the_relay_client_reads_it() {
        use nostr_sdk::prelude::RelayUrl;

        let strict = node(true, false, false);
        for spelling in [
            "wss://relay.example.com",
            "WSS://relay.example.com",
            "Wss://relay.example.com/nostr",
            " wss://relay.example.com ",
            "\twss://relay.example.com\n",
            "ws://relay.example.com",
            "WS://relay.example.com",
            "wS://relay.example.com:443",
            " ws://relay.example.com",
            "ws://relay.example.com\t",
        ] {
            let tls = RelayUrl::parse(spelling)
                .unwrap_or_else(|error| panic!("the relay client parses {spelling:?}: {error}"))
                .scheme()
                .is_secure();
            assert_eq!(
                strict.event_relay_allowed(spelling, false).is_ok(),
                tls,
                "{spelling:?}"
            );
        }

        for unparsed in ["", "relay.example.com", "https://relay.example.com", "wss:"] {
            assert!(
                strict.event_relay_allowed(unparsed, false).is_err(),
                "{unparsed:?}"
            );
        }
    }

    fn grasp_p_config(configure: impl FnOnce(&mut Config)) -> Config {
        let mut config = Config::for_testing();
        config.private_repos_enable = true;
        configure(&mut config);
        config
    }

    /// A configured peer must be wss:// unless the pair's link is declared
    /// private or every address check is lifted, whether or not it is the
    /// bootstrap relay as well.
    #[test]
    fn a_plaintext_peer_stops_the_node_unless_its_link_is_private() {
        for listed in [
            "ws://peer.example.com",
            // Read as ws:// by the peer list.
            "http://peer.example.com:8080",
            "wss://other.example.com, ws://10.20.0.2:8080",
        ] {
            let config = grasp_p_config(|config| {
                config.private_sync_peer_urls = Some(listed.to_string());
            });
            let error = check_dial_settings(&config).expect_err("a ws:// peer is refused");
            assert!(
                error.contains("NGIT_GRASP_P_SYNC_PEER_URLS")
                    && error.contains("NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS")
                    && error.contains("ws://"),
                "{listed}: {error}"
            );

            let mut private_link = config.clone();
            private_link.private_mirror_allow_private_ips = true;
            assert_eq!(
                check_dial_settings(&private_link),
                Ok(Vec::new()),
                "{listed}"
            );
            let mut non_global = config.clone();
            non_global.sync_allow_non_global_targets = true;
            assert!(check_dial_settings(&non_global).is_ok(), "{listed}");

            // A node without private repositories has no peers.
            let mut upstream = config;
            upstream.private_repos_enable = false;
            assert_eq!(check_dial_settings(&upstream), Ok(Vec::new()), "{listed}");
        }

        // The peer that is also the bootstrap relay: registered as the
        // operator's own target, it is dialled as written, and validation is
        // all that stands between it and the private filters in plaintext.
        let config = grasp_p_config(|config| {
            config.private_sync_peer_urls = Some("ws://peer.example.com".to_string());
            config.sync_bootstrap_relay_url = Some("ws://peer.example.com".to_string());
        });
        assert!(check_dial_settings(&config).is_err());

        // wss://, a bare host (read as wss://), and a ws:// entry that names
        // this node, which is no peer, all pass.
        for listed in [
            "wss://peer.example.com",
            "peer.example.com",
            "ws://localhost:7334, wss://peer.example.com",
        ] {
            let config = grasp_p_config(|config| {
                config.private_sync_peer_urls = Some(listed.to_string());
            });
            assert_eq!(check_dial_settings(&config), Ok(Vec::new()), "{listed}");
        }
    }

    /// The warnings for a GRASP-P node configured by `configure`, which
    /// must not stop it.
    fn warned(configure: impl FnOnce(&mut Config)) -> Vec<String> {
        check_dial_settings(&grasp_p_config(configure)).expect("only warnings")
    }

    /// The two warnings, each alone and only on a node with private
    /// repositories.
    #[test]
    fn a_plaintext_bootstrap_relay_and_lifted_address_checks_are_warned_about() {
        assert_eq!(warned(|_| {}), Vec::<String>::new());

        let warnings = warned(|config| {
            config.sync_bootstrap_relay_url = Some("ws://bootstrap.example.com".to_string());
        });
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].contains("NGIT_SYNC_BOOTSTRAP_RELAY_URL")
                && warnings[0].contains("ws://bootstrap.example.com"),
            "{warnings:?}"
        );

        for tls in ["wss://bootstrap.example.com", "bootstrap.example.com"] {
            let mut config = grasp_p_config(|_| {});
            config.sync_bootstrap_relay_url = Some(tls.to_string());
            assert_eq!(check_dial_settings(&config), Ok(Vec::new()), "{tls}");
        }

        let warnings = warned(|config| config.sync_allow_non_global_targets = true);
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].contains("NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS=true"),
            "{warnings:?}"
        );

        // A ws:// bootstrap relay on a link declared private is still the
        // operator's plaintext target, and both warnings can stand together.
        let warnings = warned(|config| {
            config.sync_bootstrap_relay_url = Some("ws://10.20.0.2:8080".to_string());
            config.private_sync_peer_urls = Some("ws://10.20.0.2:8080".to_string());
            config.private_mirror_allow_private_ips = true;
            config.sync_allow_non_global_targets = true;
        });
        assert_eq!(warnings.len(), 2, "{warnings:?}");

        // Upstream's node says nothing about either.
        let mut config = Config::for_testing();
        config.sync_bootstrap_relay_url = Some("ws://bootstrap.example.com".to_string());
        config.sync_allow_non_global_targets = true;
        assert_eq!(check_dial_settings(&config), Ok(Vec::new()));
    }
}
