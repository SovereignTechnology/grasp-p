//! Relay names in the scrape of a GRASP-P node.
//!
//! Upstream's sync metrics label a series with the URL of the relay it is
//! about, and they do so for every relay the node dials. Most of those relays
//! are named by customers' events, and a scrape is shipped off the host into
//! a monitoring system. The label would carry, to wherever the numbers go,
//! which relays the repositories on this node point at. So on a node with
//! GRASP-P enabled no relay URL leaves in a label.
//!
//! The rewrite works on the gathered metric families, between the registry
//! and the encoder; the seam is in `Metrics::render`. Upstream's recorders
//! and the registry are left alone, and with GRASP-P off nothing is
//! rewritten. It goes by the name of the label and not by a list of
//! families, so a family that upstream labels with `relay` later is covered
//! the day it appears.
//!
//! A sample that names a relay ends in one of two ways:
//!
//! - **A peer keeps its series, under an alias**: `peer-1`, `peer-2` and so
//!   on. The alerts on the pair's other node need those series, and the
//!   alias is the same on every scrape, so the series has a history.
//! - **Any other relay's sample is dropped.** The aggregate series, which
//!   carry no relay label, still count those relays.
//!
//! The peers are the relays the operator named as the nodes this one
//! replicates private repositories with: the entries of
//! `NGIT_GRASP_P_SYNC_PEER_URLS`. That is the one set the sync code treats
//! as peers (`sync::private_index::configured_peer_relay_keys`, held by the
//! service), so a relay has an alias exactly when it carries GRASP-P
//! traffic. The setting is the operator's own, so an alias tells nothing
//! that a customer chose. The relay in `NGIT_SYNC_BOOTSTRAP_RELAY_URL` is a
//! peer, and has an alias, only when the list names it: one the list leaves
//! out carries public sync alone and is dropped with the other relays. So
//! are relays configured for another purpose, such as the user index and the
//! Sync+ fallbacks.
//!
//! A label is compared as it stands with the key the sync code files a relay
//! under, which is also what its recorders are given as the label. The
//! configured URLs are brought to that key by the function the sync code
//! uses for them, so every spelling of one relay is one peer. The comparison
//! is exact and a key has one alias, so two series of a family can never be
//! left with the same labels; a label in any other spelling names no peer
//! and is dropped.

use std::collections::HashMap;

use prometheus::proto::{Metric, MetricFamily};

use crate::config::Config;
use crate::sync::private_index::configured_peer_relay_keys;

/// The label upstream's sync metrics put a relay URL in.
const RELAY_LABEL: &str = "relay";

/// What every alias starts with; the number after it starts at 1. The alert
/// rules in `docs/grasp-p/ops/prometheus-alerts.yaml` select on it.
const ALIAS_PREFIX: &str = "peer-";

/// The aliases of this node's configured peers.
pub struct RelayLabels {
    /// From the key the sync code files a peer under to the alias its series
    /// carry.
    aliases: HashMap<String, String>,
}

impl RelayLabels {
    /// The aliases of a node with GRASP-P enabled; `None` on any other node,
    /// whose scrape stays upstream's.
    ///
    /// Peers are numbered in the order of `NGIT_GRASP_P_SYNC_PEER_URLS`, so
    /// the one peer of a pair is `peer-1`. An entry that names this node
    /// itself takes no number: the sync code never dials it, and a list
    /// shared by both nodes of a pair would otherwise number the other node
    /// differently on each.
    ///
    /// The list is read by the function the service builds its peer set
    /// with, own-address rule included, so that an alias exists for the
    /// relays the sync code treats as peers and for no other.
    pub fn from_config(config: &Config) -> Option<Self> {
        if !config.private_repos_enable {
            return None;
        }
        let peers = configured_peer_relay_keys(
            &config.private_sync_peer_url_entries(),
            &config.service_address(),
        );
        let aliases = peers
            .into_iter()
            .enumerate()
            .map(|(index, key)| (key, format!("{ALIAS_PREFIX}{}", index + 1)))
            .collect();
        Some(Self { aliases })
    }

    /// Take every relay URL out of the labels of `families`.
    ///
    /// A family left without a sample is removed with it. The registry
    /// prunes empty families before it hands the list over, and the text
    /// encoder answers one with an error, which would cost the whole scrape.
    ///
    /// This runs on every scrape. It reads each sample's label names once
    /// and looks up one string per sample that names a relay; only a peer's
    /// sample costs an allocation, and a dropped sample is one the encoder
    /// no longer writes.
    pub fn scrub(&self, mut families: Vec<MetricFamily>) -> Vec<MetricFamily> {
        families.retain_mut(|family| {
            let samples = family.mut_metric();
            samples.retain_mut(|sample| self.keep(sample));
            !samples.is_empty()
        });
        families
    }

    /// Whether `sample` stays in the scrape. One that names a peer is
    /// renamed to the peer's alias on the way.
    fn keep(&self, sample: &mut Metric) -> bool {
        let labels = sample.get_label();
        let Some(index) = labels.iter().position(|pair| pair.name() == RELAY_LABEL) else {
            return true;
        };
        let Some(alias) = self.aliases.get(labels[index].value()) else {
            return false;
        };
        let mut labels = sample.take_label();
        labels[index].set_value(alias.clone());
        sample.set_label(labels);
        true
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use prometheus::{IntCounterVec, Opts, Registry, TextEncoder};

    use super::*;
    use crate::sync::canonical_relay_key;
    use crate::sync::health::HealthState;
    use crate::sync::{ConnectionStatus, SyncMetrics};

    /// The families upstream labels with a relay, and how many series
    /// [`record_all`] leaves in each for one relay.
    const RELAY_FAMILIES: [(&str, usize); 6] = [
        ("ngit_sync_relay_connected", 1),
        ("ngit_sync_connection_attempts_total", 2),
        ("ngit_sync_relay_status", 1),
        ("ngit_sync_relay_failures", 1),
        ("ngit_sync_policy_refusals_total", 1),
        ("ngit_sync_hydration_events_total", 1),
    ];

    /// A GRASP-P node at `own.example` with this peer list and this
    /// bootstrap relay.
    fn node(peers: Option<&str>, bootstrap: Option<&str>) -> Config {
        let mut config = Config::for_testing();
        config.private_repos_enable = true;
        config.domain = "own.example".to_string();
        config.private_sync_peer_urls = peers.map(str::to_string);
        config.sync_bootstrap_relay_url = bootstrap.map(str::to_string);
        config
    }

    fn labels_for(peers: Option<&str>, bootstrap: Option<&str>) -> RelayLabels {
        RelayLabels::from_config(&node(peers, bootstrap)).expect("GRASP-P is enabled")
    }

    /// Upstream's sync metrics in a registry of their own, so that no test
    /// here touches the global one.
    fn sync_metrics() -> (Registry, SyncMetrics) {
        let registry = Registry::new();
        let metrics = SyncMetrics::register(&registry).expect("a fresh registry");
        (registry, metrics)
    }

    /// Every recorder of upstream's that takes a relay, so that all six
    /// families hold a series for `relay`.
    fn record_all(metrics: &SyncMetrics, relay: &str) {
        metrics.record_connection_attempt(relay, true);
        metrics.record_connection_attempt(relay, false);
        metrics.set_relay_connected(relay, true);
        metrics.record_connection_status(relay, ConnectionStatus::Connected);
        metrics.record_health_state(relay, HealthState::Healthy);
        metrics.record_failure_count(relay, 2);
        metrics.record_policy_refusal(relay, "blocked");
        metrics.record_hydration_events(relay, "stream", "delivered", 3);
    }

    /// The `relay` label of every series of `family`.
    fn relays_of(families: &[MetricFamily], family: &str) -> Vec<String> {
        families
            .iter()
            .filter(|candidate| candidate.name() == family)
            .flat_map(|candidate| candidate.get_metric())
            .filter_map(|sample| {
                sample
                    .get_label()
                    .iter()
                    .find(|pair| pair.name() == RELAY_LABEL)
                    .map(|pair| pair.value().to_string())
            })
            .collect()
    }

    /// The families no recorder labels with a relay.
    fn without_relay_families(families: &[MetricFamily]) -> Vec<MetricFamily> {
        families
            .iter()
            .filter(|candidate| {
                RELAY_FAMILIES
                    .iter()
                    .all(|(family, _)| *family != candidate.name())
            })
            .cloned()
            .collect()
    }

    /// The scrape as the endpoint would send it. The encoder refuses a
    /// family with no series, so this also fails on one left behind.
    fn text(families: &[MetricFamily]) -> String {
        TextEncoder::new()
            .encode_to_string(families)
            .expect("every family left has a series")
    }

    #[test]
    fn scrub_renames_configured_peers_and_drops_other_relays() {
        let (registry, metrics) = sync_metrics();
        record_all(&metrics, "wss://peer.example");
        record_all(&metrics, "wss://stranger.example");
        metrics.set_tracked_count(2);
        let gathered = registry.gather();
        for (family, series) in RELAY_FAMILIES {
            assert_eq!(
                relays_of(&gathered, family).len(),
                2 * series,
                "{family} must hold series for both relays, or this test checks nothing"
            );
        }

        let scrubbed = labels_for(Some("wss://peer.example"), None).scrub(gathered.clone());

        for (family, series) in RELAY_FAMILIES {
            assert_eq!(
                relays_of(&scrubbed, family),
                vec!["peer-1"; series],
                "{family}: the peer's series stay under its alias, the stranger's go"
            );
        }
        let rendered = text(&scrubbed);
        assert!(
            !rendered.contains("://") && !rendered.contains("example"),
            "no relay URL and no host may be left in the scrape:\n{rendered}"
        );
        assert!(
            rendered.contains("ngit_sync_relay_connected{relay=\"peer-1\"} 3\n")
                && rendered.contains("ngit_sync_relay_failures{relay=\"peer-1\"} 2\n"),
            "a renamed series keeps its value:\n{rendered}"
        );

        let aggregates = without_relay_families(&gathered);
        assert!(
            aggregates
                .iter()
                .any(|family| family.name() == "ngit_sync_relays_tracked_total"),
            "the aggregate gauges must be in the registry, or the next check is empty"
        );
        assert_eq!(
            without_relay_families(&scrubbed),
            aggregates,
            "a family without a relay label is handed on untouched"
        );
        assert!(rendered.contains("ngit_sync_relays_tracked_total 2\n"));
    }

    #[test]
    fn scrub_matches_peer_urls_in_any_configured_form() {
        let label = canonical_relay_key("wss://relay.example").expect("a valid relay URL");
        for configured in [
            "wss://relay.example",
            "wss://relay.example/",
            "relay.example",
            "relay.example/",
            "https://relay.example",
            " https://relay.example/ ",
        ] {
            let (registry, metrics) = sync_metrics();
            metrics.record_failure_count(&label, 7);
            let scrubbed = labels_for(Some(configured), None).scrub(registry.gather());
            assert_eq!(
                relays_of(&scrubbed, "ngit_sync_relay_failures"),
                vec!["peer-1"],
                "a peer configured as {configured:?} is the relay labelled {label}"
            );
        }
    }

    #[test]
    fn a_relay_on_another_scheme_host_or_path_is_not_the_peer() {
        let label = canonical_relay_key("wss://relay.example").expect("a valid relay URL");
        for configured in [
            "ws://relay.example",
            "http://relay.example",
            "wss://relay.example/nostr",
            "wss://other.example",
        ] {
            let (registry, metrics) = sync_metrics();
            metrics.record_failure_count(&label, 7);
            let scrubbed = labels_for(Some(configured), None).scrub(registry.gather());
            assert!(
                relays_of(&scrubbed, "ngit_sync_relay_failures").is_empty(),
                "a peer configured as {configured:?} is not the relay labelled {label}"
            );
        }
    }

    #[test]
    fn scrub_numbers_peers_in_configured_order_and_dedupes() {
        let (registry, metrics) = sync_metrics();
        metrics.record_failure_count("wss://a.example", 1);
        metrics.record_failure_count("wss://b.example", 2);
        metrics.record_failure_count("wss://c.example", 3);

        // b comes first and is listed twice, in two spellings.
        let labels = labels_for(
            Some("wss://b.example, b.example/, https://a.example, wss://c.example"),
            None,
        );
        let rendered = text(&labels.scrub(registry.gather()));
        for (alias, failures) in [("peer-1", 2), ("peer-2", 1), ("peer-3", 3)] {
            assert!(
                rendered.contains(&format!(
                    "ngit_sync_relay_failures{{relay=\"{alias}\"}} {failures}\n"
                )),
                "{alias} must be the relay with {failures} failures:\n{rendered}"
            );
        }
        assert!(!rendered.contains("peer-4"), "{rendered}");
    }

    /// The bootstrap relay is a peer only when the list names it, as in the
    /// sync code: one the list leaves out carries no GRASP-P traffic and its
    /// series go with every other relay's. Named in the list, it keeps the
    /// number of its entry.
    #[test]
    fn the_bootstrap_relay_is_a_peer_only_when_listed() {
        let (registry, metrics) = sync_metrics();
        record_all(&metrics, "wss://b.example");
        metrics.record_failure_count("wss://a.example", 1);

        let scrubbed = labels_for(None, Some("wss://b.example")).scrub(registry.gather());
        for (family, _) in RELAY_FAMILIES {
            assert!(
                relays_of(&scrubbed, family).is_empty(),
                "{family}: a bootstrap relay the list leaves out has no series"
            );
        }

        let scrubbed =
            labels_for(Some("wss://a.example"), Some("wss://b.example")).scrub(registry.gather());
        assert_eq!(
            relays_of(&scrubbed, "ngit_sync_relay_failures"),
            vec!["peer-1"],
            "the listed relay is the one peer"
        );

        let scrubbed = labels_for(
            Some("wss://a.example,wss://b.example"),
            Some("wss://b.example/"),
        )
        .scrub(registry.gather());
        for (family, series) in RELAY_FAMILIES {
            let relays = relays_of(&scrubbed, family);
            assert_eq!(
                relays.iter().filter(|relay| *relay == "peer-2").count(),
                series,
                "{family}: a bootstrap relay the list names is the peer of its entry"
            );
            assert!(
                relays
                    .iter()
                    .all(|relay| relay == "peer-1" || relay == "peer-2"),
                "{family}: {relays:?}"
            );
        }
    }

    #[test]
    fn an_entry_that_names_this_node_takes_no_number() {
        let (registry, metrics) = sync_metrics();
        metrics.record_failure_count("wss://own.example", 1);
        metrics.record_failure_count("wss://b.example", 2);

        // One list for both nodes of a pair: on this node its first entry
        // is the node itself.
        let labels = labels_for(Some("wss://own.example,wss://b.example"), None);
        let rendered = text(&labels.scrub(registry.gather()));

        assert!(
            rendered.contains("ngit_sync_relay_failures{relay=\"peer-1\"} 2\n")
                && !rendered.contains("peer-2"),
            "the other node must be peer-1 here as well:\n{rendered}"
        );
    }

    #[test]
    fn aliases_exist_for_exactly_the_relays_sync_treats_as_peers() {
        let config = node(
            Some("wss://own.example, b.example/, https://a.example, wss://b.example"),
            Some("wss://c.example/"),
        );
        // The peer set the service holds, which every GRASP-P privilege of a
        // relay connection goes by. Never this node, and never the bootstrap
        // relay the list does not name.
        let peers = super::super::PrivateConfig::from_config(&config).sync_peer_relays;
        assert_eq!(
            peers,
            ["wss://b.example", "wss://a.example"]
                .map(|url| canonical_relay_key(url).expect("a valid relay URL"))
                .into_iter()
                .collect::<HashSet<_>>(),
            "a and b; never this node itself, never c"
        );

        let labels = RelayLabels::from_config(&config).expect("GRASP-P is enabled");

        let aliased: HashSet<String> = labels.aliases.keys().cloned().collect();
        assert_eq!(aliased, peers);
    }

    /// Under a mount path this node is its host and that path together: a
    /// relay on the same host under another path is a peer the sync code
    /// dials, so it has an alias, and the two readings still agree.
    #[test]
    fn under_a_mount_path_only_the_mounted_url_is_this_node() {
        let mut config = node(
            Some("wss://own.example/grasp, wss://own.example/other, wss://b.example/grasp"),
            None,
        );
        config.base_path = "/grasp".to_string();

        let peers = super::super::PrivateConfig::from_config(&config).sync_peer_relays;
        assert_eq!(peers.len(), 2, "the two other services, never this one");

        let labels = RelayLabels::from_config(&config).expect("GRASP-P is enabled");
        let aliased: HashSet<String> = labels.aliases.keys().cloned().collect();
        assert_eq!(aliased, peers);
    }

    #[test]
    fn scrub_with_no_peers_drops_every_relay_series() {
        let (registry, metrics) = sync_metrics();
        record_all(&metrics, "wss://one.example");
        record_all(&metrics, "wss://two.example");
        metrics.set_tracked_count(2);

        let scrubbed = labels_for(None, None).scrub(registry.gather());

        for (family, _) in RELAY_FAMILIES {
            assert!(
                scrubbed.iter().all(|kept| kept.name() != family),
                "{family} has no series left and must be gone with them"
            );
        }
        let rendered = text(&scrubbed);
        assert!(!rendered.contains("relay="), "{rendered}");
        assert!(rendered.contains("ngit_sync_relays_tracked_total 2\n"));
    }

    #[test]
    fn a_label_in_another_spelling_is_dropped_and_never_merged() {
        let (registry, metrics) = sync_metrics();
        metrics.record_failure_count("wss://b.example", 1);
        // Not the form the sync code files the relay under. Folding it into
        // the peer would leave two series with the same labels.
        metrics.record_failure_count("wss://b.example/", 2);

        let scrubbed = labels_for(Some("wss://b.example"), None).scrub(registry.gather());

        assert_eq!(
            relays_of(&scrubbed, "ngit_sync_relay_failures"),
            vec!["peer-1"]
        );
        assert!(text(&scrubbed).contains("ngit_sync_relay_failures{relay=\"peer-1\"} 1\n"));
    }

    #[test]
    fn scrub_goes_by_the_label_name_in_any_family() {
        let registry = Registry::new();
        let added_later = IntCounterVec::new(
            Opts::new(
                "ngit_sync_added_later_total",
                "A family upstream might label with a relay one day",
            ),
            &["kind", "relay"],
        )
        .expect("valid options");
        registry
            .register(Box::new(added_later.clone()))
            .expect("a fresh registry");
        added_later
            .with_label_values(&["first", "wss://b.example"])
            .inc();
        added_later
            .with_label_values(&["first", "wss://stranger.example"])
            .inc();

        let scrubbed = labels_for(Some("wss://b.example"), None).scrub(registry.gather());

        assert_eq!(
            relays_of(&scrubbed, "ngit_sync_added_later_total"),
            vec!["peer-1"]
        );
        assert!(!text(&scrubbed).contains("://"));
    }

    /// Upstream's file, read as text. A sync that adds a family labelled
    /// with a relay, or a method that takes one, leaves `RELAY_FAMILIES` and
    /// `record_all` short without failing any test above; this one fails
    /// and names what to bring up to date.
    #[test]
    fn the_families_and_recorders_driven_here_are_all_upstream_has() {
        let upstream = include_str!("../sync/metrics.rs");
        assert_eq!(
            upstream.matches("&[\"relay\"").count(),
            RELAY_FAMILIES.len(),
            "upstream's families labelled with a relay changed: bring RELAY_FAMILIES and \
             record_all up to date"
        );
        assert_eq!(
            upstream.matches("(&self, relay: &str").count(),
            8,
            "upstream's methods that take a relay changed (seven recorders and forget_relay): \
             bring record_all up to date"
        );
    }

    #[test]
    fn relay_labels_are_absent_when_grasp_p_is_off() {
        assert!(RelayLabels::from_config(&Config::for_testing()).is_none());

        // Peers left in the configuration of a node that has GRASP-P
        // switched off do not bring the rewrite back.
        let mut config = node(Some("wss://b.example"), Some("wss://b.example"));
        config.private_repos_enable = false;
        assert!(RelayLabels::from_config(&config).is_none());
    }
}
