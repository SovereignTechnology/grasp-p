//! Relay-owner identity events and user-index publication.
//!
//! The relay owner key is also useful as a service identity for applications
//! such as `ngit-ci`. On startup the relay signs a minimal NIP-01 profile and
//! a NIP-65 relay list, but a generated event is never allowed to displace an
//! identity the operator already published: kinds with a locally stored event
//! keep the stored version, and kinds with no local copy are held back until
//! at least one configured user-index relay is reachable and confirms it has
//! no identity of that kind either. Publication is gated the same way for
//! every kind — stored or generated, nothing is sent until the local database
//! and at least one user-index relay have been checked for that kind, and
//! each individual send is preceded by a per-relay re-check. An identity
//! found on a user-index relay is adopted locally instead of being
//! overwritten, so this relay never replaces an identity an index already
//! holds. Only confirmed-absent kinds are retried against the user-index
//! relays with a capped backoff. In private mode identity events are seeded
//! locally but never published, so the relay's existence is not advertised.

use std::collections::{HashMap, HashSet};
use std::time::Duration;

use anyhow::{Context, Result};
use nostr::nips::nip01::Metadata;
use nostr::nips::nip65::RelayList;
use nostr_sdk::local_relay::LocalRelay;
use nostr_sdk::prelude::*;
use tokio::task::JoinHandle;

use crate::config::Config;
use crate::nostr::lifecycle::DeletionService;
use crate::nostr::SharedDatabase;

const INDEX_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const INDEX_PUBLISH_TIMEOUT: Duration = Duration::from_secs(10);
const INDEX_FETCH_TIMEOUT: Duration = Duration::from_secs(10);

fn in_test_mode() -> bool {
    std::env::var("NGIT_TEST").as_deref() == Ok("1")
}

fn index_retry_initial_interval() -> Duration {
    if in_test_mode() {
        Duration::from_millis(200)
    } else {
        Duration::from_secs(60)
    }
}

fn index_retry_max_interval() -> Duration {
    if in_test_mode() {
        Duration::from_secs(2)
    } else {
        Duration::from_secs(15 * 60)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublicationFailureDisposition {
    AlreadyStored,
    Terminal,
    Retry,
}

/// The replaceable identity events signed by the relay owner.
#[derive(Debug, Clone)]
pub struct RelayIdentityEvents {
    pub profile: Event,
    pub relay_list: Event,
}

impl RelayIdentityEvents {
    fn iter(&self) -> impl Iterator<Item = &Event> {
        [&self.profile, &self.relay_list].into_iter()
    }
}

/// Identity events split by their local provenance.
///
/// Stored events are the operator-approved local history. Generated events
/// exist only because no local copy was found; they must not even be seeded
/// until the user-index relays confirm no existing identity of that kind.
/// Neither set is published before at least one user-index relay has been
/// successfully queried for the kind: a stored event is not trustworthy on
/// its own either, because a database wipe followed by a boot during an
/// index outage stores a fresh minimal event that must not later displace a
/// customized profile surviving on the indexes.
#[derive(Debug, Default)]
pub struct IdentityPublicationPlan {
    stored: Vec<Event>,
    generated: Vec<Event>,
}

impl IdentityPublicationPlan {
    fn is_empty(&self) -> bool {
        self.stored.is_empty() && self.generated.is_empty()
    }
}

/// Build the relay owner's minimal profile and single-relay NIP-65 list.
pub fn build(config: &Config) -> Result<RelayIdentityEvents> {
    let keys = config.relay_owner_keys()?;
    let domain = config.domain.trim().trim_end_matches('/');
    let relay_url = public_relay_url(domain)?;
    let created_at = Timestamp::now();

    let profile = Metadata::new()
        // The scheme-less public URL (authority plus any mount path) so
        // clients that ignore the NIP-05 fallback still display something
        // meaningful. NIP-24 expects `name` to always be set.
        .name(domain)
        .nip05(format!("_@{domain}"))
        .custom_field("bot", true)
        .into_event_builder()
        .custom_created_at(created_at)
        .finalize(&keys)
        .context("sign relay-owner kind-0 profile")?;
    let relay_list = RelayList::new([(relay_url, None)])
        .into_event_builder()
        .custom_created_at(created_at)
        .finalize(&keys)
        .context("sign relay-owner kind-10002 relay list")?;

    Ok(RelayIdentityEvents {
        profile,
        relay_list,
    })
}

/// Decide how each identity kind may be published.
///
/// Kinds with a stored local event keep it — a profile the operator
/// customized through another client survives restarts — and republish the
/// stored version to the user-index relays. Kinds with no local copy are
/// deferred to the background publication task, which seeds them only after
/// a reachable user-index relay confirms no existing identity. When no
/// user-index relays are configured — or the relay runs in private mode and
/// must not check or announce anything externally — there is nothing to
/// query, so missing kinds are seeded locally right away. Deletion
/// tombstones and local
/// policy rejections skip a kind with a warning instead of failing startup —
/// identity publication is a convenience, not a precondition for serving
/// traffic. Only genuine database errors are fatal here.
pub async fn prepare(
    relay: &LocalRelay,
    database: &SharedDatabase,
    deletion: &DeletionService,
    config: &Config,
    generated: &RelayIdentityEvents,
) -> Result<IdentityPublicationPlan> {
    let has_index_targets = !config.private_mode
        && config
            .parse_user_index_relays()
            .iter()
            .any(|configured| RelayUrl::parse(configured).is_ok());

    let mut plan = IdentityPublicationPlan::default();
    for event in generated.iter() {
        let existing = database
            .query(Filter::new().author(event.pubkey).kind(event.kind).limit(1))
            .await
            .with_context(|| format!("query stored relay-owner kind {}", event.kind.as_u16()))?
            .into_iter()
            .next();
        if let Some(existing) = existing {
            tracing::info!(
                kind = existing.kind.as_u16(),
                event_id = %existing.id,
                "Relay-owner identity already stored; keeping the existing event"
            );
            plan.stored.push(existing);
            continue;
        }

        if has_index_targets {
            plan.generated.push(event.clone());
        } else {
            seed_local_event(relay, deletion, event, "generated")
                .await
                .with_context(|| {
                    format!("seed relay-owner kind {} locally", event.kind.as_u16())
                })?;
        }
    }
    Ok(plan)
}

/// Seed an identity event into this relay's database.
///
/// `add_event` writes directly to the database, so respect the same
/// NIP-09/NIP-62 tombstones the write policy enforces for events arriving
/// over WebSocket. Returns whether the event ended up stored; `Err` is
/// reserved for genuine database failures.
async fn seed_local_event(
    relay: &LocalRelay,
    deletion: &DeletionService,
    event: &Event,
    provenance: &str,
) -> Result<bool> {
    if deletion.gate(event).await.is_some() {
        tracing::warn!(
            kind = event.kind.as_u16(),
            provenance,
            "Relay-owner identity event is tombstoned by a deletion request; not seeding"
        );
        return Ok(false);
    }

    let status = relay
        .add_event(event.clone())
        .await
        .with_context(|| format!("store relay-owner kind {}", event.kind.as_u16()))?;
    match status {
        SaveEventStatus::Success | SaveEventStatus::Rejected(RejectedReason::Duplicate) => {
            tracing::info!(
                kind = event.kind.as_u16(),
                event_id = %event.id,
                author = %event.pubkey.to_hex(),
                provenance,
                "Seeded relay-owner identity event locally"
            );
            Ok(true)
        }
        SaveEventStatus::Rejected(RejectedReason::Replaced) => {
            // Expected when adopting a user-index copy that is older than
            // the locally stored identity: replaceable-event semantics keep
            // the newest, which is already what we have.
            tracing::info!(
                kind = event.kind.as_u16(),
                event_id = %event.id,
                provenance,
                "Local database already holds a newer relay-owner identity of this kind"
            );
            Ok(false)
        }
        SaveEventStatus::Rejected(reason) => {
            tracing::warn!(
                kind = event.kind.as_u16(),
                event_id = %event.id,
                ?reason,
                provenance,
                "Local database rejected relay-owner identity event; continuing"
            );
            Ok(false)
        }
    }
}

/// Publish identity events to configured user-index relays in the background.
///
/// Invalid configured URLs are reported and skipped. In private mode nothing
/// is ever published: identity events would advertise the relay's existence.
/// Otherwise nothing is published until at least one user-index relay is
/// reachable and has been successfully queried for every identity kind in
/// the plan. A kind the reachable indexes already hold is adopted locally —
/// replaceable-event semantics keep the newest copy — and is never
/// published, so this relay cannot displace an identity an index holds.
/// Generated kinds the indexes confirm absent are seeded locally and queued;
/// stored kinds confirmed absent are queued as-is. Before any event is sent
/// to an individual index relay, that relay is asked once more for an
/// existing identity of the same kind, so an index that was unreachable
/// during the initial check — perhaps holding a customized profile — still
/// cannot have it displaced. Valid targets remain in the retry set until
/// each acknowledges every event; duplicate replies count as
/// acknowledgement, terminal policy replies are reported without retrying,
/// and transient index failures remain pending with a capped backoff. Remote
/// availability therefore never gates successful server startup.
pub fn spawn_user_index_publication(
    config: &Config,
    plan: IdentityPublicationPlan,
    relay: LocalRelay,
    deletion: DeletionService,
) -> Option<JoinHandle<()>> {
    if config.private_mode {
        // A private relay must not leak its existence through identity
        // events on public user-index relays.
        tracing::info!(
            "Private mode enabled; relay-owner identity stays local and is not published"
        );
        return None;
    }
    if plan.is_empty() {
        return None;
    }

    let mut targets = HashSet::new();
    for configured in config.parse_user_index_relays() {
        match RelayUrl::parse(&configured) {
            Ok(relay) => {
                targets.insert(relay);
            }
            Err(error) => tracing::warn!(
                relay = %configured,
                %error,
                "Cannot publish relay-owner identity to invalid user-index relay"
            ),
        }
    }
    if targets.is_empty() {
        return None;
    }

    let keys = match config.relay_owner_keys() {
        Ok(keys) => keys,
        Err(error) => {
            tracing::error!(%error, "Cannot initialize relay-owner identity publisher");
            return None;
        }
    };

    Some(tokio::spawn(async move {
        publish_to_user_indexes(keys, plan, targets, relay, deletion).await;
    }))
}

async fn publish_to_user_indexes(
    keys: Keys,
    plan: IdentityPublicationPlan,
    targets: HashSet<RelayUrl>,
    local_relay: LocalRelay,
    deletion: DeletionService,
) {
    let client = Client::builder()
        .authenticator(SignerAuthenticator::new(keys))
        .connect_timeout(INDEX_CONNECT_TIMEOUT)
        .build();

    let mut registered: HashSet<RelayUrl> = HashSet::new();
    for relay in targets {
        match client
            .add_relay(relay.clone())
            .connect_timeout(INDEX_CONNECT_TIMEOUT)
            .await
        {
            Ok(_) => {
                registered.insert(relay);
            }
            Err(error) => tracing::warn!(
                relay = %relay,
                %error,
                "Cannot register user-index relay for relay-owner identity publication"
            ),
        }
    }
    if registered.is_empty() {
        return;
    }

    // Phase 1: wait for at least one reachable user-index relay and query it
    // for every identity kind in the plan — stored kinds included. Until
    // then nothing is seeded or published, so an unreachable index fleet can
    // never be a reason to sign away an identity the operator may have
    // customized elsewhere, and a database wiped and reseeded during an
    // index outage cannot push its regenerated identity over a customized
    // profile surviving on the indexes. A kind any reachable index already
    // holds is adopted locally and never published.
    //
    // Double the delay toward the cap so a permanently unreachable index
    // does not produce a warning every minute for the process lifetime. The
    // first attempt runs immediately.
    let candidates: Vec<(Event, bool)> = plan
        .stored
        .into_iter()
        .map(|event| (event, false))
        .chain(plan.generated.into_iter().map(|event| (event, true)))
        .collect();
    // `spawn_user_index_publication` only starts this task for a non-empty
    // plan, and every identity event is authored by the relay owner.
    let owner = candidates[0].0.pubkey;
    let kinds: Vec<Kind> = candidates.iter().map(|(event, _)| event.kind).collect();
    let mut retry_delay = Duration::ZERO;
    let publish_events: Vec<Event> = loop {
        tokio::time::sleep(retry_delay).await;
        retry_delay =
            (retry_delay * 2).clamp(index_retry_initial_interval(), index_retry_max_interval());
        let _ = client.try_connect().timeout(INDEX_CONNECT_TIMEOUT).await;

        let connected: Vec<RelayUrl> = client
            .relays()
            .await
            .into_iter()
            .filter(|(_, relay)| relay.status() == RelayStatus::Connected)
            .map(|(url, _)| url)
            .collect();
        if connected.is_empty() {
            tracing::warn!(
                "No user-index relay reachable; deferring relay-owner identity publication"
            );
            continue;
        }

        let filter = Filter::new().author(owner).kinds(kinds.clone());
        let target =
            ReqTarget::manual(connected.into_iter().map(|url| (url, vec![filter.clone()])));
        let found = match client
            .fetch_events(target)
            .timeout(INDEX_FETCH_TIMEOUT)
            .await
        {
            Ok(found) => found,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "Cannot check user-index relays for an existing relay-owner identity; retrying"
                );
                continue;
            }
        };

        let mut publish_events = Vec::new();
        for (event, is_generated) in &candidates {
            if let Some(remote) = newest_owner_event_of_kind(&found, owner, event.kind) {
                tracing::info!(
                    kind = event.kind.as_u16(),
                    event_id = %remote.id,
                    "User-index relays already hold a relay-owner identity of this kind; \
                     adopting it instead of publishing"
                );
                if let Err(error) =
                    seed_local_event(&local_relay, &deletion, &remote, "user-index").await
                {
                    tracing::error!(%error, "Failed to adopt relay-owner identity locally");
                }
                continue;
            }
            if *is_generated {
                match seed_local_event(&local_relay, &deletion, event, "generated").await {
                    Ok(true) => publish_events.push(event.clone()),
                    Ok(false) => {}
                    Err(error) => {
                        tracing::error!(%error, "Failed to seed relay-owner identity locally")
                    }
                }
            } else {
                publish_events.push(event.clone());
            }
        }
        break publish_events;
    };

    if publish_events.is_empty() {
        client.shutdown().await;
        return;
    }

    // Phase 2: retry publication until every registered index acknowledges
    // every event or returns a terminal rejection.
    let mut pending: HashMap<RelayUrl, HashSet<EventId>> = registered
        .into_iter()
        .map(|relay| (relay, publish_events.iter().map(|event| event.id).collect()))
        .collect();
    let mut retry_delay = Duration::ZERO;
    while !pending.is_empty() {
        tokio::time::sleep(retry_delay).await;
        retry_delay =
            (retry_delay * 2).clamp(index_retry_initial_interval(), index_retry_max_interval());
        let _ = client.try_connect().timeout(INDEX_CONNECT_TIMEOUT).await;

        let relays: Vec<RelayUrl> = pending.keys().cloned().collect();
        for relay in relays {
            for event in publish_events.iter() {
                if !pending
                    .get(&relay)
                    .is_some_and(|event_ids| event_ids.contains(&event.id))
                {
                    continue;
                }

                // No publication may displace an identity that already
                // exists on an index — including one that was unreachable
                // during the phase-1 check and may hold a customized
                // profile. Ask this specific relay right before publishing
                // any event, stored or generated; an identity found there
                // is adopted locally instead, and verification failure
                // keeps the event pending rather than risking an overwrite.
                let filter = Filter::new().author(event.pubkey).kind(event.kind).limit(1);
                match client
                    .fetch_events(ReqTarget::single(relay.clone(), [filter]))
                    .timeout(INDEX_FETCH_TIMEOUT)
                    .await
                {
                    Ok(found) => {
                        if let Some(remote) =
                            newest_owner_event_of_kind(&found, event.pubkey, event.kind)
                        {
                            if let Some(event_ids) = pending.get_mut(&relay) {
                                event_ids.remove(&event.id);
                            }
                            tracing::info!(
                                relay = %relay,
                                kind = event.kind.as_u16(),
                                event_id = %remote.id,
                                "User-index relay already has a relay-owner identity of this \
                                 kind; adopting it instead of publishing"
                            );
                            if let Err(error) =
                                seed_local_event(&local_relay, &deletion, &remote, "user-index")
                                    .await
                            {
                                tracing::error!(
                                    %error,
                                    "Failed to adopt relay-owner identity locally"
                                );
                            }
                            continue;
                        }
                    }
                    Err(error) => {
                        tracing::warn!(
                            relay = %relay,
                            kind = event.kind.as_u16(),
                            %error,
                            "Cannot verify user-index relay before publishing relay-owner \
                             identity; keeping it pending"
                        );
                        continue;
                    }
                }

                let send = client.send_event(event).to(std::iter::once(relay.clone()));
                match tokio::time::timeout(INDEX_PUBLISH_TIMEOUT, send).await {
                    Ok(Ok(output)) if output.success.contains_key(&relay) => {
                        if let Some(event_ids) = pending.get_mut(&relay) {
                            event_ids.remove(&event.id);
                        }
                        tracing::info!(
                            relay = %relay,
                            event_id = %event.id,
                            kind = event.kind.as_u16(),
                            "Published relay-owner identity event to user-index relay"
                        );
                    }
                    Ok(Ok(output)) => {
                        let failure = output.failed.get(&relay);
                        match failure.map(|failure| publication_failure_disposition(failure)) {
                            Some(PublicationFailureDisposition::AlreadyStored) => {
                                if let Some(event_ids) = pending.get_mut(&relay) {
                                    event_ids.remove(&event.id);
                                }
                                tracing::info!(
                                    relay = %relay,
                                    event_id = %event.id,
                                    kind = event.kind.as_u16(),
                                    "User-index relay already stores relay-owner identity event"
                                );
                            }
                            Some(PublicationFailureDisposition::Terminal) => {
                                if let Some(event_ids) = pending.get_mut(&relay) {
                                    event_ids.remove(&event.id);
                                }
                                tracing::warn!(
                                    relay = %relay,
                                    event_id = %event.id,
                                    kind = event.kind.as_u16(),
                                    failure,
                                    "User-index relay permanently rejected relay-owner identity event"
                                );
                            }
                            Some(PublicationFailureDisposition::Retry) | None => tracing::warn!(
                                relay = %relay,
                                event_id = %event.id,
                                kind = event.kind.as_u16(),
                                failures = ?output.failed,
                                "User-index relay did not acknowledge relay-owner identity event"
                            ),
                        }
                    }
                    Ok(Err(error)) => tracing::warn!(
                        relay = %relay,
                        event_id = %event.id,
                        kind = event.kind.as_u16(),
                        %error,
                        "Failed to publish relay-owner identity event to user-index relay"
                    ),
                    Err(_) => tracing::warn!(
                        relay = %relay,
                        event_id = %event.id,
                        kind = event.kind.as_u16(),
                        "Timed out publishing relay-owner identity event to user-index relay"
                    ),
                }
            }
            if pending.get(&relay).is_some_and(HashSet::is_empty) {
                pending.remove(&relay);
            }
        }
    }

    client.shutdown().await;
}

/// Newest verified owner-authored event of the given kind in a fetch result.
///
/// The author and kind are re-checked because the filter is only advisory to
/// the remote relay, and the signature is verified before the event can be
/// adopted into the local database.
fn newest_owner_event_of_kind(
    events: &std::collections::BTreeSet<Event>,
    owner: PublicKey,
    kind: Kind,
) -> Option<Event> {
    events
        .iter()
        .filter(|event| event.pubkey == owner && event.kind == kind && event.verify().is_ok())
        .max_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        })
        .cloned()
}

fn publication_failure_disposition(message: &str) -> PublicationFailureDisposition {
    match MachineReadablePrefix::parse(message) {
        Some(MachineReadablePrefix::Duplicate) => PublicationFailureDisposition::AlreadyStored,
        Some(
            MachineReadablePrefix::Pow
            | MachineReadablePrefix::Blocked
            | MachineReadablePrefix::Invalid
            | MachineReadablePrefix::Unsupported
            | MachineReadablePrefix::Restricted,
        ) => PublicationFailureDisposition::Terminal,
        _ => PublicationFailureDisposition::Retry,
    }
}

fn public_relay_url(domain: &str) -> Result<RelayUrl> {
    let scheme = if is_loopback_authority(domain) {
        "ws"
    } else {
        "wss"
    };
    // A bare IPv6 authority must be bracketed to form a valid URL.
    let authority = if domain.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{domain}]")
    } else {
        domain.to_string()
    };
    RelayUrl::parse(&format!("{scheme}://{authority}"))
        .with_context(|| format!("derive public relay URL from NGIT_DOMAIN={domain}"))
}

fn is_loopback_authority(domain: &str) -> bool {
    // A bare IP authority (including unbracketed IPv6 like `::1`) parses
    // whole; otherwise strip an optional port from `host:port` / `[v6]:port`.
    if let Ok(address) = domain.parse::<std::net::IpAddr>() {
        return address.is_loopback();
    }
    let host = domain
        .strip_prefix('[')
        .and_then(|value| value.split_once(']').map(|(host, _)| host))
        .unwrap_or_else(|| domain.split(':').next().unwrap_or(domain));
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::nips::nip65;

    #[test]
    fn identity_is_minimal_and_lists_only_this_relay_for_read_and_write() {
        let config = Config::for_testing();
        let events = build(&config).expect("build relay identity");

        let profile: serde_json::Value =
            serde_json::from_str(&events.profile.content).expect("parse profile metadata");
        let fields = profile.as_object().expect("profile object");
        assert_eq!(fields.len(), 3);
        assert_eq!(
            fields.get("name"),
            Some(&serde_json::json!("localhost:7334"))
        );
        assert_eq!(
            fields.get("nip05"),
            Some(&serde_json::json!("_@localhost:7334"))
        );
        assert_eq!(fields.get("bot"), Some(&serde_json::json!(true)));
        assert_eq!(events.profile.kind, Kind::Metadata);
        assert!(events.profile.tags.is_empty());

        let relays: Vec<_> = nip65::extract_relay_list(&events.relay_list).collect();
        assert_eq!(events.relay_list.kind, Kind::RelayList);
        assert!(events.relay_list.content.is_empty());
        assert_eq!(relays.len(), 1);
        assert_eq!(relays[0].0.to_string(), "ws://localhost:7334");
        assert_eq!(relays[0].1, None, "an unmarked relay is read and write");
    }

    #[test]
    fn production_domain_defaults_to_secure_websocket_url() {
        assert_eq!(
            public_relay_url("relay.example.com").unwrap().to_string(),
            "wss://relay.example.com"
        );
    }

    #[test]
    fn loopback_authorities_use_plain_websocket_urls() {
        for domain in ["localhost:7334", "127.0.0.1:8080", "[::1]:7334", "::1"] {
            let url = public_relay_url(domain).unwrap().to_string();
            assert!(url.starts_with("ws://"), "{domain} -> {url}");
        }
    }

    #[test]
    fn publication_retries_only_transient_failures() {
        assert_eq!(
            publication_failure_disposition("duplicate: already stored"),
            PublicationFailureDisposition::AlreadyStored
        );
        assert_eq!(
            publication_failure_disposition("restricted: author is not admitted"),
            PublicationFailureDisposition::Terminal
        );
        assert_eq!(
            publication_failure_disposition("rate-limited: slow down"),
            PublicationFailureDisposition::Retry
        );
        assert_eq!(
            publication_failure_disposition("not connected"),
            PublicationFailureDisposition::Retry
        );
    }
}
