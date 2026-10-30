//! Kind-30640 private repo registration: shape validation, admission modes,
//! alias/key claims, and replay-safe application to the meta store.

use nostr::nips::nip19::ToBech32;
use nostr::prelude::Event;
use nostr_sdk::local_relay::WritePolicyResult;

use crate::config::RegistrationMode;
use crate::nostr::policy::{reject_error, reject_restricted};

use super::meta::RegistrationRecord;
use super::{quota, PrivateConfig, PrivateService};

/// Alias: exactly 32 lowercase hex chars.
pub(crate) fn is_valid_alias(alias: &str) -> bool {
    alias.len() == 32
        && alias
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

/// All values of every tag named `name` (tags may carry multiple values).
fn tag_values(event: &Event, name: &str) -> Vec<String> {
    event
        .tags
        .iter()
        .filter_map(|tag| {
            let v = tag.clone().to_vec();
            if v.len() >= 2 && v[0] == name {
                Some(v[1..].to_vec())
            } else {
                None
            }
        })
        .flatten()
        .collect()
}

/// Domain-separated message a claimed w/aux key must sign to prove
/// possession: sha256("grasp-p key-claim:<tenant-hex>:<alias>"). Binding the
/// signature to (tenant, alias) stops replaying one registration's proof into
/// another tenant's/alias's 30640.
pub fn key_pop_input(tenant_hex: &str, alias: &str) -> String {
    format!("grasp-p key-claim:{tenant_hex}:{alias}")
}

/// Verification-only secp256k1 context for proof-of-possession checks
/// (nostr 0.45.5 no longer exports its own global context).
static VERIFY_CTX: std::sync::LazyLock<secp256k1::Secp256k1<secp256k1::VerifyOnly>> =
    std::sync::LazyLock::new(secp256k1::Secp256k1::verification_only);

#[cfg(test)]
thread_local! {
    /// Proofs verified on this thread; tests read it to show that a step
    /// ran or did not.
    static PROOFS_VERIFIED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Verify the schnorr proof-of-possession `sig_hex` for `key_hex`.
fn verify_key_pop(
    key_hex: &str,
    sig_hex: &str,
    tenant_hex: &str,
    alias: &str,
) -> Result<(), String> {
    use std::str::FromStr;

    use bitcoin_hashes::sha256;
    use secp256k1::{schnorr::Signature, XOnlyPublicKey};

    #[cfg(test)]
    PROOFS_VERIFIED.with(|n| n.set(n.get() + 1));

    let pk = XOnlyPublicKey::from_str(key_hex)
        .map_err(|_| "w/aux key is not a valid x-only pubkey".to_string())?;
    let sig = Signature::from_str(sig_hex)
        .map_err(|_| "w/aux key proof-of-possession signature is malformed".to_string())?;
    let digest = sha256::Hash::hash(key_pop_input(tenant_hex, alias).as_bytes());
    VERIFY_CTX
        .verify_schnorr(&sig, &digest.to_byte_array(), &pk)
        .map_err(|_| "w/aux key proof-of-possession signature is invalid".to_string())
}

/// The claimed keys of every `name` tag, in tag order, each with the proof
/// its tag carries as a third value, if any. Nothing is judged here.
fn claimed_keys(event: &Event, name: &str) -> Vec<(String, Option<String>)> {
    event
        .tags
        .iter()
        .filter_map(|tag| {
            let v = tag.as_slice();
            if v.len() >= 2 && v[0] == name {
                Some((v[1].clone(), v.get(2).cloned()))
            } else {
                None
            }
        })
        .collect()
}

/// Verify every proof of possession a registration carries.
///
/// A claimed key must either BE the event author (the event signature is
/// the proof) or carry a schnorr signature over [`key_pop_input`]; without
/// that, any account could claim someone else's known write key, deny its
/// owner a registration and take over the attribution of its events.
/// [`parse_shape`] has already made sure a proof is present wherever one is
/// needed. This is the only costly step of handling a registration (one
/// signature check per key), which is why it runs after every check that
/// can refuse the registration more cheaply.
fn verify_proofs(parsed: &ParsedRegistration, tenant_hex: &str) -> Result<(), String> {
    for (key, proof) in &parsed.proofs {
        verify_key_pop(key, proof, tenant_hex, &parsed.alias)?;
    }
    Ok(())
}

fn first_tag_value(event: &Event, name: &str) -> Option<String> {
    event.tags.iter().find_map(|tag| {
        let v = tag.clone().to_vec();
        if v.len() >= 2 && v[0] == name {
            Some(v[1].clone())
        } else {
            None
        }
    })
}

/// Shape-validated registration fields.
struct ParsedRegistration {
    alias: String,
    w_keys: Vec<String>,
    aux_keys: Vec<String>,
    /// Every claimed key that is not the author's, with the proof of
    /// possession its tag carries: present, not yet verified.
    proofs: Vec<(String, String)>,
    relays: Vec<String>,
    servers: Vec<String>,
    quota_class: Option<String>,
}

/// Everything about a registration that can be judged from its text alone.
///
/// No signature is verified here, so a registration that is refused for its
/// shape costs the node next to nothing. The count of keys is checked before
/// the keys themselves for the same reason: the cap bounds every loop below
/// it, and the proof checks that follow in [`verify_proofs`].
fn parse_shape(event: &Event, cfg: &PrivateConfig) -> Result<ParsedRegistration, String> {
    let alias =
        first_tag_value(event, "d").ok_or_else(|| "registration must carry a d tag".to_string())?;
    if !is_valid_alias(&alias) {
        return Err("registration d tag must be exactly 32 lowercase hex chars".to_string());
    }

    let w_claims = claimed_keys(event, "w");
    let aux_claims = claimed_keys(event, "aux");
    if w_claims.is_empty() {
        return Err("registration must carry at least one w (write key) tag".to_string());
    }
    if w_claims.len() + aux_claims.len() > cfg.max_write_keys_per_alias as usize {
        return Err(format!(
            "registration exceeds the {} key limit",
            cfg.max_write_keys_per_alias
        ));
    }
    if w_claims
        .iter()
        .chain(aux_claims.iter())
        .any(|(key, _)| !super::blossom_auth::is_lower_hex_64(key))
    {
        return Err("w/aux keys must be 64 lowercase hex chars".to_string());
    }
    // Duplicate keys across w+aux would corrupt the claim index diffing.
    {
        let mut seen = std::collections::HashSet::new();
        for (key, _) in w_claims.iter().chain(aux_claims.iter()) {
            if !seen.insert(key) {
                return Err("registration lists the same key more than once".to_string());
            }
        }
    }
    // The author's own key needs no proof: the event signature is one.
    let tenant_hex = event.pubkey.to_hex();
    let mut proofs = Vec::new();
    for (key, proof) in w_claims.iter().chain(aux_claims.iter()) {
        if *key == tenant_hex {
            continue;
        }
        let proof = proof
            .as_ref()
            .ok_or_else(|| "w/aux keys must carry a proof-of-possession signature".to_string())?;
        proofs.push((key.clone(), proof.clone()));
    }

    let relays = tag_values(event, "relays");
    let servers = tag_values(event, "server");
    // The node has to find ITSELF among the values, by host and, when it is
    // served under a mount path, by that path too. Other values are not
    // judged: a registration for a pair names both nodes, and each of them
    // looks for its own name only. A plain substring match is not enough
    // ("wss://evil.com/x?example.com" and "example.com.attacker.tld" would
    // pass), and neither is the host alone under a mount path: a client that
    // was told the bare host would talk to whatever else is served there.
    if !relays
        .iter()
        .any(|v| super::host::url_denotes_service(v, &cfg.service_address))
    {
        return Err("registration relays tag must list this node".to_string());
    }
    if !servers
        .iter()
        .any(|v| super::host::url_denotes_service(v, &cfg.service_address))
    {
        return Err("registration server tag must list this node".to_string());
    }

    Ok(ParsedRegistration {
        alias,
        w_keys: w_claims.into_iter().map(|(key, _)| key).collect(),
        aux_keys: aux_claims.into_iter().map(|(key, _)| key).collect(),
        proofs,
        relays,
        servers,
        quota_class: first_tag_value(event, "quota-class"),
    })
}

/// May this event's author take a seat it does not hold yet?
///
/// This is the whole admission decision, as a function of the node's
/// configuration and the event alone, so that the two places that ask (the
/// early check outside the write lock and the check inside the write
/// transaction) cannot disagree, and so that a different source for the
/// list of admitted accounts replaces this one function. `None` admits; a
/// refusal carries the message the client is given.
fn new_seat_admission(cfg: &PrivateConfig, event: &Event) -> Option<WritePolicyResult> {
    match cfg.registration_mode {
        RegistrationMode::Open => None,
        RegistrationMode::Whitelist => {
            let npub = event.pubkey.to_bech32().unwrap_or_default();
            if cfg.tenant_whitelist.iter().any(|entry| entry == &npub) {
                None
            } else {
                Some(reject_restricted(
                    "tenant is not on the registration whitelist",
                ))
            }
        }
        RegistrationMode::Pow => {
            if event.id.check_pow(cfg.pow_bits) {
                None
            } else {
                Some(reject_restricted(format!(
                    "registration requires {} bits of NIP-13 proof of work",
                    cfg.pow_bits
                )))
            }
        }
        // Unreachable: Config::validate() rejects paid mode.
        RegistrationMode::Paid => {
            Some(reject_restricted("paid registration mode is not available"))
        }
    }
}

/// The admission decision for a registration, given what the meta store
/// holds for its alias.
///
/// The mode gates new seats only. An account that already holds the alias
/// passes whatever the mode says now, so an operator who tightens the mode,
/// or takes an account off the list, does not lock that account out of the
/// repositories it has. `stored` must come from the same transaction as the
/// decision that relies on this answer.
fn seat_admission(
    cfg: &PrivateConfig,
    event: &Event,
    stored: Option<&RegistrationRecord>,
) -> Option<WritePolicyResult> {
    if stored.is_some_and(|record| record.tenant_hex == event.pubkey.to_hex()) {
        return None;
    }
    new_seat_admission(cfg, event)
}

/// [`seat_admission`] against a read snapshot, before anything costly.
///
/// It takes no write lock, so a flood of registrations from accounts the
/// mode refuses neither queues behind writers nor makes the node verify
/// proofs. It only sheds load: the write transaction asks the same question
/// again and its answer is the one that counts, so a registration that
/// changes hands between the two reads is still judged correctly.
fn pre_admission(
    svc: &PrivateService,
    event: &Event,
    alias: &str,
) -> anyhow::Result<Option<WritePolicyResult>> {
    let txn = svc.meta.read_txn()?;
    let stored = svc.meta.get_registration(&txn, alias)?;
    Ok(seat_admission(&svc.cfg, event, stored.as_ref()))
}

/// Is `incoming` (created_at, id) strictly newer than the stored record per
/// nostr addressable-replacement semantics (equal created_at → lowest id wins)?
fn is_newer_than_stored(created_at: u64, event_id_hex: &str, stored: &RegistrationRecord) -> bool {
    created_at > stored.created_at
        || (created_at == stored.created_at && *event_id_hex < *stored.event_id)
}

/// §3.2 deterministic cross-node conflict merge (issue !11): between two
/// registrations claiming the same alias or overlapping keys, the one with
/// the LOWEST created_at wins (first-registrant-wins); ties break to the
/// lowest event id. Both operands are event-intrinsic (never node-local
/// state like arrival order or tombstones), so every node that has seen the
/// same pair of registrations resolves the same winner — that is what makes
/// partitioned nodes converge instead of permanently disagreeing about who
/// owns an alias/key set. A live decision also asks whether the holder's
/// seat has settled ([`challenge`]); this order alone cannot protect an
/// established seat, since the signer chooses `created_at`. Nodes that meet
/// a conflict only after a seat has settled on one of them no longer
/// converge.
fn incoming_wins_conflict(
    created_at: u64,
    event_id_hex: &str,
    stored: &RegistrationRecord,
) -> bool {
    // FA (verify round 1): compare against the seat's FIRST-edition anchor,
    // not the latest edition's (created_at, id) — same-tenant replacement
    // overwrites those fields with every rotation, which used to let the
    // seat's conflict priority decay until a squatter with an
    // intermediate-created_at registration started winning. For records
    // written before the anchor fields existed, `anchor()` falls back to the
    // latest edition, so the ordering itself (lowest created_at wins, ties to
    // the lowest event id) is exactly what it was.
    let (anchor_created_at, anchor_id) = stored.anchor();
    created_at < anchor_created_at.as_secs()
        || (created_at == anchor_created_at.as_secs() && *event_id_hex < *anchor_id)
}

/// How long a seat is open to the merge order, counted from the
/// `created_at` of its first edition. Past it the seat is settled: no other
/// account takes its alias or any of its keys, whatever date it puts on its
/// registration.
///
/// Whoever registers second can date its registration before the holder's,
/// so the merge order by itself lets any admitted account evict any
/// repository. Within the hour the order still decides, which is what lets
/// two nodes that saw a fresh conflict in different orders agree. A constant
/// and not a setting: both nodes of a pair must judge a seat settled at the
/// same moment.
pub(crate) const SEAT_SETTLE_SECS: u64 = 3600;

/// Whether `stored` has settled at `now`: its first edition is more than
/// [`SEAT_SETTLE_SECS`] older than `now`.
///
/// The age comes from the anchor, an event's own date, and not from when
/// this node first stored the seat, so two nodes that hold the same anchor
/// judge a seat settled at the same moment. A node rebuilt from its relay
/// database, or a peer that joined late, holds only each seat's newest
/// edition and anchors there, so a seat with an edition from the last hour
/// is young on that node only. A seat dated after `now` is young.
fn seat_is_settled(stored: &RegistrationRecord, now: u64) -> bool {
    now.saturating_sub(stored.anchor().0.as_secs()) > SEAT_SETTLE_SECS
}

/// How a registration fares against a seat another account holds, for the
/// alias or for one of its keys (a key also against another alias of the
/// same account).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Challenge {
    /// The registration takes the seat; the holder is evicted.
    Wins,
    /// The holder keeps the seat by the merge order.
    LosesByOrder,
    /// The merge order favours the registration, but the seat has settled
    /// and the holder keeps it. Only a registration dated before a first
    /// edition that is over an hour old gets here (or one on the same
    /// second with a lower id): a claim backdated against an established
    /// repository, or an older one that reaches this node late, such as
    /// after a partition, or a new edition of the sender's own seat that
    /// claims a key of a seat whose first edition is over an hour old (an older
    /// edition is judged by the order alone, see `apply`).
    LosesToSettledSeat,
}

/// Judge a registration dated (`created_at`, `event_id_hex`) against the
/// seat `stored`, which another account holds, or, for a key, another alias
/// of the same account.
///
/// `settle_clock` is the node's clock for a live decision and for a replay
/// against a seat the node held before the replay began, and `None` where
/// the order alone decides (see [`handle_replay`]). This is where the
/// node's clock enters a merge decision, on purpose: two nodes judging a
/// challenger that arrives within their delivery lag of the moment a seat
/// settles can disagree, one evicting the holder and the other refusing,
/// and both raise the conflict alert. Two nodes that saw the two
/// registrations in different orders can also disagree with no timing near
/// that moment: a seat dated more than an hour back is settled on arrival,
/// so a challenger that the other node saw first is kept there and refused
/// here.
fn challenge(
    created_at: u64,
    event_id_hex: &str,
    stored: &RegistrationRecord,
    settle_clock: Option<u64>,
) -> Challenge {
    if !incoming_wins_conflict(created_at, event_id_hex, stored) {
        Challenge::LosesByOrder
    } else if settle_clock.is_some_and(|now| seat_is_settled(stored, now)) {
        Challenge::LosesToSettledSeat
    } else {
        Challenge::Wins
    }
}

/// Result of applying a 30640: the admission verdict plus the relay-DB
/// 30640 coordinates (`(tenant_hex, alias)`) whose events must be pruned —
/// merge-evicted losers, and a conflict-losing incoming's own coordinate
/// when no live registration claims it (heals lingering pre-merge
/// split-brain leftovers). Async callers do the pruning (the meta txn
/// cannot — the relay DB is not covered by the meta lock).
pub(crate) struct RegistrationOutcome {
    pub result: WritePolicyResult,
    pub prune: Vec<(String, String)>,
}

/// Replay suppression window for conflict alerts (FG): covers boot
/// reconciles and sync redelivery bursts, while a loser event resurfacing
/// much later still earns one fresh alert.
pub(crate) const CONFLICT_ALERT_DEDUP_TTL: std::time::Duration =
    std::time::Duration::from_secs(3600);

/// The A2 replacement-cadence rejection message (FS-2). Shared constant so
/// the sync layer and the client write path can recognize THIS rejection —
/// and only this one — as hold-and-retry-able: a cadence-rejected same-
/// tenant replacement is held in the PrivateRejectedIndex and re-offered
/// after bucket refill instead of depending on the client to retry.
pub(crate) const REPLACE_CADENCE_REJECT_MESSAGE: &str = "replacement rate-limited; retry later";

/// FG (verify round 1): dedup for the `incoming_rejected` conflict alert,
/// keyed on the loser EVENT id (never the alias — a NEW conflict on the
/// same alias must still alert). Replays of an already-resolved loser event
/// (boot_reconcile on every restart, sync redelivery) used to re-increment
/// the counter forever, re-firing "alert on any increase" alerts long after
/// the conflict healed. Bounded + TTL'd in-memory only; the counter stays
/// monotonic and the first genuine firing always increments.
pub(crate) struct ConflictAlertDedup {
    seen: std::collections::HashMap<String, std::time::Instant>,
    ttl: std::time::Duration,
}

impl ConflictAlertDedup {
    /// Flood backstop; genuine conflicts are rare and the TTL keeps the map
    /// self-cleaning, so hitting this already means abuse.
    const MAX_ENTRIES: usize = 4096;

    pub(crate) fn new(ttl: std::time::Duration) -> Self {
        Self {
            seen: std::collections::HashMap::new(),
            ttl,
        }
    }

    /// True the first time `event_id_hex` is seen within the TTL (recording
    /// it); false for replays.
    pub(crate) fn should_alert(&mut self, event_id_hex: &str) -> bool {
        self.should_alert_at(event_id_hex, std::time::Instant::now())
    }

    fn should_alert_at(&mut self, event_id_hex: &str, now: std::time::Instant) -> bool {
        if let Some(at) = self.seen.get(event_id_hex) {
            if now.duration_since(*at) < self.ttl {
                return false;
            }
        }
        // Expire stale entries; conflicts are rare, so a full scan is cheap.
        let ttl = self.ttl;
        self.seen.retain(|_, at| now.duration_since(*at) < ttl);
        if self.seen.len() >= Self::MAX_ENTRIES {
            // Evict the OLDEST entry (never the new one): a fresh conflict
            // must still alert.
            if let Some(oldest) = self
                .seen
                .iter()
                .max_by_key(|(_, at)| now.duration_since(**at))
                .map(|(k, _)| k.clone())
            {
                self.seen.remove(&oldest);
            }
        }
        self.seen.insert(event_id_hex.to_string(), now);
        true
    }
}

/// What the meta txn decided. `evicted` is non-empty only on accept —
/// rejection paths never mutate, so a rejected event cannot evict anyone.
struct TxnOutcome {
    rejection: Option<WritePolicyResult>,
    evicted: Vec<(String, String)>,
    /// The rejection above was a lost §3.2 conflict (fires the alert).
    incoming_conflict_loss: bool,
    /// That conflict was lost to a settled seat ([`Challenge::LosesToSettledSeat`]):
    /// by the merge order alone the incoming registration would have won.
    /// The warning carries it, so an operator can tell a refusal by the
    /// seat's age, never an ordinary merge, from a loss by the order.
    incumbent_settled: bool,
    /// The conflict-losing incoming's own coordinate holds no live
    /// registration, so any lingering relay-DB events there are stale and
    /// safe to prune. NEVER set when the loser tenant still holds a live
    /// registration at that coordinate (a stale edition losing a key
    /// conflict must not take down its own genuine coordinate).
    prune_incoming: bool,
}

impl TxnOutcome {
    fn accept(evicted: Vec<(String, String)>) -> Self {
        Self {
            rejection: None,
            evicted,
            incoming_conflict_loss: false,
            incumbent_settled: false,
            prune_incoming: false,
        }
    }

    fn reject(rejection: WritePolicyResult) -> Self {
        Self {
            rejection: Some(rejection),
            evicted: Vec::new(),
            incoming_conflict_loss: false,
            incumbent_settled: false,
            prune_incoming: false,
        }
    }

    fn conflict_reject(
        rejection: WritePolicyResult,
        prune_incoming: bool,
        lost: Challenge,
    ) -> Self {
        Self {
            rejection: Some(rejection),
            evicted: Vec::new(),
            incoming_conflict_loss: true,
            incumbent_settled: lost == Challenge::LosesToSettledSeat,
            prune_incoming,
        }
    }
}

/// Handle a kind-30640 registration event (admission + meta application).
///
/// Live admission: the Phase-4b A2 same-tenant replacement-cadence bucket
/// applies (client-submitted AND synced events — the knob is part of the
/// policy fingerprint, so both paths must behave identically).
pub(crate) fn handle(svc: &PrivateService, event: &Event) -> RegistrationOutcome {
    let now = nostr::prelude::Timestamp::now().as_secs();
    handle_inner(svc, event, Admission::Live { now })
}

/// Re-admission of an event this node already holds (boot_reconcile).
/// Differs from [`handle`] in three ways. The A2 replacement-cadence bucket
/// is not consulted: replays must not consume replacement budget. The
/// admission mode is asked where it always was, after the conflict checks:
/// a stored registration that lost a conflict is then still recognised as
/// the loser and pruned, even when its author is no longer admitted. The
/// early position exists to shed load from senders the mode refuses, and
/// the events replayed here are the node's own. And a seat counts as settled
/// only when this node held it before the replay began
/// (`reconcile_started`, the node's clock when `boot_reconcile` started):
/// a seat the replay itself creates is judged by the merge order alone.
///
/// A replay has to reach the decisions the node already made. The node
/// writes its meta record before it stores the event, and a refused event
/// is never stored, so a stored registration the meta store does not hold
/// (a leftover) is a holder the node evicted, whose prune failed or never
/// ran. Against a seat the meta store already held, the clock decides as it
/// would live: the order refuses a leftover dated after that seat, and a
/// settled seat that another account took after the eviction refuses an
/// older one, which the order alone would let evict it on this node only.
/// Such a refusal by age prunes nothing, since a meta store restored from an
/// older copy than the relay database could otherwise delete the only copy
/// of a registration the node accepted. A seat the replay creates is a meta
/// store being rebuilt from the relay database, newest first; judged by the
/// clock, it would seat the evicted holder first, settled at once by its
/// old date, and then refuse the winner, the opposite of what this node
/// decided and of what its peer holds, so the order alone decides there.
/// What the rule still gets wrong is listed in SEAMS.md, "A settled seat is
/// not displaced".
pub(crate) fn handle_replay(
    svc: &PrivateService,
    event: &Event,
    reconcile_started: u64,
) -> RegistrationOutcome {
    handle_inner(svc, event, Admission::Replay { reconcile_started })
}

/// Where a 30640 comes from: a client or a peer (live), or this node's own
/// relay database at start-up (replay). `now` is the node's time, which
/// says whether a seat has settled; `reconcile_started` is the node's time
/// when the replay began.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admission {
    Live { now: u64 },
    Replay { reconcile_started: u64 },
}

impl Admission {
    /// The clock a conflict with `holder` is judged by: the node's for a
    /// live registration; for a replay, the replay's start when this node
    /// held the seat before the replay began, and none for a seat the
    /// replay created (see [`handle_replay`]). `registered_at` is when this
    /// node first stored the seat and is kept across its editions.
    fn settle_clock(self, holder: &RegistrationRecord) -> Option<u64> {
        match self {
            Admission::Live { now } => Some(now),
            Admission::Replay { reconcile_started } => {
                (holder.registered_at < reconcile_started).then_some(reconcile_started)
            }
        }
    }
}

/// A refusal that changed nothing and leaves nothing to prune.
fn refused(result: WritePolicyResult) -> RegistrationOutcome {
    RegistrationOutcome {
        result,
        prune: Vec::new(),
    }
}

/// Handle a kind-30640 registration event (admission + meta application).
///
/// The checks run from the cheapest to the most costly, so that a
/// registration the node will refuse anyway costs it as little as possible:
/// date and size, then the shape, then whether this sender may register at
/// all, and only then the proofs of possession (one signature check per
/// key). The write transaction in [`apply`] comes last and is the authority
/// on everything that depends on stored state.
fn handle_inner(svc: &PrivateService, event: &Event, admission: Admission) -> RegistrationOutcome {
    let cfg = &svc.cfg;

    if let Some(rejection) = super::check_not_future_dated(event) {
        return refused(rejection);
    }

    // Size cap on serialized JSON.
    if event.as_json().len() as u64 > cfg.max_event_bytes {
        return refused(reject_restricted(super::admission::OVERSIZE_REJECT_MESSAGE));
    }

    let parsed = match parse_shape(event, cfg) {
        Ok(p) => p,
        Err(reason) => return refused(crate::nostr::policy::reject_invalid(reason)),
    };

    if matches!(admission, Admission::Live { .. }) {
        match pre_admission(svc, event, &parsed.alias) {
            Ok(None) => {}
            Ok(Some(rejection)) => return refused(rejection),
            Err(e) => {
                tracing::warn!("private registration admission read failed: {e}");
                return refused(reject_error("private meta store failure"));
            }
        }
    }

    if let Err(reason) = verify_proofs(&parsed, &event.pubkey.to_hex()) {
        return refused(crate::nostr::policy::reject_invalid(reason));
    }

    apply(svc, event, &parsed, admission)
}

/// The write transaction of a registration, and what follows from its
/// verdict (alerts, counters, the coordinates to prune).
///
/// The caller has checked the shape and the proofs. Every check that reads
/// stored state is made here, inside the transaction that acts on it.
fn apply(
    svc: &PrivateService,
    event: &Event,
    parsed: &ParsedRegistration,
    admission: Admission,
) -> RegistrationOutcome {
    let cfg = &svc.cfg;
    let tenant_hex = event.pubkey.to_hex();
    let event_id_hex = event.id.to_hex();
    let created_at = event.created_at.as_secs();
    let event_bytes = event.as_json().len() as u64;
    // A live registration is asked for admission before anything else; a
    // replayed one where it always was (see `handle_replay`).
    let admission_first = matches!(admission, Admission::Live { .. });

    let result = svc.meta.with_write(|meta, txn| {
        let stored = meta.get_registration(txn, &parsed.alias)?;
        // A same-tenant edition no newer than the stored one changes no
        // claim: the stale-edition path below accepts it as a no-op and
        // drops `evict`. A settled seat has nothing to lose to it, so it is
        // judged by the order alone, as before seats settled, instead of
        // being refused with a settled-seat warning that names its own
        // author; and it still lowers the anchor when it is older evidence.
        let judged_by_age = !matches!(
            &stored,
            Some(r) if r.tenant_hex == tenant_hex
                && !is_newer_than_stored(created_at, &event_id_hex, r)
        );
        let settle_clock = |holder: &RegistrationRecord| {
            if !judged_by_age {
                None
            } else if admission_first && cfg.write_blacklist.contains(&holder.tenant_hex) {
                // Decision D9: a listed account's seat is settled whatever
                // its age, so no registration displaces it, on either node:
                // its keys stay frozen, and what it stored stays claimed and
                // readable. A replay is judged as before, so it seats again
                // what this node held before the list.
                Some(u64::MAX)
            } else {
                admission.settle_clock(holder)
            }
        };
        // A replay's refusal by a seat's age deletes nothing. The meta store
        // it judges by can be older than the relay database (a restore that
        // was not taken from one snapshot), and the stored event may then be
        // the only copy of a registration this node accepted; kept, it is
        // seated again by a rebuild of the meta store.
        let may_prune_loser = |verdict: Challenge| {
            !(verdict == Challenge::LosesToSettledSeat
                && matches!(admission, Admission::Replay { .. }))
        };

        // ---- Decision phase: NO mutations until every check has passed.
        // with_write COMMITS on Ok (including Ok-with-rejection), so any
        // mutation made before a later reject-path would silently land.

        // Admission, first, for every sender that does not already hold
        // this alias. The read above and this decision share the write
        // transaction, so the answer cannot be stale; the check before the
        // proofs asked the same function and only saved work. A sender the
        // mode refuses stops here: it takes part in no conflict, so it
        // raises no conflict alert and gets nothing pruned.
        let refused_at_the_door = if admission_first {
            seat_admission(cfg, event, stored.as_ref())
        } else {
            None
        };
        if let Some(rejection) = refused_at_the_door {
            return Ok(TxnOutcome::reject(rejection));
        }

        // Decision D9: no new registration by a key that a listed account's
        // registration lists. Upstream has already refused what a listed key
        // signs itself. A replay does not ask, so a registration this node
        // took before the list is seated again.
        if admission_first {
            if let Some(holder_alias) = meta.get_key_claim(txn, &tenant_hex)? {
                if let Some(holder) = meta.get_registration(txn, &holder_alias)? {
                    if let Some(reason) = svc.write_blocked(&tenant_hex, &holder.tenant_hex) {
                        return Ok(TxnOutcome::reject(super::blacklist::reject_blocked(reason)));
                    }
                }
            }
        }

        // §3.2 alias conflict: the alias is held by a DIFFERENT tenant.
        // Resolved by the deterministic merge (issue !11), never by arrival
        // order: the (created_at, id) winner takes the alias on every node,
        // the loser is evicted (claims freed, record dropped, relay-DB
        // coordinate pruned by the caller) with a conflict alert. A settled
        // seat is never the loser (`challenge`).
        let mut evict: Vec<(String, RegistrationRecord)> = Vec::new();
        let mut alias_takeover = false;
        if let Some(ref record) = stored {
            if record.tenant_hex != tenant_hex {
                let verdict = challenge(created_at, &event_id_hex, record, settle_clock(record));
                if verdict == Challenge::Wins {
                    evict.push((parsed.alias.clone(), record.clone()));
                    alias_takeover = true;
                } else {
                    // The alias's live record belongs to the holder, so the
                    // loser's own coordinate holds nothing live → prunable.
                    return Ok(TxnOutcome::conflict_reject(
                        reject_restricted("alias already registered"),
                        may_prune_loser(verdict),
                        verdict,
                    ));
                }
            }
        }

        // Key conflicts: any claimed key held by a DIFFERENT alias — the
        // same deterministic merge, against each holder's registration, and
        // the same protection for a settled holder. Every member of a
        // repository holds its shared aux key, so without it any member
        // could evict the whole repository from an alias of its own.
        for key in parsed.w_keys.iter().chain(parsed.aux_keys.iter()) {
            if let Some(holder) = meta.get_key_claim(txn, key)? {
                if evict.iter().any(|(alias, _)| *alias == holder) {
                    continue; // holder already losing this merge
                }
                if holder == parsed.alias {
                    continue; // held by this alias (same-tenant replacement)
                }
                let Some(holder_record) = meta.get_registration(txn, &holder)? else {
                    // Dangling claim row without a backing registration
                    // (should not happen — claims are diffed atomically):
                    // stale, the incoming registration may take the key.
                    continue;
                };
                let verdict = challenge(
                    created_at,
                    &event_id_hex,
                    &holder_record,
                    settle_clock(&holder_record),
                );
                if verdict == Challenge::Wins {
                    evict.push((holder, holder_record));
                } else {
                    // Prunable only when the incoming's own coordinate has no
                    // live same-tenant registration: a stale edition losing a
                    // key conflict must not take down its genuine coordinate.
                    let prune_incoming = !stored
                        .as_ref()
                        .map(|r| r.tenant_hex == tenant_hex)
                        .unwrap_or(false);
                    return Ok(TxnOutcome::conflict_reject(
                        reject_restricted("write key already registered"),
                        prune_incoming && may_prune_loser(verdict),
                        verdict,
                    ));
                }
            }
        }

        // A conflict-merge alias takeover is a NEW claim by this tenant:
        // admission gates and the alias limit apply exactly as for a fresh
        // alias (both nodes of a pair share admission config — policy
        // fingerprint parity — so the gates cannot diverge the merge).
        let is_new_alias = stored.is_none() || alias_takeover;
        if is_new_alias {
            // Admission mode gates NEW aliases only. A live registration
            // was asked at the top of this transaction.
            let refused_as_new = if admission_first {
                None
            } else {
                new_seat_admission(cfg, event)
            };
            if let Some(rejection) = refused_as_new {
                return Ok(TxnOutcome::reject(rejection));
            }

            // FB (verify round 1): a conflict-merge WINNER is exempt from
            // the alias-limit check (never from the accounting — the alias
            // is still recorded in `tenant_aliases` below). Occupancy is
            // node-local state, exactly like the quota ledger exempted
            // further down: if the winner's tenant is at the limit on this
            // node but not on a peer, the check would flip the deterministic
            // merge here and permanently split-brain the alias. Fresh
            // non-conflict registrations KEEP the limit (anti-sybil, !7).
            if evict.is_empty() {
                let aliases = meta.get_tenant_aliases(txn, &tenant_hex)?;
                if aliases.len() >= cfg.max_aliases_per_tenant as usize {
                    return Ok(TxnOutcome::reject(reject_restricted(
                        "tenant has reached the alias limit",
                    )));
                }
            }
        }

        // Replay/replacement ordering (§4b): apply meta changes only when the
        // event is strictly newer than the stored record; the relay DB will
        // discard older editions itself. Same-tenant only — a cross-tenant
        // merge winner is by definition OLDER than the stored record.
        if let Some(ref record) = stored {
            if record.tenant_hex == tenant_hex
                && !is_newer_than_stored(created_at, &event_id_hex, record)
            {
                // R2-B (verify round 2): authentic OLDER same-tenant evidence
                // LOWERS the conflict anchor. The anchor is first-WITNESSED —
                // a late-joining or rebuilt node that only ever synced a
                // later edition anchors there and would let an
                // intermediate-created_at squatter win; when genuine earlier
                // evidence arrives (only the tenant can mint its own
                // editions, so this cannot be forged), adopting it is safe,
                // monotone, and idempotent (the same event never beats
                // itself), and repairs pre-fix `None` anchors for free. The
                // anchor may reference an event the local relay DB later
                // discards via addressable replacement — benign: it is pure
                // comparison data, never served. Everything else stays
                // accept-no-op (no charge/ledger changes).
                if incoming_wins_conflict(created_at, &event_id_hex, record) {
                    let mut repaired = record.clone();
                    repaired.first_created_at =
                        Some(nostr::prelude::Timestamp::from_secs(created_at));
                    repaired.first_event_id = Some(event_id_hex.clone());
                    meta.put_registration(txn, &parsed.alias, &repaired)?;
                }
                return Ok(TxnOutcome::accept(Vec::new())); // no other meta changes
            }
        }

        // Quota: registrations are small but still counted. A conflict-merge
        // WINNER is exempt from the check (never the charge): the ledger is
        // node-local state — a squatter who pre-filled the shared r:<alias>
        // (or global) scope on one node could otherwise get the genuine
        // earlier registration rejected there while it wins elsewhere,
        // resurrecting the very split-brain the deterministic merge exists
        // to prevent. Overshoot is bounded by one ≤max_event_bytes event per
        // conflict, and every conflict already fires the operator alert.
        if evict.is_empty()
            && !quota::check(meta, txn, cfg, &tenant_hex, &parsed.alias, event_bytes)?
        {
            return Ok(TxnOutcome::reject(reject_restricted("quota exceeded")));
        }

        // Phase-4b A2: 30640 replacement-cadence limit — SAME-TENANT NEWER
        // replacements only (exactly the branch that survives to here with
        // `stored` belonging to this tenant; every other admission is
        // exempt by construction):
        // - new aliases (`is_new_alias`) — the bucket is keyed
        //   (tenant, alias), and fresh seats are bounded by the alias limit;
        // - cross-tenant conflict-merge losers — they returned above;
        // - conflict-merge WINNERS (`evict` non-empty): an alias takeover
        //   has a different-tenant `stored` and never reaches here, but a
        //   same-tenant newer replacement that WINS A KEY CONFLICT against
        //   another tenant's alias DOES reach here with a non-empty evict
        //   list — and it is exempt for the same reason the quota and
        //   alias-limit gates above are (§3.2 hard invariant): the bucket is
        //   node-local state, and node-local state must NEVER gate the
        //   deterministic merge (the node's clock in `challenge` is the one
        //   deliberate exception). A cadence-rejected key-conflict winner
        //   evicts the loser on nodes that admit it while leaving the loser
        //   live on nodes that reject it — permanent split-brain once a
        //   newer edition supersedes the winner everywhere (the loser can
        //   no longer be re-evicted). Only the tenant can mint same-tenant
        //   replacements, so the exemption cannot be abused to evict
        //   others: the merge decides those.
        // - stale same-tenant editions — the accept-no-op anchor-repair
        //   path returned above;
        // - boot_reconcile replays (Admission::Replay) — already-admitted
        //   events must not consume budget.
        // A rejected replacement is HELD (FS-2: PrivateRejectedIndex) and
        // retried by the sync layer after bucket refill, with the hourly
        // re-issue as backstop; the knob values are part of the
        // policy_fingerprint preimage (since v2) so paired nodes run identical
        // cadence config. Bucket state itself is node-local, so a transient
        // divergence after a flood is possible — it heals on refill +
        // redelivery, unless the retried edition meets, on this node only, a
        // claim that has settled meanwhile (SEAT_SETTLE_SECS): that split
        // stays.
        let is_same_tenant_replacement = stored
            .as_ref()
            .map(|r| r.tenant_hex == tenant_hex)
            .unwrap_or(false);
        if is_same_tenant_replacement
            && matches!(admission, Admission::Live { .. })
            && evict.is_empty()
            && !svc.registration_replace_allowed(&tenant_hex, &parsed.alias)
        {
            return Ok(TxnOutcome::reject(reject_restricted(
                REPLACE_CADENCE_REJECT_MESSAGE,
            )));
        }

        // ---- Mutation phase: every check has passed, apply atomically.

        // Evict the conflict losers: free their key claims and drop their
        // records + alias slots (same discipline as an author-valid kind-5
        // deletion — `free_registration_claims` also drops the loser's blob
        // references (its charges go, but for stored bytes it was the last
        // to reference, which it pays until GC), resets the alias's
        // event-bytes column, and deletes its state-ring editions, all in
        // this txn).
        let mut evicted: Vec<(String, String)> = Vec::new();
        for (loser_alias, loser) in &evict {
            super::free_registration_claims(meta, txn, &loser.tenant_hex, loser_alias, u64::MAX)?;
            evicted.push((loser.tenant_hex.clone(), loser_alias.clone()));
        }

        // Diff key sets against the previous edition (same-tenant
        // replacement only — an evicted holder's claims are already gone).
        let (old_w, old_aux) = match (&stored, alias_takeover) {
            (Some(r), false) => (r.w_keys.clone(), r.aux_keys.clone()),
            _ => Default::default(),
        };
        let new_keys: std::collections::HashSet<&String> =
            parsed.w_keys.iter().chain(parsed.aux_keys.iter()).collect();
        for old_key in old_w.iter().chain(old_aux.iter()) {
            if !new_keys.contains(old_key) {
                meta.delete_key_claim(txn, old_key)?;
            }
        }
        for key in parsed.w_keys.iter().chain(parsed.aux_keys.iter()) {
            meta.put_key_claim(txn, key, &parsed.alias)?;
        }

        // FA: resolve the §3.2 conflict anchor for the record being written.
        // A same-tenant replacement PRESERVES the existing anchor (mirroring
        // the `registered_at` preservation below); a pre-fix record (`None`)
        // adopts the OLD latest edition as its anchor just before those
        // fields are overwritten. A new registration — including a
        // cross-tenant takeover winner — anchors on the winning event itself.
        //
        // R2-B irreducible residual: the anchor is first-WITNESSED, so when
        // the earliest edition has been purged from EVERY relay DB by
        // addressable replacement, a late-joining/rebuilt node anchors on
        // the earliest edition it does see and can stay permanently
        // mis-anchored (an intermediate-created_at squatter wins there).
        // The stale-edition path above lowers the anchor whenever authentic
        // earlier evidence survives somewhere; when none survives, the
        // victim's self-heal is to re-mint a registration with created_at ≤
        // the squatter's — a same-tenant no-op on correctly-witnessed nodes
        // (lowering their anchors if it is older evidence), a cross-tenant
        // winner on mis-anchored ones while the squatter's seat there is
        // under SEAT_SETTLE_SECS old; a settled squat is not displaced by
        // the re-mint either. Inherent to §3.2's created_at anchor choice,
        // not a bug this layer can fix.
        let (first_created_at, first_event_id) = match (&stored, alias_takeover) {
            (Some(r), false) => {
                let (anchor_created_at, anchor_id) = r.anchor();
                (Some(anchor_created_at), Some(anchor_id.to_string()))
            }
            _ => (
                Some(nostr::prelude::Timestamp::from_secs(created_at)),
                Some(event_id_hex.clone()),
            ),
        };

        let record = RegistrationRecord {
            tenant_hex: tenant_hex.clone(),
            event_id: event_id_hex.clone(),
            created_at,
            w_keys: parsed.w_keys.clone(),
            aux_keys: parsed.aux_keys.clone(),
            relays: parsed.relays.clone(),
            servers: parsed.servers.clone(),
            quota_class: parsed.quota_class.clone(),
            registered_at: match (&stored, alias_takeover) {
                (Some(r), false) => r.registered_at,
                // A seat a replay creates is never dated before the replay,
                // even if the clock stepped back meanwhile: it must stay a
                // seat the replay created (`Admission::settle_clock`).
                _ => match admission {
                    Admission::Replay { reconcile_started } => nostr::prelude::Timestamp::now()
                        .as_secs()
                        .max(reconcile_started),
                    Admission::Live { .. } => nostr::prelude::Timestamp::now().as_secs(),
                },
            },
            tombstoned_at: None,
            first_created_at,
            first_event_id,
        };
        meta.put_registration(txn, &parsed.alias, &record)?;

        if is_new_alias {
            let mut aliases = meta.get_tenant_aliases(txn, &tenant_hex)?;
            if !aliases.contains(&parsed.alias) {
                aliases.push(parsed.alias.clone());
                meta.put_tenant_aliases(txn, &tenant_hex, &aliases)?;
            }
        }

        quota::charge(meta, txn, &tenant_hex, &parsed.alias, event_bytes, false)?;
        Ok(TxnOutcome::accept(evicted))
    });

    match result {
        Ok(outcome) => {
            if let Some(rejection) = outcome.rejection {
                let mut prune = Vec::new();
                if outcome.incoming_conflict_loss {
                    // FG: alert once per loser EVENT id — boot_reconcile and
                    // sync redelivery replay resolved losers; re-firing the
                    // "alert on any increase" counter on every replay
                    // re-alerts forever. A NEW conflict on the same alias is
                    // a different event id and still alerts.
                    if svc.conflict_alert_dedup.lock().should_alert(&event_id_hex) {
                        crate::metrics::record_private_registration_conflict("incoming_rejected");
                    }
                    tracing::warn!(
                        alias = %parsed.alias,
                        loser_tenant = %tenant_hex,
                        loser_created_at = created_at,
                        loser_event_id = %event_id_hex,
                        incumbent_settled = outcome.incumbent_settled,
                        "private registration conflict: incoming registration lost the \
                         deterministic merge (§3.2) and was rejected"
                    );
                    if outcome.prune_incoming {
                        prune.push((tenant_hex.clone(), parsed.alias.clone()));
                    }
                }
                return RegistrationOutcome {
                    result: rejection,
                    prune,
                };
            }
            for (loser_tenant, loser_alias) in &outcome.evicted {
                crate::metrics::record_private_registration_conflict("stored_evicted");
                tracing::warn!(
                    alias = %loser_alias,
                    loser_tenant = %loser_tenant,
                    winner_tenant = %tenant_hex,
                    winner_created_at = created_at,
                    winner_event_id = %event_id_hex,
                    "private registration conflict: stored registration evicted by the \
                     deterministic merge (§3.2); key claims freed"
                );
            }
            crate::metrics::record_private_registration(&cfg.registration_mode.to_string());
            svc.refresh_gauges();
            RegistrationOutcome {
                result: WritePolicyResult::Accept,
                prune: outcome.evicted,
            }
        }
        Err(e) => {
            tracing::warn!("private registration meta update failed: {e}");
            refused(reject_error("private meta store failure"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(created_at: u64, event_id: &str) -> RegistrationRecord {
        RegistrationRecord {
            tenant_hex: "t".to_string(),
            event_id: event_id.to_string(),
            created_at,
            w_keys: vec![],
            aux_keys: vec![],
            relays: vec![],
            servers: vec![],
            quota_class: None,
            registered_at: 0,
            tombstoned_at: None,
            first_created_at: None,
            first_event_id: None,
        }
    }

    /// §3.2 merge comparator: lowest created_at wins; ties break to the
    /// lowest event id; an incoming that is not strictly lower loses. The
    /// comparator must be a strict total order over distinct events so every
    /// node picks the same winner from the same pair.
    #[test]
    fn conflict_merge_orders_by_created_at_then_id() {
        // Lower created_at wins regardless of id ordering.
        assert!(incoming_wins_conflict(100, "ff", &record(200, "00")));
        // Higher created_at loses.
        assert!(!incoming_wins_conflict(200, "00", &record(100, "ff")));
        // Tie: lower id wins…
        assert!(incoming_wins_conflict(100, "0a", &record(100, "0b")));
        // …and higher id loses.
        assert!(!incoming_wins_conflict(100, "0b", &record(100, "0a")));
        // Identical (created_at, id) — same event — never "wins" a conflict.
        assert!(!incoming_wins_conflict(100, "0a", &record(100, "0a")));
    }

    /// Same-tenant replacement ordering is the OPPOSITE comparison (newest
    /// wins) — pin both so a refactor cannot swap them.
    #[test]
    fn replacement_and_conflict_orderings_are_duals() {
        let stored = record(100, "aa");
        // A strictly newer edition replaces; an older one wins conflicts.
        assert!(is_newer_than_stored(101, "aa", &stored));
        assert!(!incoming_wins_conflict(101, "aa", &stored));
        assert!(!is_newer_than_stored(99, "aa", &stored));
        assert!(incoming_wins_conflict(99, "aa", &stored));
    }

    /// FA: `anchor()` prefers the recorded first edition and falls back to
    /// the latest edition for records written before the anchor fields
    /// existed.
    #[test]
    fn anchor_prefers_first_edition_and_falls_back() {
        let mut r = record(2000, "bb");
        assert_eq!(
            r.anchor(),
            (nostr::prelude::Timestamp::from_secs(2000), "bb"),
            "pre-fix record: anchor falls back to the latest edition"
        );
        r.first_created_at = Some(nostr::prelude::Timestamp::from_secs(1000));
        r.first_event_id = Some("aa".to_string());
        assert_eq!(
            r.anchor(),
            (nostr::prelude::Timestamp::from_secs(1000), "aa")
        );
    }

    /// FA: the conflict comparator runs against the FIRST-edition anchor, so
    /// a squatter whose created_at sits between edition 1 and a later
    /// rotation keeps LOSING after the rotation (pre-FA it started winning
    /// once `created_at` was overwritten). Same-tenant replacement ordering
    /// stays latest-edition (the two are duals only for anchorless records,
    /// pinned above).
    #[test]
    fn conflict_comparator_uses_first_edition_anchor() {
        let mut stored = record(2000, "bb");
        stored.first_created_at = Some(nostr::prelude::Timestamp::from_secs(1000));
        stored.first_event_id = Some("aa".to_string());
        // Squatter at t=1500: newer than the anchor, older than the latest
        // edition — must lose.
        assert!(!incoming_wins_conflict(1500, "cc", &stored));
        // A genuinely earlier registration still wins.
        assert!(incoming_wins_conflict(500, "zz", &stored));
        // Tie at the anchor: lowest id wins.
        assert!(incoming_wins_conflict(1000, "00", &stored));
        assert!(!incoming_wins_conflict(1000, "ff", &stored));
        // Replacement ordering is untouched: strictly newer than the LATEST
        // edition replaces; older does not.
        assert!(is_newer_than_stored(2001, "cc", &stored));
        assert!(!is_newer_than_stored(1500, "cc", &stored));
    }

    /// D8: a seat settles once its first edition is more than
    /// `SEAT_SETTLE_SECS` older than the clock: not at an hour exactly, at
    /// the next second. The age is the first edition's, so a newer edition
    /// does not make an old seat young again, and a seat dated after the
    /// clock is young.
    #[test]
    fn seat_settles_one_second_after_an_hour() {
        assert_eq!(SEAT_SETTLE_SECS, 3600);
        let mut seat = record(10_000, "bb");
        assert!(!seat_is_settled(&seat, 10_000));
        assert!(!seat_is_settled(&seat, 10_000 + SEAT_SETTLE_SECS - 1));
        assert!(
            !seat_is_settled(&seat, 10_000 + SEAT_SETTLE_SECS),
            "an hour old exactly is still young"
        );
        assert!(seat_is_settled(&seat, 10_000 + SEAT_SETTLE_SECS + 1));
        assert!(
            !seat_is_settled(&seat, 9_000),
            "a seat dated after the clock is young"
        );

        seat.first_created_at = Some(nostr::prelude::Timestamp::from_secs(1_000));
        seat.first_event_id = Some("aa".to_string());
        assert!(!seat_is_settled(&seat, 1_000 + SEAT_SETTLE_SECS));
        assert!(
            seat_is_settled(&seat, 1_000 + SEAT_SETTLE_SECS + 1),
            "the first edition's age counts, not the latest's"
        );
    }

    /// D8: the settle rule only ever turns a win into a refusal. A
    /// registration the merge order refuses is refused by the order,
    /// settled seat or not, so its warning does not blame the settle rule;
    /// and without a clock (a replay of a seat the replay created) the
    /// order alone decides, however old the seat.
    #[test]
    fn a_settled_seat_turns_only_a_win_into_a_refusal() {
        let seat = record(10_000, "bb");
        let young = Some(10_000 + SEAT_SETTLE_SECS);
        let settled = Some(10_000 + SEAT_SETTLE_SECS + 1);

        // Dated before the seat, or on its second with a lower id.
        for (created_at, id) in [(9_000, "ff"), (1, "ff"), (10_000, "aa")] {
            assert_eq!(challenge(created_at, id, &seat, young), Challenge::Wins);
            assert_eq!(
                challenge(created_at, id, &seat, settled),
                Challenge::LosesToSettledSeat
            );
            assert_eq!(challenge(created_at, id, &seat, None), Challenge::Wins);
        }
        // Dated after the seat, or on its second with a higher id.
        for (created_at, id) in [(11_000, "00"), (10_000, "cc")] {
            for clock in [young, settled, None] {
                assert_eq!(
                    challenge(created_at, id, &seat, clock),
                    Challenge::LosesByOrder
                );
            }
        }
    }

    // ------------------------------------------------------------------
    // Meta-level harness: drive `handle()` against a real meta store with an
    // empty in-memory relay DB (registration admission never queries it).
    // ------------------------------------------------------------------

    struct Harness {
        _dir: tempfile::TempDir,
        svc: std::sync::Arc<PrivateService>,
    }

    async fn harness() -> Harness {
        harness_with(|_| {}).await
    }

    /// The harness with settings of the caller's choosing on top of the
    /// test defaults (open mode, a node at the root of `localhost:7334`).
    async fn harness_with(configure: impl FnOnce(&mut crate::config::Config)) -> Harness {
        let database: crate::nostr::SharedDatabase =
            std::sync::Arc::new(nostr_memory::MemoryDatabase::unbounded());
        harness_on(database, configure).await
    }

    /// The harness over a relay database the caller already filled, with an
    /// empty meta store of its own: a node whose meta store is rebuilt from
    /// that database at start-up, as after a wipe.
    async fn harness_on(
        database: crate::nostr::SharedDatabase,
        configure: impl FnOnce(&mut crate::config::Config),
    ) -> Harness {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = crate::config::Config::for_testing();
        config.private_repos_enable = true;
        config.private_meta_data_path =
            Some(dir.path().join("meta").to_string_lossy().into_owned());
        config.private_blob_data_path =
            Some(dir.path().join("blobs").to_string_lossy().into_owned());
        configure(&mut config);
        let svc = PrivateService::new(&config, database)
            .await
            .expect("private service");
        Harness { _dir: dir, svc }
    }

    /// A clock under an hour after every 1970 date that the tests of this
    /// module older than the settle rule give a seat. Those tests decide
    /// their conflicts at this clock, so their seats are young and the merge
    /// order alone decides, as before seats settled. Decided at the real
    /// clock those seats are decades old: a challenger a test expects to win
    /// would be refused, and one it expects to lose would lose to the settle
    /// rule whatever the order said, so the test would no longer catch a
    /// fault in the order.
    const WHILE_YOUNG: u64 = 4_000;

    /// A replay that began before this node stored any seat, as when a
    /// meta store is rebuilt from the relay database: every seat is the
    /// replay's own, so the merge order alone decides.
    const BEFORE_EVERY_SEAT: u64 = 0;

    /// A live decision with the node's clock at `now`.
    fn handle_at(svc: &PrivateService, event: &Event, now: u64) -> RegistrationOutcome {
        handle_inner(svc, event, Admission::Live { now })
    }

    /// Run `f` under a log subscriber of its own and return what it logged
    /// with its result.
    fn logged<R>(f: impl FnOnce() -> R) -> (R, String) {
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct Capture(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        // One subscriber for the whole test binary that wants every warning.
        // Without it, a warning first reached on another test's thread while
        // this capture is the only subscriber is cached as unwanted while it lives
        // (tracing-core asks that thread's default, which is none), and the
        // capture then misses its own line.
        static EVERY_THREAD: std::sync::Once = std::sync::Once::new();
        EVERY_THREAD.call_once(|| {
            let _ = tracing::subscriber::set_global_default(
                tracing_subscriber::fmt()
                    .with_writer(std::io::sink)
                    .finish(),
            );
        });

        let bytes = Arc::new(Mutex::new(Vec::new()));
        let capture = Capture(bytes.clone());
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_writer(move || capture.clone())
            .finish();
        let result = tracing::subscriber::with_default(subscriber, f);
        let log = String::from_utf8(bytes.lock().unwrap().clone()).expect("utf-8 log");
        (result, log)
    }

    /// A shape-valid 30640: alias `d`, the tenant's own pubkey as the sole w
    /// key (no proof-of-possession needed for the author key), relays/server
    /// tags listing the test domain.
    fn registration_event(
        tenant: &nostr_sdk::prelude::Keys,
        alias: &str,
        created_at: u64,
    ) -> Event {
        registration_event_with_w(
            tenant,
            alias,
            created_at,
            vec![vec![tenant.public_key().to_hex()]],
        )
    }

    /// Schnorr proof-of-possession entry for a w key that is not the author.
    fn key_entry(
        key: &nostr_sdk::prelude::Keys,
        tenant: &nostr_sdk::prelude::Keys,
        alias: &str,
    ) -> Vec<String> {
        use bitcoin_hashes::sha256;

        let digest =
            sha256::Hash::hash(key_pop_input(&tenant.public_key().to_hex(), alias).as_bytes());
        let sig = key.sign_schnorr(digest.to_byte_array());
        vec![key.public_key().to_hex(), sig.to_string()]
    }

    fn registration_event_with_w(
        tenant: &nostr_sdk::prelude::Keys,
        alias: &str,
        created_at: u64,
        w_entries: Vec<Vec<String>>,
    ) -> Event {
        registration_event_naming(
            tenant,
            alias,
            created_at,
            &["ws://localhost:7334"],
            &["http://localhost:7334"],
            w_entries,
            Vec::new(),
        )
    }

    /// A 30640 with every tag chosen by the caller: the values of its
    /// `relays` and `server` tags, and its `w` and `aux` entries.
    fn registration_event_naming(
        tenant: &nostr_sdk::prelude::Keys,
        alias: &str,
        created_at: u64,
        relays: &[&str],
        servers: &[&str],
        w_entries: Vec<Vec<String>>,
        aux_entries: Vec<Vec<String>>,
    ) -> Event {
        use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Kind, Tag};

        let values = |urls: &[&str]| urls.iter().map(|url| url.to_string()).collect::<Vec<_>>();
        let mut tags = vec![
            Tag::identifier(alias),
            Tag::custom("relays", values(relays)),
            Tag::custom("server", values(servers)),
        ];
        for entry in w_entries {
            tags.push(Tag::custom("w", entry));
        }
        for entry in aux_entries {
            tags.push(Tag::custom("aux", entry));
        }
        EventBuilder::new(Kind::Custom(super::super::KIND_REGISTRATION), "")
            .tags(tags)
            .custom_created_at(nostr::prelude::Timestamp::from_secs(created_at))
            .finalize(tenant)
            .expect("sign 30640")
    }

    /// FA end-to-end through `handle()`: the anchor is written at the first
    /// edition, PRESERVED across a same-tenant rotation, and an intermediate
    /// -created_at squatter keeps losing afterwards. A pre-fix record (anchor
    /// fields `None`) adopts its old latest edition on the next replacement.
    #[tokio::test]
    async fn same_tenant_replacement_preserves_anchor() {
        use nostr_sdk::prelude::Keys;

        let h = harness().await;
        let svc = &h.svc;
        let tenant = Keys::generate();
        let alias = "a".repeat(32);

        // Edition 1 at t=1000 anchors the seat.
        let ed1 = registration_event(&tenant, &alias, 1000);
        let outcome = handle(svc, &ed1);
        assert!(matches!(outcome.result, WritePolicyResult::Accept));
        {
            let txn = svc.meta.read_txn().unwrap();
            let r = svc.meta.get_registration(&txn, &alias).unwrap().unwrap();
            assert_eq!(
                r.first_created_at,
                Some(nostr::prelude::Timestamp::from_secs(1000))
            );
            assert_eq!(r.first_event_id, Some(ed1.id.to_hex()));
        }

        // Rotation at t=2000: latest-edition fields advance, anchor holds.
        let ed2 = registration_event(&tenant, &alias, 2000);
        let outcome = handle(svc, &ed2);
        assert!(matches!(outcome.result, WritePolicyResult::Accept));
        {
            let txn = svc.meta.read_txn().unwrap();
            let r = svc.meta.get_registration(&txn, &alias).unwrap().unwrap();
            assert_eq!(r.created_at, 2000);
            assert_eq!(r.event_id, ed2.id.to_hex());
            assert_eq!(
                r.first_created_at,
                Some(nostr::prelude::Timestamp::from_secs(1000)),
                "anchor must survive same-tenant replacement"
            );
            assert_eq!(r.first_event_id, Some(ed1.id.to_hex()));
        }

        // Squatter at t=1500 (between the editions) still loses; the victim
        // keeps the seat and no eviction happens. Decided while the seat is
        // young, so it is the preserved anchor that refuses it, not the
        // seat's age.
        let squatter = Keys::generate();
        let squat = registration_event(&squatter, &alias, 1500);
        let outcome = handle_at(svc, &squat, WHILE_YOUNG);
        assert!(
            !matches!(outcome.result, WritePolicyResult::Accept),
            "intermediate-created_at squatter must keep losing after rotation"
        );
        {
            let txn = svc.meta.read_txn().unwrap();
            let r = svc.meta.get_registration(&txn, &alias).unwrap().unwrap();
            assert_eq!(r.tenant_hex, tenant.public_key().to_hex());
            assert_eq!(r.event_id, ed2.id.to_hex(), "no eviction, no churn");
        }

        // Pre-fix record (anchor fields None): the next same-tenant
        // replacement adopts the OLD latest edition as the anchor. The
        // record claims a dedicated (PoP-signed) writer key — reusing the
        // tenant key would collide with the first alias's key claim.
        let alias2 = "b".repeat(32);
        let writer2 = Keys::generate();
        let ed_old = registration_event(&tenant, &alias2, 3000);
        svc.meta
            .with_write(|m, txn| {
                m.put_registration(
                    txn,
                    &alias2,
                    &RegistrationRecord {
                        tenant_hex: tenant.public_key().to_hex(),
                        event_id: ed_old.id.to_hex(),
                        created_at: 3000,
                        w_keys: vec![writer2.public_key().to_hex()],
                        aux_keys: vec![],
                        relays: vec![],
                        servers: vec![],
                        quota_class: None,
                        registered_at: 1,
                        tombstoned_at: None,
                        first_created_at: None,
                        first_event_id: None,
                    },
                )?;
                m.put_key_claim(txn, &writer2.public_key().to_hex(), &alias2)
            })
            .unwrap();
        let ed_new = registration_event_with_w(
            &tenant,
            &alias2,
            4000,
            vec![key_entry(&writer2, &tenant, &alias2)],
        );
        let outcome = handle(svc, &ed_new);
        assert!(matches!(outcome.result, WritePolicyResult::Accept));
        {
            let txn = svc.meta.read_txn().unwrap();
            let r = svc.meta.get_registration(&txn, &alias2).unwrap().unwrap();
            assert_eq!(r.created_at, 4000);
            assert_eq!(
                r.anchor(),
                (
                    nostr::prelude::Timestamp::from_secs(3000),
                    ed_old.id.to_hex().as_str()
                ),
                "pre-fix record must adopt its old latest edition as the anchor"
            );
        }
    }

    /// FC/FD (verify round 1) + decision D4: a merge eviction frees the
    /// loser's footprint in the winner's txn — the dead alias stops
    /// referencing every blob (a declared blob nobody else references loses
    /// its claim and its charge; a blob another repository references goes
    /// on under that one's own charge; stored bytes nobody else references
    /// keep the loser's charge until GC, as before decision D4), the alias
    /// scope's event-bytes column is reset before the winner's own charge
    /// lands, and the loser's state-ring editions are deleted. The
    /// survivor's next state root naming the shared blob charges it nothing
    /// more: it was paying already. The loser's `t:` event bytes stay
    /// stranded (pre-existing !1/!4 backlog).
    #[tokio::test]
    async fn eviction_cleans_loser_footprint() {
        use super::super::claims;
        use super::super::meta::MetaEnv;
        use nostr_sdk::prelude::Keys;

        let h = harness().await;
        let svc = &h.svc;
        let loser = Keys::generate();
        let winner = Keys::generate();
        let survivor = Keys::generate();
        let alias = "d".repeat(32);
        let other = "e".repeat(32);

        // The loser holds the alias (t=2000).
        let reg1 = registration_event(&loser, &alias, 2000);
        let outcome = handle(svc, &reg1);
        assert!(matches!(outcome.result, WritePolicyResult::Accept));
        let reg1_bytes = reg1.as_json().len() as u64;

        // Loser footprint: two ring editions; a declared (unstored) claim; a
        // stored claim; a claim shared with the survivor's alias, which pays
        // its own charge; event bytes in the alias scope.
        let sha_declared = "11".repeat(32);
        let sha_stored = "22".repeat(32);
        let sha_shared = "33".repeat(32);
        let loser_hex = loser.public_key().to_hex();
        let survivor_hex = survivor.public_key().to_hex();
        svc.meta
            .with_write(|m, txn| {
                for (i, id) in ["aa", "bb"].iter().enumerate() {
                    m.put_state_ring(
                        txn,
                        &MetaEnv::state_ring_key(&alias, 2000 + i as u64, id),
                        "{}",
                    )?;
                }
                quota::charge(m, txn, &loser_hex, &alias, 5000, false)?;
                let cfg = &svc.cfg;
                claims::attach_to(m, txn, cfg, &sha_declared, &loser_hex, &alias, 4096)?;
                claims::attach_to(m, txn, cfg, &sha_stored, &loser_hex, &alias, 512)?;
                let before = m.get_blob_claim(txn, &sha_stored)?;
                let mut stored = before.clone().expect("declared");
                let moves = claims::settle_stored(cfg, &mut stored, 512, 1);
                claims::commit(m, txn, &sha_stored, before.as_ref(), Some(&stored), &moves)?;
                claims::attach_to(m, txn, cfg, &sha_shared, &loser_hex, &alias, 100)?;
                claims::attach_to(m, txn, cfg, &sha_shared, &survivor_hex, &other, 100)
            })
            .unwrap();
        let blob_column = |key: String| {
            let txn = svc.meta.read_txn().unwrap();
            svc.meta.get_ledger_txn(&txn, &key).unwrap().blob_bytes
        };
        assert_eq!(blob_column(quota::alias_key(&alias)), 4096 + 512 + 100);

        // The earlier-created winner takes the alias (the loser's seat is
        // young).
        let reg_w = registration_event(&winner, &alias, 1000);
        let outcome = handle_at(svc, &reg_w, WHILE_YOUNG);
        assert!(matches!(outcome.result, WritePolicyResult::Accept));
        assert_eq!(outcome.prune, vec![(loser_hex.clone(), alias.clone())]);
        let winner_bytes = reg_w.as_json().len() as u64;

        let txn = svc.meta.read_txn().unwrap();
        // Ring editions deleted — the winner starts a fresh ring.
        assert!(
            svc.meta
                .state_ring_for_alias(&txn, &alias)
                .unwrap()
                .is_empty(),
            "loser ring editions must be deleted at eviction"
        );
        // A declared blob nobody else references: claim and charge gone.
        assert!(
            svc.meta
                .get_blob_claim(&txn, &sha_declared)
                .unwrap()
                .is_none(),
            "a never-stored claim goes with its last reference"
        );
        // Stored bytes nobody else references: kept for GC, and so is the
        // loser's charge for them.
        let c = svc.meta.get_blob_claim(&txn, &sha_stored).unwrap().unwrap();
        assert!(c.aliases.is_empty());
        assert!(c.unreferenced_since.is_some());
        assert!(c.stored, "{c:?}");
        assert_eq!(
            c.charges,
            vec![super::super::meta::ClaimCharge {
                tenant: loser_hex.clone(),
                alias: alias.clone(),
                bytes: 512,
            }],
            "the last referrer of stored bytes pays until GC"
        );
        // The shared claim keeps the survivor and its own charge only.
        let c = svc.meta.get_blob_claim(&txn, &sha_shared).unwrap().unwrap();
        assert_eq!(c.aliases, vec![other.clone()]);
        assert_eq!(claims::charge_of(&c, &alias), None);
        assert_eq!(claims::charge_of(&c, &other), Some(100));
        assert_eq!(
            svc.meta.alias_claim_shas(&txn, &alias).unwrap(),
            vec![sha_stored.clone()],
            "the index keeps the grace charge for GC to find"
        );
        assert_eq!(
            svc.meta.alias_claim_shas(&txn, &other).unwrap(),
            vec![sha_shared.clone()]
        );
        // The alias scope's event column was reset and the winner's own
        // registration charge then landed in the same txn; the blob column
        // keeps only the stored bytes' grace charge.
        let r = svc
            .meta
            .get_ledger_txn(&txn, &quota::alias_key(&alias))
            .unwrap();
        assert_eq!(r.event_bytes, winner_bytes);
        assert_eq!(r.blob_bytes, 512);
        // The loser's tenant scope keeps its stranded event bytes (!1/!4);
        // its blob column only the stored bytes' grace charge.
        let t = svc
            .meta
            .get_ledger_txn(&txn, &quota::tenant_key(&loser_hex))
            .unwrap();
        assert_eq!(t.event_bytes, 5000 + reg1_bytes);
        assert_eq!(t.blob_bytes, 512);
        // Loser record + key claim gone; the winner is anchored on its event.
        let r = svc.meta.get_registration(&txn, &alias).unwrap().unwrap();
        assert_eq!(r.tenant_hex, winner.public_key().to_hex());
        assert_eq!(
            r.anchor(),
            (
                nostr::prelude::Timestamp::from_secs(1000),
                reg_w.id.to_hex().as_str()
            )
        );
        assert!(svc.meta.get_key_claim(&txn, &loser_hex).unwrap().is_none());
        assert_eq!(
            svc.meta
                .get_key_claim(&txn, &winner.public_key().to_hex())
                .unwrap(),
            Some(alias.clone())
        );
        drop(txn);

        // The survivor's next state root naming the shared sha is charged
        // nothing more for it: one charge per repository. Register the
        // survivor (w = its own tenant key) and make its 30640 coordinate
        // queryable (liveness checks the relay DB too).
        let reg_s = registration_event(&survivor, &other, 1500);
        let outcome = handle(svc, &reg_s);
        assert!(matches!(outcome.result, WritePolicyResult::Accept));
        svc.database
            .save_event(&reg_s)
            .await
            .expect("save survivor 30640");

        let edition = state_root_event(&survivor, &other, &sha_shared, 100, 3000);
        let result = super::super::state_root::handle(svc, &edition).await;
        assert!(
            matches!(result, WritePolicyResult::Accept),
            "survivor's referencing 30641 must be accepted"
        );
        let txn = svc.meta.read_txn().unwrap();
        let c = svc.meta.get_blob_claim(&txn, &sha_shared).unwrap().unwrap();
        assert_eq!(c.charges.len(), 1, "{c:?}");
        assert_eq!(claims::charge_of(&c, &other), Some(100));
        drop(txn);
        assert_eq!(blob_column(quota::tenant_key(&survivor_hex)), 100);
        assert_eq!(blob_column(quota::alias_key(&other)), 100);
    }

    /// A shape-valid 30641 for the harness: `d`, `a` coordinate of the
    /// tenant's own registration, one `m` tag.
    fn state_root_event(
        tenant: &nostr_sdk::prelude::Keys,
        alias: &str,
        sha: &str,
        size: u64,
        created_at: u64,
    ) -> Event {
        use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Kind, Tag};

        let tags = vec![
            Tag::identifier(alias),
            Tag::custom(
                "a",
                vec![format!("30640:{}:{}", tenant.public_key().to_hex(), alias)],
            ),
            Tag::custom("m", vec![sha.to_string(), size.to_string()]),
        ];
        EventBuilder::new(Kind::Custom(super::super::KIND_STATE_ROOT), "")
            .tags(tags)
            .custom_created_at(nostr::prelude::Timestamp::from_secs(created_at))
            .finalize(tenant)
            .expect("sign 30641")
    }

    /// R2-B (verify round 2): a stale same-tenant edition LOWERS the
    /// conflict anchor — a late-witness node that only ever saw edition 2
    /// adopts the authentic earlier evidence (only the tenant can mint its
    /// own editions), after which an intermediate-created_at squatter loses.
    /// Non-beating stale editions and replays leave the anchor alone
    /// (monotone, idempotent).
    #[tokio::test]
    async fn stale_same_tenant_edition_lowers_anchor() {
        use nostr_sdk::prelude::Keys;

        let h = harness().await;
        let svc = &h.svc;
        let tenant = Keys::generate();
        let alias = "f".repeat(32);

        // Late-witness node: edition 2 (t=2000) lands first; the anchor is
        // the witnessed edition.
        let ed2 = registration_event(&tenant, &alias, 2000);
        let outcome = handle(svc, &ed2);
        assert!(matches!(outcome.result, WritePolicyResult::Accept));
        {
            let txn = svc.meta.read_txn().unwrap();
            let r = svc.meta.get_registration(&txn, &alias).unwrap().unwrap();
            assert_eq!(
                r.anchor(),
                (
                    nostr::prelude::Timestamp::from_secs(2000),
                    ed2.id.to_hex().as_str()
                )
            );
        }

        // Authentic earlier evidence (edition 1, t=1000) arrives stale:
        // accept-no-op, but the anchor LOWERS to it.
        let ed1 = registration_event(&tenant, &alias, 1000);
        let outcome = handle(svc, &ed1);
        assert!(matches!(outcome.result, WritePolicyResult::Accept));
        {
            let txn = svc.meta.read_txn().unwrap();
            let r = svc.meta.get_registration(&txn, &alias).unwrap().unwrap();
            assert_eq!(r.created_at, 2000, "latest-edition fields untouched");
            assert_eq!(r.event_id, ed2.id.to_hex());
            assert_eq!(
                r.anchor(),
                (
                    nostr::prelude::Timestamp::from_secs(1000),
                    ed1.id.to_hex().as_str()
                ),
                "authentic older evidence must lower the anchor"
            );
        }

        // Replaying the same event is idempotent, and a stale edition that
        // does NOT beat the anchor moves nothing.
        let outcome = handle(svc, &ed1);
        assert!(matches!(outcome.result, WritePolicyResult::Accept));
        let ed_mid = registration_event(&tenant, &alias, 1500);
        let outcome = handle(svc, &ed_mid);
        assert!(matches!(outcome.result, WritePolicyResult::Accept));
        {
            let txn = svc.meta.read_txn().unwrap();
            let r = svc.meta.get_registration(&txn, &alias).unwrap().unwrap();
            assert_eq!(
                r.anchor(),
                (
                    nostr::prelude::Timestamp::from_secs(1000),
                    ed1.id.to_hex().as_str()
                ),
                "replay and non-beating stale editions must not move the anchor"
            );
        }

        // The intermediate-created_at squatter now LOSES (pre-R2-B it won on
        // late-witness nodes anchored at edition 2). Decided while the seat
        // is young, so it is the lowered anchor that refuses it.
        let squat = registration_event(&Keys::generate(), &alias, 1500);
        let outcome = handle_at(svc, &squat, WHILE_YOUNG);
        assert!(
            !matches!(outcome.result, WritePolicyResult::Accept),
            "the squatter must lose once the anchor reflects the earlier edition"
        );
        let txn = svc.meta.read_txn().unwrap();
        let r = svc.meta.get_registration(&txn, &alias).unwrap().unwrap();
        assert_eq!(r.tenant_hex, tenant.public_key().to_hex());
        assert_eq!(r.event_id, ed2.id.to_hex(), "no eviction, no churn");
    }

    /// R2-C (verify round 2): the 30641 charge txn re-verifies the
    /// registration identity inside the write txn. Pass liveness with a live
    /// record, evict it, then run the handler's txn against the stale
    /// record: rejection — and ZERO mutations (no claims, no charges, no
    /// ring rows).
    #[tokio::test]
    async fn stale_record_state_root_txn_rejects_without_mutation() {
        use nostr_sdk::prelude::Keys;

        let h = harness().await;
        let svc = &h.svc;
        let loser = Keys::generate();
        let winner = Keys::generate();
        let alias = "a".repeat(32);

        // The loser holds the alias (t=2000); its 30640 coordinate is
        // queryable (liveness checks the relay DB too).
        let reg1 = registration_event(&loser, &alias, 2000);
        let outcome = handle(svc, &reg1);
        assert!(matches!(outcome.result, WritePolicyResult::Accept));
        svc.database
            .save_event(&reg1)
            .await
            .expect("save loser 30640");

        // Liveness passes with the live record — the pre-txn admission view
        // the handler would have carried into its txn.
        let record = svc.live_registration(&alias).await.unwrap().unwrap();
        assert_eq!(record.event_id, reg1.id.to_hex());

        // The eviction lands between liveness and the charge txn.
        let reg_w = registration_event(&winner, &alias, 1000);
        let outcome = handle_at(svc, &reg_w, WHILE_YOUNG);
        assert!(matches!(outcome.result, WritePolicyResult::Accept));
        let winner_bytes = reg_w.as_json().len() as u64;

        // The loser's 30641 (admitted on the stale record) must now be
        // rejected by the in-txn identity re-check, with ZERO mutations.
        let sha = "44".repeat(32);
        let edition = state_root_event(&loser, &alias, &sha, 4096, 3000);
        let parsed = super::super::state_root::parse_shape(&edition, u64::MAX).unwrap();
        let json = edition.as_json();
        let outcome = svc
            .meta
            .with_write(|meta, txn| {
                super::super::state_root::apply_state_root_txn(
                    meta, txn, &svc.cfg, &record, &parsed, &edition, &json,
                )
            })
            .unwrap();
        assert!(
            outcome.is_some(),
            "the stale-record txn must reject, not commit"
        );

        let txn = svc.meta.read_txn().unwrap();
        assert!(
            svc.meta.get_blob_claim(&txn, &sha).unwrap().is_none(),
            "no zombie claim"
        );
        assert!(svc.meta.alias_claim_shas(&txn, &alias).unwrap().is_empty());
        assert!(
            svc.meta
                .state_ring_for_alias(&txn, &alias)
                .unwrap()
                .is_empty(),
            "no zombie ring edition"
        );
        let r = svc
            .meta
            .get_ledger_txn(&txn, &quota::alias_key(&alias))
            .unwrap();
        assert_eq!(r.event_bytes, winner_bytes, "ledger untouched");
        assert_eq!(r.blob_bytes, 0, "no zombie charge");
    }

    /// R2-C: the wrap charge txn re-verifies registration identity inside
    /// the write txn — a stale record maps to the Unregistered arm (NOT
    /// quota), and nothing is charged or marked.
    #[tokio::test]
    async fn stale_record_wrap_charge_txn_rejects_without_mutation() {
        use nostr_sdk::prelude::Keys;

        let h = harness().await;
        let svc = &h.svc;
        let loser = Keys::generate();
        let winner = Keys::generate();
        let alias = "b".repeat(32);

        let reg1 = registration_event(&loser, &alias, 2000);
        let outcome = handle(svc, &reg1);
        assert!(matches!(outcome.result, WritePolicyResult::Accept));
        let reg1_bytes = reg1.as_json().len() as u64;
        let loser_record = {
            let txn = svc.meta.read_txn().unwrap();
            svc.meta.get_registration(&txn, &alias).unwrap().unwrap()
        };

        // The registration dies (takeover) before the wrap's charge txn.
        let reg_w = registration_event(&winner, &alias, 1000);
        let outcome = handle_at(svc, &reg_w, WHILE_YOUNG);
        assert!(matches!(outcome.result, WritePolicyResult::Accept));

        let outcome = svc
            .meta
            .with_write(|meta, txn| {
                super::super::apply_wrap_charge_txn(
                    meta,
                    txn,
                    &svc.cfg,
                    &loser_record,
                    &alias,
                    350,
                    "cc",
                )
            })
            .unwrap();
        assert!(
            matches!(outcome, super::super::WrapCharge::Unregistered),
            "a stale record must map to Unregistered, never quota"
        );

        let txn = svc.meta.read_txn().unwrap();
        assert!(
            !svc.meta.is_wrap_charged(&txn, "cc").unwrap(),
            "the wrap id must not be marked charged"
        );
        let t = svc
            .meta
            .get_ledger_txn(&txn, &quota::tenant_key(&loser.public_key().to_hex()))
            .unwrap();
        assert_eq!(
            t.event_bytes, reg1_bytes,
            "only the (stranded) registration charge remains — no wrap charge"
        );
    }

    /// FG: the conflict-alert dedup fires once per loser EVENT id within the
    /// TTL (never keyed on the alias — a new conflict is a new event id and
    /// still alerts) and refires after expiry.
    #[test]
    fn conflict_alert_dedup_fires_once_per_event_id() {
        let ttl = std::time::Duration::from_secs(3600);
        let mut dedup = ConflictAlertDedup::new(ttl);
        let t0 = std::time::Instant::now();
        assert!(dedup.should_alert_at("ev1", t0), "first firing alerts");
        assert!(
            !dedup.should_alert_at("ev1", t0 + std::time::Duration::from_secs(1)),
            "replay of the same loser event is suppressed"
        );
        assert!(
            dedup.should_alert_at("ev2", t0 + std::time::Duration::from_secs(2)),
            "a NEW conflict (new event id) still alerts"
        );
        assert!(
            dedup.should_alert_at("ev1", t0 + ttl + std::time::Duration::from_secs(1)),
            "after the TTL the same event earns one fresh alert"
        );
    }

    /// FG: at the cap the OLDEST entry is evicted to make room, never the
    /// fresh one — a new conflict must still alert under a flood.
    #[test]
    fn conflict_alert_dedup_cap_evicts_oldest() {
        let ttl = std::time::Duration::from_secs(3600);
        let mut dedup = ConflictAlertDedup::new(ttl);
        let t0 = std::time::Instant::now();
        for i in 0..ConflictAlertDedup::MAX_ENTRIES {
            assert!(dedup.should_alert_at(
                &format!("flood-{i}"),
                t0 + std::time::Duration::from_millis(i as u64)
            ));
        }
        assert!(
            dedup.should_alert_at("fresh", t0 + std::time::Duration::from_secs(1)),
            "a fresh conflict must alert even at the cap"
        );
        assert!(
            !dedup.should_alert_at("flood-1", t0 + std::time::Duration::from_secs(2)),
            "entries that survived the cap stay suppressed"
        );
        assert!(
            dedup.should_alert_at("flood-0", t0 + std::time::Duration::from_secs(3)),
            "the oldest entry was evicted to make room"
        );
    }

    /// Phase-4b A2: same-tenant 30640 replacements are cadence-gated (a
    /// rotation burst within capacity is allowed, the sustained flood is
    /// blocked), while new-alias registrations, stale same-tenant editions
    /// (anchor repair), cross-tenant conflict merges, and boot_reconcile
    /// replays are ALL exempt.
    #[tokio::test]
    async fn same_tenant_replacement_cadence() {
        use nostr_sdk::prelude::Keys;

        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = crate::config::Config::for_testing();
        config.private_repos_enable = true;
        config.private_meta_data_path =
            Some(dir.path().join("meta").to_string_lossy().into_owned());
        config.private_blob_data_path =
            Some(dir.path().join("blobs").to_string_lossy().into_owned());
        config.private_registration_replace_capacity = 2;
        config.private_registration_replace_refill_per_hour = 1;
        let database: crate::nostr::SharedDatabase =
            std::sync::Arc::new(nostr_memory::MemoryDatabase::unbounded());
        let svc = PrivateService::new(&config, database)
            .await
            .expect("private service");
        let _dir = dir;

        let tenant = Keys::generate();
        let alias = "c".repeat(32);

        // New-alias registration: exempt, consumes no replacement budget.
        let ed1 = registration_event(&tenant, &alias, 1000);
        assert!(matches!(
            handle(&svc, &ed1).result,
            WritePolicyResult::Accept
        ));

        // Rotation burst within capacity (2) is allowed — a §3.3 widen->
        // narrow rotation plus retries must never trip at sane defaults.
        let ed2 = registration_event(&tenant, &alias, 2000);
        assert!(matches!(
            handle(&svc, &ed2).result,
            WritePolicyResult::Accept
        ));
        let ed3 = registration_event(&tenant, &alias, 3000);
        assert!(matches!(
            handle(&svc, &ed3).result,
            WritePolicyResult::Accept
        ));

        // The flood beyond capacity is blocked, and the stored record is
        // untouched (rejection mutates nothing).
        let ed4 = registration_event(&tenant, &alias, 4000);
        let outcome = handle(&svc, &ed4);
        assert!(
            !matches!(outcome.result, WritePolicyResult::Accept),
            "the replacement flood must be cadence-rejected"
        );
        {
            let txn = svc.meta.read_txn().unwrap();
            let r = svc.meta.get_registration(&txn, &alias).unwrap().unwrap();
            assert_eq!(r.event_id, ed3.id.to_hex(), "rejection must not mutate");
        }

        // Stale same-tenant edition (accept-no-op anchor repair): exempt.
        let stale = registration_event(&tenant, &alias, 2500);
        assert!(
            matches!(handle(&svc, &stale).result, WritePolicyResult::Accept),
            "stale editions must not be cadence-gated"
        );

        // New alias from the same tenant: exempt (fresh (tenant, alias)
        // bucket key AND the new-alias path never consults the bucket).
        // A dedicated writer key — reusing the tenant key would collide
        // with the first alias's key claim.
        let alias2 = "d".repeat(32);
        let writer2 = Keys::generate();
        let reg2 = registration_event_with_w(
            &tenant,
            &alias2,
            3500,
            vec![key_entry(&writer2, &tenant, &alias2)],
        );
        assert!(matches!(
            handle(&svc, &reg2).result,
            WritePolicyResult::Accept
        ));

        // boot_reconcile replay of the cadence-rejected edition: bypasses
        // the bucket entirely (replays must not consume budget).
        let outcome = handle_replay(&svc, &ed4, BEFORE_EVERY_SEAT);
        assert!(
            matches!(outcome.result, WritePolicyResult::Accept),
            "replay admission must bypass the cadence bucket"
        );

        // §3.2 hard invariant: a cross-tenant conflict-merge WINNER is
        // never gated by node-local state. The bucket is irrelevant here,
        // but pin it anyway: an earlier-created squatter takes alias2 even
        // with the tenant's cadence budget for OTHER aliases exhausted.
        let squatter = Keys::generate();
        let squat = registration_event(&squatter, &alias2, 3400);
        let outcome = handle_at(&svc, &squat, WHILE_YOUNG);
        assert!(
            matches!(outcome.result, WritePolicyResult::Accept),
            "a conflict-merge winner must never be cadence-gated"
        );
        let txn = svc.meta.read_txn().unwrap();
        let r = svc.meta.get_registration(&txn, &alias2).unwrap().unwrap();
        assert_eq!(r.tenant_hex, squatter.public_key().to_hex());
    }

    /// FS-1 (review L1-F1): the cadence gate must exempt a same-tenant
    /// newer replacement that WINS A KEY CONFLICT (evict non-empty) — the
    /// §3.2 merge is event-intrinsic and node-local bucket state must never
    /// gate it, exactly like the quota and alias-limit guards above it.
    /// Otherwise the winner evicts the loser's alias on nodes whose bucket
    /// had budget but is cadence-rejected on exhausted nodes, and once a
    /// newer edition supersedes the winner everywhere the loser can never
    /// be re-evicted: permanent split-brain. The pure same-tenant flood
    /// (no conflict won) must STILL be cadence-rejected.
    #[tokio::test]
    async fn key_conflict_winning_replacement_exempt_from_cadence() {
        use nostr_sdk::prelude::Keys;

        let dir = tempfile::tempdir().expect("tempdir");
        let mut config = crate::config::Config::for_testing();
        config.private_repos_enable = true;
        config.private_meta_data_path =
            Some(dir.path().join("meta").to_string_lossy().into_owned());
        config.private_blob_data_path =
            Some(dir.path().join("blobs").to_string_lossy().into_owned());
        // One replacement token, no meaningful refill: the bucket is
        // EXHAUSTED when the conflict winner arrives.
        config.private_registration_replace_capacity = 1;
        config.private_registration_replace_refill_per_hour = 1;
        let database: crate::nostr::SharedDatabase =
            std::sync::Arc::new(nostr_memory::MemoryDatabase::unbounded());
        let svc = PrivateService::new(&config, database)
            .await
            .expect("private service");
        let _dir = dir;

        let tenant = Keys::generate();
        let other = Keys::generate();
        let shared = Keys::generate(); // the contested key k2
        let alias = "0".repeat(32);
        let other_alias = "1".repeat(32);

        // The tenant's seat (anchor t=1000); the other tenant's alias
        // anchors LATER (t=2000) and claims the shared key with a valid
        // proof-of-possession.
        let ed1 = registration_event(&tenant, &alias, 1000);
        assert!(matches!(
            handle(&svc, &ed1).result,
            WritePolicyResult::Accept
        ));
        let reg_other = registration_event_with_w(
            &other,
            &other_alias,
            2000,
            vec![key_entry(&shared, &other, &other_alias)],
        );
        assert!(matches!(
            handle(&svc, &reg_other).result,
            WritePolicyResult::Accept
        ));

        // Drain the tenant's single replacement token with a pure rotation.
        let rot = registration_event(&tenant, &alias, 1100);
        assert!(matches!(
            handle(&svc, &rot).result,
            WritePolicyResult::Accept
        ));

        // The backdated key-conflict WINNER: a same-tenant NEWER edition
        // (1500 > 1100) that is OLDER than the other alias's anchor
        // (1500 < 2000) and claims the shared key. On an exhausted bucket
        // it must STILL be admitted and apply the eviction — the merge is
        // not cadence-gated.
        let winner = registration_event_with_w(
            &tenant,
            &alias,
            1500,
            vec![key_entry(&shared, &tenant, &alias)],
        );
        let outcome = handle_at(&svc, &winner, WHILE_YOUNG);
        assert!(
            matches!(outcome.result, WritePolicyResult::Accept),
            "a key-conflict-winning replacement must bypass the cadence gate"
        );
        assert_eq!(
            outcome.prune,
            vec![(other.public_key().to_hex(), other_alias.clone())],
            "the loser's coordinate must be pruned"
        );
        {
            let txn = svc.meta.read_txn().unwrap();
            assert!(
                svc.meta
                    .get_registration(&txn, &other_alias)
                    .unwrap()
                    .is_none(),
                "the conflict loser must be evicted"
            );
            assert_eq!(
                svc.meta
                    .get_key_claim(&txn, &shared.public_key().to_hex())
                    .unwrap(),
                Some(alias.clone()),
                "the contested key must move to the winner's alias"
            );
            let r = svc.meta.get_registration(&txn, &alias).unwrap().unwrap();
            assert_eq!(r.event_id, winner.id.to_hex());
        }

        // The pure same-tenant flood (no conflict won) is STILL
        // cadence-rejected on the exhausted bucket, mutating nothing.
        let flood = registration_event(&tenant, &alias, 1600);
        let outcome = handle(&svc, &flood);
        assert!(
            !matches!(outcome.result, WritePolicyResult::Accept),
            "a plain same-tenant replacement must stay cadence-gated"
        );
        let txn = svc.meta.read_txn().unwrap();
        let r = svc.meta.get_registration(&txn, &alias).unwrap().unwrap();
        assert_eq!(r.event_id, winner.id.to_hex(), "rejection must not mutate");
    }

    // ------------------------------------------------------------------
    // Order of checks: shape, then admission, then proofs, then the write
    // transaction. None of these tests counts signature checks. They give a
    // registration a proof that cannot verify and assert that the refusal it
    // gets is the one of an EARLIER step: had a proof been verified first,
    // the proof's own message would have come back instead.
    // ------------------------------------------------------------------

    const KEY_LIMIT: &str = "registration exceeds the 64 key limit";
    const NOT_LISTED: &str = "tenant is not on the registration whitelist";
    const PROOF_INVALID: &str = "w/aux key proof-of-possession signature is invalid";
    const PROOF_MISSING: &str = "w/aux keys must carry a proof-of-possession signature";

    /// The message of a refusal; panics on anything else.
    fn refusal(outcome: &RegistrationOutcome) -> &str {
        match &outcome.result {
            WritePolicyResult::Reject {
                message,
                status: false,
                ..
            } => message.as_ref(),
            _ => panic!("expected a refusal"),
        }
    }

    /// The message `parse_shape` refuses with; panics when it accepts.
    fn shape_error(event: &Event, cfg: &PrivateConfig) -> String {
        match parse_shape(event, cfg) {
            Err(reason) => reason,
            Ok(_) => panic!("the shape check must refuse this registration"),
        }
    }

    /// A `w`/`aux` entry whose proof is a real signature by `key`, made for
    /// another alias: well formed, and never valid for the registration it
    /// is put in.
    fn unprovable_entry(
        key: &nostr_sdk::prelude::Keys,
        tenant: &nostr_sdk::prelude::Keys,
    ) -> Vec<String> {
        key_entry(key, tenant, &"9".repeat(32))
    }

    /// A node in whitelist mode that admits exactly `listed`.
    async fn whitelist_harness(listed: &[&nostr_sdk::prelude::Keys]) -> Harness {
        let whitelist = listed
            .iter()
            .map(|keys| keys.public_key().to_bech32().expect("npub"))
            .collect::<Vec<_>>()
            .join(",");
        harness_with(|config| {
            config.private_registration_mode = RegistrationMode::Whitelist;
            config.private_tenant_whitelist = whitelist;
        })
        .await
    }

    /// A registration over the key cap is refused for the cap, whatever its
    /// proofs are worth: the count is taken before any key is looked at.
    #[tokio::test]
    async fn key_count_cap_is_checked_before_any_proof() {
        use nostr_sdk::prelude::Keys;

        let h = harness().await;
        let svc = &h.svc;
        let tenant = Keys::generate();
        let alias = "a".repeat(32);

        let over_the_cap: Vec<Vec<String>> = (0..65)
            .map(|_| unprovable_entry(&Keys::generate(), &tenant))
            .collect();
        let event = registration_event_with_w(&tenant, &alias, 1000, over_the_cap);
        assert_eq!(shape_error(&event, &svc.cfg), KEY_LIMIT);
        assert_eq!(refusal(&handle(svc, &event)), KEY_LIMIT);

        // The cap counts w and aux together, and comes before the look at
        // each key: a malformed key among too many is still "too many".
        let mut w_entries: Vec<Vec<String>> = (0..40)
            .map(|_| unprovable_entry(&Keys::generate(), &tenant))
            .collect();
        w_entries.push(vec!["not-a-key".to_string()]);
        let aux_entries: Vec<Vec<String>> = (0..24)
            .map(|_| unprovable_entry(&Keys::generate(), &tenant))
            .collect();
        let event = registration_event_naming(
            &tenant,
            &alias,
            1000,
            &["ws://localhost:7334"],
            &["http://localhost:7334"],
            w_entries,
            aux_entries,
        );
        assert_eq!(shape_error(&event, &svc.cfg), KEY_LIMIT);

        // At the cap the proofs are what decides.
        let at_the_cap: Vec<Vec<String>> = (0..64)
            .map(|_| unprovable_entry(&Keys::generate(), &tenant))
            .collect();
        let event = registration_event_with_w(&tenant, &alias, 1000, at_the_cap);
        assert!(parse_shape(&event, &svc.cfg).is_ok());
        assert_eq!(refusal(&handle(svc, &event)), PROOF_INVALID);
    }

    /// Every refusal the shape check can give comes before any proof is
    /// verified: each registration here carries a proof that cannot verify,
    /// and none of them is told so.
    #[tokio::test]
    async fn shape_refusals_come_before_proof_refusals() {
        use nostr_sdk::prelude::Keys;

        let h = harness().await;
        let cfg = &h.svc.cfg;
        let tenant = Keys::generate();
        let alias = "b".repeat(32);
        let own = ["ws://localhost:7334"];
        let own_server = ["http://localhost:7334"];
        let bad = || unprovable_entry(&Keys::generate(), &tenant);
        let bare = || vec![Keys::generate().public_key().to_hex()];

        // A tag that does not name this node.
        let event = registration_event_naming(
            &tenant,
            &alias,
            1000,
            &["ws://other.example"],
            &own_server,
            vec![bad()],
            Vec::new(),
        );
        assert_eq!(
            shape_error(&event, cfg),
            "registration relays tag must list this node"
        );
        let event = registration_event_naming(
            &tenant,
            &alias,
            1000,
            &own,
            &["http://other.example"],
            vec![bad()],
            Vec::new(),
        );
        assert_eq!(
            shape_error(&event, cfg),
            "registration server tag must list this node"
        );

        // The same key twice.
        let twice = bad();
        let event = registration_event_naming(
            &tenant,
            &alias,
            1000,
            &own,
            &own_server,
            vec![twice.clone()],
            vec![twice],
        );
        assert_eq!(
            shape_error(&event, cfg),
            "registration lists the same key more than once"
        );

        // A missing proof on a later key.
        let event = registration_event_naming(
            &tenant,
            &alias,
            1000,
            &own,
            &own_server,
            vec![bad()],
            vec![bare()],
        );
        assert_eq!(shape_error(&event, cfg), PROOF_MISSING);

        // A malformed key after one whose proof is missing: the shape of
        // every key is looked at before the presence of any proof.
        let event = registration_event_naming(
            &tenant,
            &alias,
            1000,
            &own,
            &own_server,
            vec![bare()],
            vec![vec!["ABCDEF".to_string()]],
        );
        assert_eq!(
            shape_error(&event, cfg),
            "w/aux keys must be 64 lowercase hex chars"
        );

        // A registration that passes the shape check is refused by the
        // proof step, and only there.
        let event = registration_event_with_w(&tenant, &alias, 1000, vec![bad()]);
        let parsed = parse_shape(&event, cfg).expect("the shape is fine");
        assert_eq!(parsed.proofs.len(), 1);
        assert_eq!(
            verify_proofs(&parsed, &tenant.public_key().to_hex()),
            Err(PROOF_INVALID.to_string())
        );

        // The author's own key carries no proof and needs none.
        let writer = Keys::generate();
        let event = registration_event_with_w(
            &tenant,
            &alias,
            1000,
            vec![
                vec![tenant.public_key().to_hex()],
                key_entry(&writer, &tenant, &alias),
            ],
        );
        let parsed = parse_shape(&event, cfg).expect("the shape is fine");
        assert_eq!(parsed.proofs.len(), 1);
        assert_eq!(parsed.w_keys.len(), 2);
        assert_eq!(
            verify_proofs(&parsed, &tenant.public_key().to_hex()),
            Ok(())
        );
    }

    /// A sender the whitelist refuses is told so before any proof is
    /// verified: its unverifiable proof goes unnoticed. The same
    /// registration from a listed sender reaches the proof step.
    #[tokio::test]
    async fn unlisted_sender_is_refused_before_any_proof() {
        use nostr_sdk::prelude::Keys;

        let listed = Keys::generate();
        let h = whitelist_harness(&[&listed]).await;
        let svc = &h.svc;
        let alias = "c".repeat(32);

        let outsider = Keys::generate();
        let event = registration_event_with_w(
            &outsider,
            &alias,
            1000,
            vec![unprovable_entry(&Keys::generate(), &outsider)],
        );
        let before = PROOFS_VERIFIED.with(|n| n.get());
        let outcome = handle(svc, &event);
        assert_eq!(
            PROOFS_VERIFIED.with(|n| n.get()),
            before,
            "no proof may be verified for a refused sender"
        );
        assert_eq!(refusal(&outcome), NOT_LISTED);
        assert!(outcome.prune.is_empty());

        let event = registration_event_with_w(
            &listed,
            &alias,
            1000,
            vec![unprovable_entry(&Keys::generate(), &listed)],
        );
        assert_eq!(refusal(&handle(svc, &event)), PROOF_INVALID);
        assert_eq!(PROOFS_VERIFIED.with(|n| n.get()), before + 1);
    }

    /// Proof-of-work mode is asked before the proofs as well.
    #[tokio::test]
    async fn pow_mode_asks_for_work_before_proofs() {
        use nostr_sdk::prelude::Keys;

        let h = harness_with(|config| {
            config.private_registration_mode = RegistrationMode::Pow;
            config.private_pow_bits = 40;
        })
        .await;
        let tenant = Keys::generate();
        let event = registration_event_with_w(
            &tenant,
            &"d".repeat(32),
            1000,
            vec![unprovable_entry(&Keys::generate(), &tenant)],
        );
        assert_eq!(
            refusal(&handle(&h.svc, &event)),
            "registration requires 40 bits of NIP-13 proof of work"
        );
    }

    /// A sender the mode refuses takes part in no conflict: whether its
    /// registration would have lost or won against the holder, it gets the
    /// mode's message, nothing is pruned and no conflict alert is recorded.
    /// A listed sender in the same position still gets the conflict answer.
    #[tokio::test]
    async fn unlisted_sender_takes_part_in_no_conflict() {
        use nostr_sdk::prelude::Keys;

        let holder = Keys::generate();
        let rival = Keys::generate();
        let h = whitelist_harness(&[&holder, &rival]).await;
        let svc = &h.svc;
        let alias = "e".repeat(32);
        let held = registration_event(&holder, &alias, 1000);
        assert!(matches!(
            handle(svc, &held).result,
            WritePolicyResult::Accept
        ));

        let outsider = Keys::generate();
        // Dated after the holder (would lose the alias), dated before it
        // (would win it, the holder's seat being young at the clock these
        // are decided at), and under another alias while claiming the
        // holder's key with a valid proof (would lose a key conflict).
        let other_alias = "f".repeat(32);
        let attempts = [
            registration_event(&outsider, &alias, 2000),
            registration_event(&outsider, &alias, 500),
            registration_event_with_w(
                &outsider,
                &other_alias,
                2000,
                vec![key_entry(&holder, &outsider, &other_alias)],
            ),
        ];
        for attempt in &attempts {
            let outcome = handle_at(svc, attempt, WHILE_YOUNG);
            assert_eq!(refusal(&outcome), NOT_LISTED);
            assert!(outcome.prune.is_empty(), "nothing to prune");
            assert!(
                svc.conflict_alert_dedup
                    .lock()
                    .should_alert(&attempt.id.to_hex()),
                "no conflict alert may have been recorded for a refused sender"
            );
        }
        {
            let txn = svc.meta.read_txn().unwrap();
            let r = svc.meta.get_registration(&txn, &alias).unwrap().unwrap();
            assert_eq!(r.event_id, held.id.to_hex(), "the holder is untouched");
            assert!(svc
                .meta
                .get_registration(&txn, &other_alias)
                .unwrap()
                .is_none());
        }

        // A listed sender that loses the same conflict is told about the
        // conflict, its coordinate is pruned and the alert is recorded.
        let late = registration_event(&rival, &alias, 2000);
        let outcome = handle(svc, &late);
        assert_eq!(refusal(&outcome), "alias already registered");
        assert_eq!(
            outcome.prune,
            vec![(rival.public_key().to_hex(), alias.clone())]
        );
        assert!(!svc
            .conflict_alert_dedup
            .lock()
            .should_alert(&late.id.to_hex()));
    }

    /// The mode gates new seats only. An account that holds an alias and is
    /// not (or no longer) on the list can still replace its registration;
    /// what it cannot do is take a new alias.
    #[tokio::test]
    async fn lapsed_account_can_still_replace_its_registration() {
        use nostr_sdk::prelude::Keys;

        let someone_else = Keys::generate();
        let h = whitelist_harness(&[&someone_else]).await;
        let svc = &h.svc;
        let tenant = Keys::generate();
        let tenant_hex = tenant.public_key().to_hex();
        let alias = "1".repeat(32);

        // The seat as an earlier, more permissive configuration left it.
        let first = registration_event(&tenant, &alias, 3000);
        let held_aliases = vec![alias.clone()];
        svc.meta
            .with_write(|m, txn| {
                m.put_registration(
                    txn,
                    &alias,
                    &RegistrationRecord {
                        tenant_hex: tenant_hex.clone(),
                        event_id: first.id.to_hex(),
                        created_at: 3000,
                        w_keys: vec![tenant_hex.clone()],
                        aux_keys: vec![],
                        relays: vec![],
                        servers: vec![],
                        quota_class: None,
                        registered_at: 1,
                        tombstoned_at: None,
                        first_created_at: None,
                        first_event_id: None,
                    },
                )?;
                m.put_key_claim(txn, &tenant_hex, &alias)?;
                m.put_tenant_aliases(txn, &tenant_hex, &held_aliases)
            })
            .unwrap();

        let writer = Keys::generate();
        let newer = registration_event_with_w(
            &tenant,
            &alias,
            4000,
            vec![key_entry(&writer, &tenant, &alias)],
        );
        assert!(
            matches!(handle(svc, &newer).result, WritePolicyResult::Accept),
            "an account must keep control of the alias it holds"
        );
        {
            let txn = svc.meta.read_txn().unwrap();
            let r = svc.meta.get_registration(&txn, &alias).unwrap().unwrap();
            assert_eq!(r.event_id, newer.id.to_hex());
            assert_eq!(r.w_keys, vec![writer.public_key().to_hex()]);
        }

        // Its proofs are still verified.
        let forged = registration_event_with_w(
            &tenant,
            &alias,
            5000,
            vec![unprovable_entry(&Keys::generate(), &tenant)],
        );
        assert_eq!(refusal(&handle(svc, &forged)), PROOF_INVALID);

        // A new alias is a new seat, and the mode refuses it.
        let another = registration_event(&tenant, &"2".repeat(32), 4000);
        assert_eq!(refusal(&handle(svc, &another)), NOT_LISTED);
    }

    /// The write transaction asks for admission by itself, first: with the
    /// early check left out, a sender the mode refuses is still refused with
    /// the mode's message, before any conflict is looked at.
    #[tokio::test]
    async fn write_transaction_refuses_without_the_early_check() {
        use nostr_sdk::prelude::Keys;

        let holder = Keys::generate();
        let h = whitelist_harness(&[&holder]).await;
        let svc = &h.svc;
        let alias = "3".repeat(32);
        let held = registration_event(&holder, &alias, 1000);
        assert!(matches!(
            handle(svc, &held).result,
            WritePolicyResult::Accept
        ));

        let outsider = Keys::generate();
        // On the held alias (a conflict it would lose) and on a free one.
        for target in [alias.clone(), "4".repeat(32)] {
            let event = registration_event(&outsider, &target, 2000);
            let parsed = parse_shape(&event, &svc.cfg).expect("the shape is fine");
            let outcome = apply(svc, &event, &parsed, Admission::Live { now: WHILE_YOUNG });
            assert_eq!(refusal(&outcome), NOT_LISTED);
            assert!(outcome.prune.is_empty());
            assert!(svc
                .conflict_alert_dedup
                .lock()
                .should_alert(&event.id.to_hex()));
        }
        let txn = svc.meta.read_txn().unwrap();
        let r = svc.meta.get_registration(&txn, &alias).unwrap().unwrap();
        assert_eq!(r.event_id, held.id.to_hex());
        assert!(svc
            .meta
            .get_registration(&txn, &"4".repeat(32))
            .unwrap()
            .is_none());
    }

    /// A replay of the node's own stored events keeps the conflict checks
    /// ahead of the mode: a stored loser whose author is not admitted any
    /// more is still recognised as the loser, and its coordinate pruned.
    /// The mode is still asked for a seat the replay would create.
    #[tokio::test]
    async fn replay_keeps_the_conflict_checks_ahead_of_the_mode() {
        use nostr_sdk::prelude::Keys;

        let holder = Keys::generate();
        let h = whitelist_harness(&[&holder]).await;
        let svc = &h.svc;
        let alias = "5".repeat(32);
        let held = registration_event(&holder, &alias, 1000);
        assert!(matches!(
            handle(svc, &held).result,
            WritePolicyResult::Accept
        ));

        let outsider = Keys::generate();
        let leftover = registration_event(&outsider, &alias, 2000);
        let outcome = handle_replay(svc, &leftover, BEFORE_EVERY_SEAT);
        assert_eq!(refusal(&outcome), "alias already registered");
        assert_eq!(
            outcome.prune,
            vec![(outsider.public_key().to_hex(), alias.clone())]
        );

        // The same event arriving live is refused by the mode instead.
        assert_eq!(refusal(&handle(svc, &leftover)), NOT_LISTED);

        let fresh = registration_event(&outsider, &"6".repeat(32), 2000);
        let outcome = handle_replay(svc, &fresh, BEFORE_EVERY_SEAT);
        assert_eq!(refusal(&outcome), NOT_LISTED);
        assert!(outcome.prune.is_empty());
    }

    /// A node served under a mount path is named by host and path together:
    /// a registration that names the bare host, or another path on the host,
    /// does not list this node. A registration for a pair names two nodes,
    /// and this node only has to find itself among them.
    #[tokio::test]
    async fn registration_under_a_base_path_must_name_the_mount() {
        use nostr_sdk::prelude::Keys;

        let h = harness_with(|config| config.base_path = "/grasp".to_string()).await;
        let cfg = &h.svc.cfg;
        assert_eq!(cfg.service_address, "localhost:7334/grasp");
        let tenant = Keys::generate();
        let alias = "7".repeat(32);
        let named = |relays: &[&str], servers: &[&str]| {
            registration_event_naming(
                &tenant,
                &alias,
                1000,
                relays,
                servers,
                vec![vec![tenant.public_key().to_hex()]],
                Vec::new(),
            )
        };
        let relays_refusal = "registration relays tag must list this node";
        let server_refusal = "registration server tag must list this node";

        let bare = named(&["ws://localhost:7334"], &["http://localhost:7334"]);
        assert_eq!(shape_error(&bare, cfg), relays_refusal);
        let bare_server = named(&["ws://localhost:7334/grasp"], &["http://localhost:7334"]);
        assert_eq!(shape_error(&bare_server, cfg), server_refusal);
        let other_path = named(
            &["ws://localhost:7334/other"],
            &["http://localhost:7334/grasp"],
        );
        assert_eq!(shape_error(&other_path, cfg), relays_refusal);
        let child_path = named(
            &["ws://localhost:7334/grasp"],
            &["http://localhost:7334/grasp/blobs"],
        );
        assert_eq!(shape_error(&child_path, cfg), server_refusal);

        let mounted = named(
            &["ws://localhost:7334/grasp"],
            &["http://localhost:7334/grasp/"],
        );
        let parsed = parse_shape(&mounted, cfg).expect("the mounted URLs name this node");
        assert_eq!(parsed.relays, vec!["ws://localhost:7334/grasp"]);

        let pair = named(
            &["wss://other.example/grasp", "ws://localhost:7334/grasp"],
            &["https://other.example", "http://localhost:7334/grasp"],
        );
        assert!(parse_shape(&pair, cfg).is_ok());
        assert!(matches!(
            handle(&h.svc, &pair).result,
            WritePolicyResult::Accept
        ));
    }

    /// At the root of a domain nothing changes: the path of a URL is not
    /// compared, and a registration for a pair passes on finding this node.
    #[tokio::test]
    async fn registration_at_the_root_ignores_the_path() {
        use nostr_sdk::prelude::Keys;

        let h = harness().await;
        let cfg = &h.svc.cfg;
        let tenant = Keys::generate();
        let event = registration_event_naming(
            &tenant,
            &"8".repeat(32),
            1000,
            &["wss://other.example", "ws://localhost:7334/any/path"],
            &["http://localhost:7334/", "https://other.example/grasp"],
            vec![vec![tenant.public_key().to_hex()]],
            Vec::new(),
        );
        assert!(parse_shape(&event, cfg).is_ok());
    }

    // ------------------------------------------------------------------
    // Settled seats (D8). A seat whose first edition is more than
    // SEAT_SETTLE_SECS old keeps its alias and its keys against every
    // other account; a younger one merges by the order, as before; a
    // replay judges a seat it created by the order alone and one the meta
    // store held before it by its age. Except where a test says
    // otherwise, the clock is passed in, so the dates are free and the
    // tests do not depend on when they run.
    // ------------------------------------------------------------------

    /// The date these tests give the first edition of an established seat.
    const SEATED_AT: u64 = 100_000;

    /// Who holds `alias` in the meta store, and by which event.
    fn seated(svc: &PrivateService, alias: &str) -> Option<(String, String)> {
        let txn = svc.meta.read_txn().unwrap();
        svc.meta
            .get_registration(&txn, alias)
            .unwrap()
            .map(|record| (record.tenant_hex, record.event_id))
    }

    /// A backdated registration from another account takes no alias from a
    /// settled seat, where the merge order alone would hand it over. It
    /// gets the ordinary conflict answer, its own coordinate is pruned and
    /// the alert is raised; the warning says the seat had settled and names
    /// the challenger. The holder loses nothing: record, key claim, ring
    /// and blob claim stay.
    #[tokio::test]
    async fn settled_seat_keeps_its_alias_against_a_backdated_claim() {
        use super::super::claims;
        use super::super::meta::MetaEnv;
        use nostr_sdk::prelude::Keys;

        let h = harness().await;
        let svc = &h.svc;
        let holder = Keys::generate();
        let holder_hex = holder.public_key().to_hex();
        let alias = "a".repeat(32);

        let held = registration_event(&holder, &alias, SEATED_AT);
        assert!(matches!(
            handle_at(svc, &held, SEATED_AT).result,
            WritePolicyResult::Accept
        ));
        // What an eviction would strip: a state-root edition and a claim.
        let sha = "55".repeat(32);
        svc.meta
            .with_write(|m, txn| {
                m.put_state_ring(
                    txn,
                    &MetaEnv::state_ring_key(&alias, SEATED_AT + 60, "aa"),
                    "{}",
                )?;
                claims::attach_to(m, txn, &svc.cfg, &sha, &holder_hex, &alias, 512)
            })
            .unwrap();

        let challenger = Keys::generate();
        let backdated = registration_event(&challenger, &alias, 1);
        let (outcome, log) =
            logged(|| handle_at(svc, &backdated, SEATED_AT + SEAT_SETTLE_SECS + 1));
        assert_eq!(refusal(&outcome), "alias already registered");
        assert_eq!(
            outcome.prune,
            vec![(challenger.public_key().to_hex(), alias.clone())],
            "the challenger's own coordinate is pruned, as for any lost conflict"
        );
        assert!(log.contains("incumbent_settled=true"), "{log}");
        assert!(
            log.contains(&format!(
                "loser_tenant={}",
                challenger.public_key().to_hex()
            )),
            "the warning names the challenger: {log}"
        );
        assert!(
            !svc.conflict_alert_dedup
                .lock()
                .should_alert(&backdated.id.to_hex()),
            "the conflict alert was raised"
        );

        assert_eq!(
            seated(svc, &alias),
            Some((holder_hex.clone(), held.id.to_hex()))
        );
        let txn = svc.meta.read_txn().unwrap();
        assert_eq!(
            svc.meta.get_key_claim(&txn, &holder_hex).unwrap(),
            Some(alias.clone())
        );
        assert_eq!(
            svc.meta.state_ring_for_alias(&txn, &alias).unwrap().len(),
            1,
            "the holder's ring is kept"
        );
        let claim = svc.meta.get_blob_claim(&txn, &sha).unwrap().unwrap();
        assert_eq!(claim.aliases, vec![alias.clone()], "the claim is kept");
        assert_eq!(
            claim.charges.len(),
            1,
            "and so is the holder's charge for it"
        );
        assert!(claim.unreferenced_since.is_none());
    }

    /// The member case. Every writer of a repository holds its write key
    /// and every member its shared aux key, so any of them can register an
    /// alias of its own that claims that key, with a valid proof, dated
    /// before the repository. By the merge order that evicts the whole
    /// repository; against a settled seat it is refused, for a write key
    /// and for an aux key alike, and the repository keeps both keys.
    #[tokio::test]
    async fn settled_seat_keeps_its_keys_against_a_backdated_member() {
        use nostr_sdk::prelude::Keys;

        let h = harness().await;
        let svc = &h.svc;
        let own = ["ws://localhost:7334"];
        let own_server = ["http://localhost:7334"];
        let holder = Keys::generate();
        let writer = Keys::generate();
        let shared = Keys::generate();
        let alias = "b".repeat(32);
        let held = registration_event_naming(
            &holder,
            &alias,
            SEATED_AT,
            &own,
            &own_server,
            vec![key_entry(&writer, &holder, &alias)],
            vec![key_entry(&shared, &holder, &alias)],
        );
        assert!(matches!(
            handle_at(svc, &held, SEATED_AT).result,
            WritePolicyResult::Accept
        ));

        for (claimed, as_aux, member_alias) in [
            (&writer, false, "c".repeat(32)),
            (&shared, true, "d".repeat(32)),
        ] {
            let member = Keys::generate();
            let entry = key_entry(claimed, &member, &member_alias);
            let (w_entries, aux_entries) = if as_aux {
                (vec![vec![member.public_key().to_hex()]], vec![entry])
            } else {
                (vec![entry], Vec::new())
            };
            let claim = registration_event_naming(
                &member,
                &member_alias,
                1,
                &own,
                &own_server,
                w_entries,
                aux_entries,
            );
            let (outcome, log) =
                logged(|| handle_at(svc, &claim, SEATED_AT + SEAT_SETTLE_SECS + 1));
            assert_eq!(refusal(&outcome), "write key already registered");
            assert_eq!(
                outcome.prune,
                vec![(member.public_key().to_hex(), member_alias.clone())]
            );
            assert!(log.contains("incumbent_settled=true"), "{log}");
            assert_eq!(seated(svc, &member_alias), None);
        }

        assert_eq!(
            seated(svc, &alias),
            Some((holder.public_key().to_hex(), held.id.to_hex()))
        );
        let txn = svc.meta.read_txn().unwrap();
        for key in [&writer, &shared] {
            assert_eq!(
                svc.meta
                    .get_key_claim(&txn, &key.public_key().to_hex())
                    .unwrap(),
                Some(alias.clone())
            );
        }
    }

    /// A holder's own new edition (a widen dated just after its live one)
    /// that claims a key a settled seat of another account holds is refused
    /// like any challenger, and its own coordinate, which still holds its
    /// live registration, is not pruned.
    #[tokio::test]
    async fn settled_squat_refuses_a_widen_without_pruning_the_victim() {
        use nostr_sdk::prelude::Keys;

        let h = harness().await;
        let svc = &h.svc;
        let victim = Keys::generate();
        let squatter = Keys::generate();
        let rekey = Keys::generate();
        let (v_alias, s_alias) = ("7".repeat(32), "8".repeat(32));
        let live = registration_event(&victim, &v_alias, SEATED_AT - 500);
        assert!(matches!(
            handle_at(svc, &live, SEATED_AT - 500).result,
            WritePolicyResult::Accept
        ));
        let squat = registration_event_with_w(
            &squatter,
            &s_alias,
            SEATED_AT,
            vec![key_entry(&rekey, &squatter, &s_alias)],
        );
        assert!(matches!(
            handle_at(svc, &squat, SEATED_AT).result,
            WritePolicyResult::Accept
        ));
        let widen = registration_event_with_w(
            &victim,
            &v_alias,
            SEATED_AT - 499,
            vec![
                vec![victim.public_key().to_hex()],
                key_entry(&rekey, &victim, &v_alias),
            ],
        );
        let (outcome, log) = logged(|| handle_at(svc, &widen, SEATED_AT + SEAT_SETTLE_SECS + 1));
        assert_eq!(refusal(&outcome), "write key already registered");
        assert!(
            outcome.prune.is_empty(),
            "the victim's live coordinate stays"
        );
        assert!(log.contains("incumbent_settled=true"), "{log}");
        assert_eq!(
            seated(svc, &v_alias),
            Some((victim.public_key().to_hex(), live.id.to_hex()))
        );
        assert_eq!(
            seated(svc, &s_alias).map(|(tenant, _)| tenant),
            Some(squatter.public_key().to_hex())
        );
    }

    /// A registration that the order would let take a young alias, but that
    /// also claims a key a settled seat holds, is refused outright: the young
    /// holder is not evicted either, and the settled seat keeps its key.
    #[tokio::test]
    async fn a_settled_key_holder_refuses_a_claim_that_would_take_a_young_alias() {
        use nostr_sdk::prelude::Keys;

        let h = harness().await;
        let svc = &h.svc;
        let settled_at = SEATED_AT + SEAT_SETTLE_SECS + 1;
        let young = Keys::generate();
        let holder = Keys::generate();
        let writer = Keys::generate();
        let challenger = Keys::generate();
        let (young_alias, held_alias) = ("5".repeat(32), "6".repeat(32));

        let held = registration_event_with_w(
            &holder,
            &held_alias,
            SEATED_AT,
            vec![
                vec![holder.public_key().to_hex()],
                key_entry(&writer, &holder, &held_alias),
            ],
        );
        let fresh = registration_event(&young, &young_alias, settled_at - 60);
        for event in [&held, &fresh] {
            assert!(matches!(
                handle_at(svc, event, event.created_at.as_secs()).result,
                WritePolicyResult::Accept
            ));
        }

        let claim = registration_event_with_w(
            &challenger,
            &young_alias,
            SEATED_AT - 100,
            vec![
                vec![challenger.public_key().to_hex()],
                key_entry(&writer, &challenger, &young_alias),
            ],
        );
        let (outcome, log) = logged(|| handle_at(svc, &claim, settled_at));
        assert_eq!(refusal(&outcome), "write key already registered");
        assert_eq!(
            outcome.prune,
            vec![(challenger.public_key().to_hex(), young_alias.clone())]
        );
        assert!(log.contains("incumbent_settled=true"), "{log}");
        assert!(!log.contains("stored registration evicted"), "{log}");
        assert_eq!(
            seated(svc, &young_alias),
            Some((young.public_key().to_hex(), fresh.id.to_hex()))
        );
        let txn = svc.meta.read_txn().unwrap();
        assert_eq!(
            svc.meta
                .get_key_claim(&txn, &writer.public_key().to_hex())
                .unwrap(),
            Some(held_alias.clone())
        );
    }

    /// An older edition of the holder's own registration, sent again after a
    /// key it listed has passed to another account whose seat has since
    /// settled, changes no claim (a stale edition never evicts), so the
    /// settle rule has nothing to protect and the order alone judges it, as
    /// before seats settled. It is accepted as a no-op with no conflict
    /// warning naming the holder, the key stays where it is, and on a node
    /// that never saw it, it still lowers the holder's anchor.
    #[tokio::test]
    async fn a_stale_own_edition_is_not_refused_by_a_settled_seat() {
        use nostr_sdk::prelude::Keys;

        let holder = Keys::generate();
        let other = Keys::generate();
        let dropped = Keys::generate();
        let (alias, other_alias) = ("9".repeat(32), "a".repeat(32));
        let first = registration_event_with_w(
            &holder,
            &alias,
            SEATED_AT,
            vec![
                vec![holder.public_key().to_hex()],
                key_entry(&dropped, &holder, &alias),
            ],
        );
        let narrowed = registration_event(&holder, &alias, SEATED_AT + 50);
        let claim = registration_event_with_w(
            &other,
            &other_alias,
            SEATED_AT + 100,
            vec![
                vec![other.public_key().to_hex()],
                key_entry(&dropped, &other, &other_alias),
            ],
        );
        let settled = SEATED_AT + 100 + SEAT_SETTLE_SECS + 1;

        // A node that saw every edition, and one that joined after the first
        // edition had been replaced.
        for saw_first in [true, false] {
            let h = harness().await;
            let svc = &h.svc;
            let mut arrivals = vec![&narrowed, &claim];
            if saw_first {
                arrivals.insert(0, &first);
            }
            for event in arrivals {
                assert!(matches!(
                    handle_at(svc, event, event.created_at.as_secs()).result,
                    WritePolicyResult::Accept
                ));
            }

            let (outcome, log) = logged(|| handle_at(svc, &first, settled));
            assert!(matches!(outcome.result, WritePolicyResult::Accept));
            assert!(outcome.prune.is_empty());
            assert!(!log.contains("private registration conflict"), "{log}");
            assert_eq!(
                seated(svc, &alias),
                Some((holder.public_key().to_hex(), narrowed.id.to_hex()))
            );
            let txn = svc.meta.read_txn().unwrap();
            assert_eq!(
                svc.meta
                    .get_key_claim(&txn, &dropped.public_key().to_hex())
                    .unwrap(),
                Some(other_alias.clone())
            );
            let record = svc.meta.get_registration(&txn, &alias).unwrap().unwrap();
            assert_eq!(
                record.first_created_at,
                Some(nostr::prelude::Timestamp::from_secs(SEATED_AT))
            );
            assert_eq!(record.first_event_id, Some(first.id.to_hex()));
        }
    }

    /// Just under the settle age the merge order decides, as before seats
    /// settled: an hour old exactly, a seat is still young (it settles the
    /// next second, above). A claim dated before the holder takes the
    /// alias, or a key and with it the holder's whole registration, and the
    /// same pair of registrations leaves the same holder in either arrival
    /// order, which is what lets two nodes agree.
    #[tokio::test]
    async fn young_seat_still_merges_by_created_at() {
        use nostr_sdk::prelude::Keys;

        let young = SEATED_AT + SEAT_SETTLE_SECS;
        let holder = Keys::generate();
        let challenger = Keys::generate();
        let alias = "e".repeat(32);
        let held = registration_event(&holder, &alias, SEATED_AT);
        let earlier = registration_event(&challenger, &alias, SEATED_AT - 100);
        let winner = Some((challenger.public_key().to_hex(), earlier.id.to_hex()));

        // The holder arrives first: the earlier claim evicts it.
        let h = harness().await;
        assert!(matches!(
            handle_at(&h.svc, &held, SEATED_AT).result,
            WritePolicyResult::Accept
        ));
        let (outcome, log) = logged(|| handle_at(&h.svc, &earlier, young));
        assert!(matches!(outcome.result, WritePolicyResult::Accept));
        assert_eq!(
            outcome.prune,
            vec![(holder.public_key().to_hex(), alias.clone())]
        );
        assert!(log.contains("stored registration evicted"), "{log}");
        assert_eq!(seated(&h.svc, &alias), winner);

        // The earlier claim arrives first: the holder's registration is
        // refused by the order. By this clock the earlier seat is itself over
        // an hour old, but the order refuses first, so the warning does not
        // blame the settle rule.
        let h = harness().await;
        assert!(matches!(
            handle_at(&h.svc, &earlier, SEATED_AT).result,
            WritePolicyResult::Accept
        ));
        let (outcome, log) = logged(|| handle_at(&h.svc, &held, young));
        assert_eq!(refusal(&outcome), "alias already registered");
        assert!(log.contains("incumbent_settled=false"), "{log}");
        assert_eq!(seated(&h.svc, &alias), winner);

        // A member's claim of the shared aux key still evicts a young
        // repository.
        let h = harness().await;
        let own = ["ws://localhost:7334"];
        let own_server = ["http://localhost:7334"];
        let owner = Keys::generate();
        let shared = Keys::generate();
        let member = Keys::generate();
        let repo = "f".repeat(32);
        let member_alias = "0".repeat(32);
        let repo_registration = registration_event_naming(
            &owner,
            &repo,
            SEATED_AT,
            &own,
            &own_server,
            vec![vec![owner.public_key().to_hex()]],
            vec![key_entry(&shared, &owner, &repo)],
        );
        assert!(matches!(
            handle_at(&h.svc, &repo_registration, SEATED_AT).result,
            WritePolicyResult::Accept
        ));
        let claim = registration_event_naming(
            &member,
            &member_alias,
            SEATED_AT - 100,
            &own,
            &own_server,
            vec![vec![member.public_key().to_hex()]],
            vec![key_entry(&shared, &member, &member_alias)],
        );
        let outcome = handle_at(&h.svc, &claim, young);
        assert!(matches!(outcome.result, WritePolicyResult::Accept));
        assert_eq!(
            outcome.prune,
            vec![(owner.public_key().to_hex(), repo.clone())]
        );
        assert_eq!(seated(&h.svc, &repo), None);
        let txn = h.svc.meta.read_txn().unwrap();
        assert_eq!(
            h.svc
                .meta
                .get_key_claim(&txn, &shared.public_key().to_hex())
                .unwrap(),
            Some(member_alias.clone())
        );
    }

    /// `handle`, the path of clients and peers, judges a seat's age by the
    /// node's own clock: a seat first registered two hours ago is settled,
    /// one registered ten minutes ago is not.
    #[tokio::test]
    async fn handle_judges_seat_age_by_the_node_clock() {
        use nostr_sdk::prelude::Keys;

        let h = harness().await;
        let svc = &h.svc;
        let now = nostr::prelude::Timestamp::now().as_secs();
        for (alias, seated_at, settled) in [
            ("1".repeat(32), now - 2 * SEAT_SETTLE_SECS, true),
            ("2".repeat(32), now - 600, false),
        ] {
            let holder = Keys::generate();
            let challenger = Keys::generate();
            let held = registration_event(&holder, &alias, seated_at);
            assert!(matches!(
                handle(svc, &held).result,
                WritePolicyResult::Accept
            ));
            let backdated = registration_event(&challenger, &alias, seated_at - 100);
            let outcome = handle(svc, &backdated);
            let (tenant, _) = seated(svc, &alias).expect("the alias has a holder");
            if settled {
                assert_eq!(refusal(&outcome), "alias already registered");
                assert_eq!(tenant, holder.public_key().to_hex());
            } else {
                assert!(matches!(outcome.result, WritePolicyResult::Accept));
                assert_eq!(tenant, challenger.public_key().to_hex());
            }
        }
    }

    /// The trap the settle rule sets for a replay. A claim dated before a
    /// seat took it while the seat was minutes old, and the evicted
    /// holder's 30640 stayed in the relay database, as after a prune that
    /// failed. Long after, with both dates decades old by the real clock:
    ///
    /// - a restart over the same meta store keeps the winner; the leftover
    ///   is refused by the order and pruned, and sent again live it loses
    ///   by the order too, not to the settle rule;
    /// - a node whose meta store was wiped and is rebuilt from the relay
    ///   database seats the winner again. The rebuild replays the newest
    ///   event first, the evicted holder's; judged by the clock, that seat
    ///   would be settled from its first second and would refuse the
    ///   winner;
    /// - replayed by hand, the two events give the winner in either order.
    #[tokio::test]
    async fn replay_reaches_the_decision_made_while_the_seat_was_young() {
        use nostr_sdk::prelude::{Filter, Keys, Kind};

        let h = harness().await;
        let svc = &h.svc;
        let holder = Keys::generate();
        let challenger = Keys::generate();
        let alias = "3".repeat(32);
        let first = registration_event(&holder, &alias, 2_000);
        let backdated = registration_event(&challenger, &alias, 1_000);
        let winner = Some((challenger.public_key().to_hex(), backdated.id.to_hex()));

        assert!(matches!(
            handle_at(svc, &first, 2_000).result,
            WritePolicyResult::Accept
        ));
        svc.database
            .save_event(&first)
            .await
            .expect("save the holder's 30640");
        let outcome = handle_at(svc, &backdated, 2_300);
        assert!(matches!(outcome.result, WritePolicyResult::Accept));
        assert_eq!(
            outcome.prune,
            vec![(holder.public_key().to_hex(), alias.clone())]
        );
        svc.database
            .save_event(&backdated)
            .await
            .expect("save the winner's 30640");
        // The prune is not carried out: both 30640s stay in the database.

        // A restart over the same meta store.
        svc.boot_reconcile().await.expect("boot reconcile");
        assert_eq!(seated(svc, &alias), winner);
        let leftover = svc
            .database
            .query(
                Filter::new()
                    .kind(Kind::Custom(super::super::KIND_REGISTRATION))
                    .author(holder.public_key()),
            )
            .await
            .expect("query the relay database");
        assert!(leftover.is_empty(), "the replay prunes the leftover");
        let (outcome, log) = logged(|| handle(svc, &first));
        assert_eq!(refusal(&outcome), "alias already registered");
        assert!(log.contains("incumbent_settled=false"), "{log}");
        assert_eq!(seated(svc, &alias), winner);

        // A wiped meta store, rebuilt from a relay database that holds both
        // events again.
        svc.database
            .save_event(&first)
            .await
            .expect("put the leftover back");
        let rebuilt = harness_on(svc.database.clone(), |_| {}).await;
        assert_eq!(
            seated(&rebuilt.svc, &alias),
            winner,
            "a rebuilt node must seat the winner it seated before"
        );

        for order in [[&first, &backdated], [&backdated, &first]] {
            let fresh = harness().await;
            for event in order {
                handle_replay(&fresh.svc, event, BEFORE_EVERY_SEAT);
            }
            assert_eq!(seated(&fresh.svc, &alias), winner);
        }
    }

    /// A registration this node evicted once (through one of its keys) and
    /// failed to prune is still stored, and another account has since taken
    /// its alias and held it for over an hour. A restart over the same meta
    /// store replays the leftover against that seat, which was there before
    /// the replay began, so the seat is judged by its age as it would be
    /// live: the leftover is refused, and nothing is pruned, since a replay's
    /// refusal by age deletes nothing. By the order alone the older leftover
    /// would take the alias on this node and not on its peer. A seat the
    /// replay created itself, as in a rebuild, is judged by the order.
    #[tokio::test]
    async fn replay_judges_a_seat_it_did_not_create_by_its_age() {
        use nostr_sdk::prelude::Keys;

        let h = harness().await;
        let svc = &h.svc;
        let holder = Keys::generate();
        let alias = "e".repeat(32);
        let held = registration_event(&holder, &alias, SEATED_AT);
        assert!(matches!(
            handle_at(svc, &held, SEATED_AT).result,
            WritePolicyResult::Accept
        ));
        let holder_seat = seated(svc, &alias);

        // The leftover is dated before the seat; arriving live now, it would
        // be refused by the seat's age too, and its coordinate pruned.
        let challenger = Keys::generate();
        let backdated = registration_event(&challenger, &alias, 1);
        let live = handle_at(svc, &backdated, SEATED_AT + SEAT_SETTLE_SECS + 1);
        assert_eq!(refusal(&live), "alias already registered");
        assert_eq!(
            live.prune,
            vec![(challenger.public_key().to_hex(), alias.clone())]
        );

        let registered_at = {
            let txn = svc.meta.read_txn().unwrap();
            svc.meta
                .get_registration(&txn, &alias)
                .unwrap()
                .expect("the holder is seated")
                .registered_at
        };

        // A restart: the replay began after the node stored the seat.
        let outcome = handle_replay(svc, &backdated, registered_at + 1);
        assert_eq!(refusal(&outcome), "alias already registered");
        assert!(
            outcome.prune.is_empty(),
            "a replay's refusal by age deletes nothing: {:?}",
            outcome.prune
        );
        assert_eq!(seated(svc, &alias), holder_seat);

        // The seat counts as the replay's own when the replay began no
        // earlier than the node stored it: the order decides, and the older
        // claim takes the alias.
        let outcome = handle_replay(svc, &backdated, registered_at);
        assert!(matches!(outcome.result, WritePolicyResult::Accept));
        assert_eq!(
            seated(svc, &alias),
            Some((challenger.public_key().to_hex(), backdated.id.to_hex()))
        );
    }
}
