//! GRASP-P admission arms for `Nip34WritePolicy::admit_event`.
//!
//! The write policy calls [`admit`] only when the private-repo service is
//! installed (`NGIT_GRASP_P_REPOS_ENABLE=true`), after its blacklist and
//! deletion gates. Which stream-wrap kinds route here is decided in one place
//! (`PrivateService::accepts_*_stream_wrap_kind`), so the dual-accept window
//! (3359 + legacy 1059) can never diverge from the sync filters or the NIP-11
//! advert; its complement (`rejects_retired_wrap_kind`) refuses the legacy
//! kinds outright once the window closes, so they are never handed to the
//! weaker public related-event path.

use nostr_sdk::local_relay::WritePolicyResult;
use nostr_sdk::prelude::Event;

use super::PrivateService;
use crate::nostr::policy::reject_restricted;

/// Route a private-repo kind. `None` means the event is not one of GRASP-P's
/// kinds and the caller continues with its own dispatch.
///
/// Synced events (`is_synced`, loopback:0) get identical admission: a synced
/// 30640/30641/stream wrap must apply under the same rules. They only bypass
/// the per-write-key token bucket, which is a node-local DoS knob.
pub async fn admit(
    service: &PrivateService,
    event: &Event,
    is_synced: bool,
) -> Option<WritePolicyResult> {
    let kind = event.kind.as_u16();

    if kind == super::KIND_REGISTRATION {
        let result = service.handle_registration(event).await;
        // FS-2 (review L3-F4): a cadence-rejected same-tenant replacement is
        // held AND rejected to the client. The NIP-20 message still says
        // retry-later, but convergence must not depend on the client actually
        // retrying: the sync timer re-offers the held event after the bucket
        // refills. Dedup by event id makes the sync path's own hold a no-op.
        if let WritePolicyResult::Reject { ref message, .. } = result {
            if message.contains(super::registration::REPLACE_CADENCE_REJECT_MESSAGE) {
                service.sync_rejected().add_registration(event.clone());
            }
        }
        return Some(result);
    }

    if kind == super::KIND_STATE_ROOT {
        // Phase-4b A1: per-write-key token bucket, client submissions only.
        // A rate-limited 30641 is NOT added to the out-of-order hold: the
        // client retries.
        if !is_synced && !service.client_write_allowed(&event.pubkey.to_hex()) {
            crate::metrics::record_private_rate_limited("state_root");
            crate::metrics::record_private_event_rejected(super::KIND_STATE_ROOT);
            return Some(reject_restricted("rate-limited; retry later"));
        }
        let result = service.handle_state_root(event).await;
        // Phase 2 (design 1.4): a 30641 can be pushed BEFORE its authorizing
        // 30640 is known here. Hold the rejection keyed by target alias so
        // the 30640 reprocess hook can resurrect it.
        if !matches!(result, WritePolicyResult::Accept) {
            if let Some(alias) = d_tag(event) {
                service.sync_rejected().add_state_root(alias, event.clone());
            }
        }
        return Some(result);
    }

    if service.accepts_stream_wrap_kind(kind) {
        // Phase-4b A1: charged wraps and never-charged spam both spend one
        // token; a rate-limited wrap is rejected outright (no hold).
        if !is_synced && !service.client_write_allowed(&event.pubkey.to_hex()) {
            crate::metrics::record_private_rate_limited("wrap");
            crate::metrics::record_private_event_rejected(kind);
            return Some(reject_restricted("rate-limited; retry later"));
        }
        return Some(match service.try_handle_wrap(event, false).await {
            Some(result) => result,
            // Unregistered outer key: REJECT, never the public related-event
            // path. A GRASP-P node admits stream wraps only for outer authors
            // in w∪aux of a live registration. The wrap is still held keyed by
            // its outer author so a later 30640 registering that key
            // reprocesses it (design 1.4, out-of-order sync).
            None => {
                service
                    .sync_rejected()
                    .add_wrap(event.pubkey.to_hex(), event.clone());
                reject_restricted("unregistered key")
            }
        });
    }

    if service.accepts_ephemeral_stream_wrap_kind(kind) {
        // Ephemeral wraps are never quota-charged, so this bucket is their
        // only cost.
        if !is_synced && !service.client_write_allowed(&event.pubkey.to_hex()) {
            crate::metrics::record_private_rate_limited("ewrap");
            crate::metrics::record_private_event_rejected(kind);
            return Some(reject_restricted("rate-limited; retry later"));
        }
        return Some(match service.try_handle_wrap(event, true).await {
            Some(result) => result,
            // Never stored, so there is no out-of-order hold.
            None => reject_restricted("unregistered key"),
        });
    }

    if service.rejects_retired_wrap_kind(kind) {
        // NGIT_GRASP_P_ACCEPT_LEGACY_WRAP_KIND=false retires 1059/21059 on a
        // GRASP-P node: refuse them here rather than let them fall through to
        // the related-event policy, which would store any `a`/`e`-tagged
        // event from any key, uncapped and uncharged. Genuine NIP-59 gift
        // wraps go to inbox relays, never a git node. Nodes with GRASP-P
        // disabled never reach this and keep vanilla 1059 handling.
        crate::metrics::record_private_event_rejected(kind);
        return Some(reject_restricted(
            "legacy stream-wrap kind is not accepted on this node",
        ));
    }

    None
}

/// Phase-4b D3: NIP-56 report intake, observe-then-defer. Logs the event id,
/// the reporter and any sha256-looking tag values (the takedown evidence an
/// operator needs); the content is never logged. Admission then runs through
/// the related-event rules unchanged.
pub fn log_report(event: &Event) {
    let sha256_tags: Vec<String> = event
        .tags
        .iter()
        .flat_map(|tag| tag.clone().to_vec())
        .filter(|v| super::blossom_auth::is_lower_hex_64(v))
        .take(16)
        .collect();
    tracing::info!(
        event_id = %event.id.to_hex(),
        reporter = %event.pubkey.to_hex(),
        sha256_tags = ?sha256_tags,
        "NIP-56 report event received"
    );
    crate::metrics::record_private_report_event();
}

/// The first `d` tag value, the alias of a 30640/30641.
pub fn d_tag(event: &Event) -> Option<String> {
    event.tags.iter().find_map(|tag| {
        let v = tag.as_slice();
        if v.len() >= 2 && v[0] == "d" {
            Some(v[1].clone())
        } else {
            None
        }
    })
}
