//! Single-URL hygiene for peer-advertised NIP-65 sync targets.
//!
//! Kind 10002 relay lists are untrusted input: any author whose events an
//! accepted repository references can advertise arbitrary relay URLs. One
//! observed author advertised 983 URLs, mostly machine-generated path
//! variants layered onto real relay hostnames. Every relay URL extracted
//! from a kind 10002 event must pass [`rejection_reason`] before it may
//! occupy a selection slot, overlay entry, probe queue position, or metric
//! anywhere in the sync subsystem.
//!
//! These are single-URL rejection rules. They never reject the containing
//! kind 10002 event, never merge distinct URLs by hostname, IP, TLS, NIP-11,
//! or NIP-66, and never strip queries or fragments to infer identity.
//! Legitimate path-based relays (`/inbox`, `/outbox`, `/chat`, language
//! paths, versioned paths, semantic query endpoints) are accepted unless
//! they independently match one of the explicit rules.
//!
//! Operator-configured relays (fallback, index, and bootstrap relays) are
//! trusted input and must not be routed through this filter.
//!
//! Provenance:
//!
//! - The generated-path word rule is copied from nostr-watch
//!   (<https://github.com/sandwichfarm/nostr-watch>), which found that ~69%
//!   of its production relay database (20,938 of 30,177 rows) consisted of
//!   URLs matching this rule, purged them, and now rejects them at
//!   ingestion. See [`NOSTR_WATCH_SPAM_WORDS`] for the inspected revision.
//!   ngit-grasp intends to review upstream changes to this rule
//!   periodically.
//! - The 64-hex path segment, repeated-hostname, and URL-length rules are
//!   ngit-grasp hardening informed by the 2026-08-19 relay-corpus
//!   investigation. They are not part of nostr-watch and carry no upstream
//!   production evidence.
//! - The `.onion` rule is an explicit temporary mailbox policy. The
//!   outbound target policy already refuses to dial `.onion` destinations,
//!   but rejecting them at extraction keeps hidden services from occupying
//!   selection slots, overlays, queues, and metrics. Revisit if Tor support
//!   lands.

use nostr::types::url::{RelayUrl, Url};

use crate::outbound::{OutboundTargetKind, OutboundTargetPolicy};

/// Ceiling on the serialized length of a peer-advertised relay URL.
///
/// ngit-grasp hardening: genuine relay URLs observed in production are two
/// orders of magnitude shorter; anything near this bound is either garbage
/// or an attempt to bloat per-relay state.
pub const MAX_PEER_RELAY_URL_BYTES: usize = 2048;

/// nostr-watch's 52-word generated-path list, copied verbatim from
/// `libraries/db/src/nato-purge.ts` (`SPAM_WORDS`) in
/// <https://github.com/sandwichfarm/nostr-watch>, branch `next`, revision
/// `c34f2be4f3b8133cb73be5e419eddabd02093cde` (inspected 2026-08-19). The
/// same rule guards upstream ingestion in
/// `libraries/nostrings/src/relay-urls.ts` (`isNatoPhoneticSpam`).
const NOSTR_WATCH_SPAM_WORDS: [&str; 52] = [
    // NATO phonetic alphabet (26)
    "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet",
    "kilo", "lima", "mike", "november", "oscar", "papa", "quebec", "romeo", "sierra", "tango",
    "uniform", "victor", "whiskey", "xray", "yankee", "zulu",
    // Custom words used by the same bot network (26)
    "anchor", "beacon", "cipher", "dynamo", "ember", "flint", "glyph", "haven", "ivory", "jade",
    "karma", "lantern", "marble", "nexus", "onyx", "prism", "quartz", "raven", "sable", "titan",
    "umbra", "vertex", "warden", "xenon", "yonder", "zenith",
];

/// Why a peer-advertised relay URL may not become an outbound sync target,
/// or `None` when it is acceptable.
///
/// The static outbound checks honour the policy's test-only permissive
/// mode; the remaining rules apply unconditionally because they describe
/// hostile or unusable peer input, not network topology.
pub fn rejection_reason(relay: &RelayUrl, policy: &OutboundTargetPolicy) -> Option<String> {
    let serialized = relay.as_str();
    if serialized.len() > MAX_PEER_RELAY_URL_BYTES {
        return Some(format!(
            "URL length {} exceeds {MAX_PEER_RELAY_URL_BYTES} bytes",
            serialized.len()
        ));
    }

    // Existing static outbound-target safety checks: scheme allowlist,
    // embedded credentials, usable port, local hostnames, non-globally
    // reachable IP literals. DNS answers are still re-vetted at dial time.
    let target = match policy.authorize(OutboundTargetKind::EventRelay, serialized) {
        Ok(target) => target,
        Err(reason) => return Some(reason),
    };

    if target.host == "onion" || target.host.ends_with(".onion") {
        return Some("onion service is not an accepted mailbox target".to_string());
    }

    let Ok(parsed) = Url::parse(serialized) else {
        // `authorize` already parsed this URL, so disagreement between the
        // two parses is itself grounds to refuse the input.
        return Some("URL failed re-parsing".to_string());
    };
    let segments: Vec<&str> = parsed
        .path_segments()
        .map(Iterator::collect)
        .unwrap_or_default();

    if segments
        .iter()
        .any(|segment| segment.len() == 64 && segment.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Some("path segment is a 64-hex identifier".to_string());
    }

    if segments
        .iter()
        .any(|segment| segment.eq_ignore_ascii_case(&target.host))
    {
        return Some("hostname repeated as a path segment".to_string());
    }

    // nostr-watch's exact rule: the final non-empty path segment, split into
    // one to three hyphen-separated tokens, compared case-insensitively,
    // rejects only when every token is in the 52-word set. The URL itself is
    // never lowercased or otherwise mutated.
    if let Some(last) = segments.iter().rev().find(|segment| !segment.is_empty()) {
        let tokens: Vec<&str> = last.split('-').collect();
        if tokens.len() <= 3
            && tokens.iter().all(|token| {
                NOSTR_WATCH_SPAM_WORDS
                    .iter()
                    .any(|word| token.eq_ignore_ascii_case(word))
            })
        {
            return Some("path matches the nostr-watch generated-relay word rule".to_string());
        }
    }

    None
}

/// Filter adapter for NIP-65 extraction.
///
/// Rejections log at debug level only: a hostile relay list controls how
/// often this fires, so it must not amplify into INFO-level log volume.
pub fn accepts(relay: &RelayUrl, policy: &OutboundTargetPolicy) -> bool {
    match rejection_reason(relay, policy) {
        Some(reason) => {
            tracing::debug!(relay = %relay, %reason, "rejected peer-advertised relay target");
            false
        }
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(url: &str) -> RelayUrl {
        RelayUrl::parse(url).unwrap_or_else(|error| panic!("{url} must parse: {error}"))
    }

    fn strict() -> OutboundTargetPolicy {
        OutboundTargetPolicy {
            allow_non_global: false,
        }
    }

    fn permissive() -> OutboundTargetPolicy {
        OutboundTargetPolicy {
            allow_non_global: true,
        }
    }

    fn rejected(url: &str) -> bool {
        rejection_reason(&relay(url), &strict()).is_some()
    }

    #[test]
    fn legitimate_relay_urls_are_accepted() {
        for url in [
            "wss://relay.damus.io",
            "wss://relay.example.com/",
            "ws://relay.example.com:8080",
            // Path-based relays are real (HAVEN, language relays, filtered
            // views, versioned mounts) and must survive.
            "wss://haven.example.com/inbox",
            "wss://haven.example.com/outbox",
            "wss://haven.example.com/chat",
            "wss://lang.relays.land/ja",
            "wss://relay.nostr.band/all",
            "wss://relay.example.com/v1",
            "wss://relay.example.com/nostr",
            // Semantic query strings stay distinct targets.
            "wss://filter.example.com/npub1aeh2zw4elewy5682lxc6xnlqzjnxksq303gwu2npfaxd49vmde6qcq4nwx?broadcast=true",
        ] {
            assert_eq!(
                rejection_reason(&relay(url), &strict()),
                None,
                "{url} must be accepted"
            );
        }
    }

    #[test]
    fn nostr_watch_word_rule_rejects_generated_paths() {
        for url in [
            "wss://relay.example.com/alpha",
            "wss://relay.example.com/alpha/",
            "wss://relay.example.com/Alpha",
            "wss://relay.example.com/ALPHA-BRAVO",
            "wss://relay.example.com/delta-echo-foxtrot",
            // Upstream 52-word members beyond the NATO alphabet.
            "wss://relay.example.com/nexus",
            "wss://relay.example.com/vertex",
            "wss://relay.example.com/titan",
            "wss://relay.example.com/warden-umbra",
            // Only the final non-empty segment is inspected.
            "wss://relay.example.com/sub/foxtrot-yonder",
        ] {
            assert!(rejected(url), "{url} must be rejected");
        }
    }

    #[test]
    fn nostr_watch_word_rule_matches_exactly() {
        for url in [
            // Four tokens are deliberately allowed upstream.
            "wss://relay.example.com/alpha-bravo-charlie-delta",
            // Every token must match, not just one.
            "wss://relay.example.com/alpha-notaword",
            // Whole-token comparison, not substring.
            "wss://relay.example.com/alphabet",
            // A word-list segment that is not final does not reject.
            "wss://relay.example.com/alpha/real",
        ] {
            assert_eq!(
                rejection_reason(&relay(url), &strict()),
                None,
                "{url} must be accepted"
            );
        }
    }

    #[test]
    fn hex64_path_segments_are_rejected() {
        let hex = "a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0a1b2c3d4e5f6a7b8c9d0a1b2";
        assert_eq!(hex.len(), 64);
        assert!(rejected(&format!("wss://relay.example.com/{hex}")));
        assert!(rejected(&format!(
            "wss://relay.example.com/{}",
            hex.to_uppercase()
        )));
        // Any complete segment matches, not only the final one.
        assert!(rejected(&format!("wss://relay.example.com/{hex}/sub")));
        // 63 hex characters or a non-hex character do not.
        assert!(!rejected(&format!("wss://relay.example.com/{}", &hex[1..])));
        assert!(!rejected(&format!(
            "wss://relay.example.com/g{}",
            &hex[1..]
        )));
    }

    #[test]
    fn repeated_hostname_path_segments_are_rejected() {
        assert!(rejected("wss://relay.example.com/relay.example.com"));
        assert!(rejected("wss://relay.example.com/x/Relay.Example.Com"));
        // A different hostname or a partial repetition is not a match.
        assert!(!rejected("wss://relay.example.com/other.example.com"));
        assert!(!rejected("wss://relay.example.com/relay.example"));
    }

    #[test]
    fn oversized_urls_are_rejected() {
        let base = "wss://relay.example.com/";
        let at_limit = format!(
            "{base}{}",
            "a".repeat(MAX_PEER_RELAY_URL_BYTES - base.len())
        );
        assert_eq!(at_limit.len(), MAX_PEER_RELAY_URL_BYTES);
        assert!(!rejected(&at_limit));
        assert!(rejected(&format!("{at_limit}a")));
    }

    #[test]
    fn onion_targets_are_rejected_under_every_policy() {
        for url in [
            "ws://hidden.onion",
            "wss://sub.hidden.onion",
            "ws://HIDDEN.ONION",
        ] {
            assert!(rejected(url), "{url} must be rejected");
            assert!(
                rejection_reason(&relay(url), &permissive()).is_some(),
                "{url} must be rejected even by the permissive test policy"
            );
        }
    }

    #[test]
    fn static_outbound_checks_apply() {
        for url in [
            "ws://127.0.0.1:7334",
            "wss://user:secret@relay.example.com",
            "ws://relay.local",
            "ws://intranet",
        ] {
            assert!(rejected(url), "{url} must be rejected");
        }
        // Integration tests rely on loopback relays under the permissive
        // policy; credentials stay forbidden regardless.
        assert_eq!(
            rejection_reason(&relay("ws://127.0.0.1:7334"), &permissive()),
            None
        );
        assert!(
            rejection_reason(&relay("wss://user:secret@relay.example.com"), &permissive())
                .is_some()
        );
    }
}
