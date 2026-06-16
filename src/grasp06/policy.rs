//! Acceptance helpers for GRASP-06 PR / PR-Update events.
//!
//! Spec: <https://github.com/DanConwayDev/grasp/blob/main/06.md> (lines 21–24).
//!
//! Under GRASP-06 a relay MUST accept a kind 1618 (PR) or 1619 (PR Update)
//! event for a repository coordinate it has no accepted announcement for,
//! provided the event:
//!
//! 1. carries at least one `a` tag of the form `30617:<hex-pubkey>:<d-tag>`, AND
//! 2. carries at least one `clone` tag whose URL resolves to **this relay's**
//!    `/prs/<signer-npub>/<d-tag>.git` endpoint, where
//!    - `<signer-npub>` is the bech32 of the event's signer, and
//!    - `<d-tag>` matches the `d` value of one of the event's `a` tags.
//!
//! All other matching is intentionally strict: the relaxation must not fire
//! for a foreign-host clone URL, a mismatched signer, or a `<d>` not named in
//! any `a` tag. The negative audit test
//! `pr_event_rejected_when_clone_tag_does_not_name_prs_endpoint` guards this.
//!
//! This file holds *only* the relaxation predicate plus the strict clone-URL
//! comparator it needs. Wiring into the write policy lives in
//! [`crate::nostr::builder`].

use nostr_sdk::prelude::*;

use crate::config::Config;
use crate::git::percent_decode;
use crate::grasp06::paths::PRS_URL_PREFIX;

/// Returns true when `event` qualifies for the GRASP-06 PR acceptance
/// relaxation: kind is 1618 or 1619, an `a` tag of the form
/// `30617:<hex>:<d>` is present, and a `clone` tag names this relay's
/// `/prs/<signer-npub>/<d>.git` endpoint with `<d>` matching one of the
/// event's `a` tag d values.
///
/// The function is pure: it consults `event` and `config` only and performs
/// no I/O. Returns `false` if `config.grasp06_enable` is off, so callers can
/// invoke it unconditionally.
pub fn event_qualifies_for_pr_relaxation(event: &Event, config: &Config) -> bool {
    if !config.grasp06_enable {
        return false;
    }

    if !matches!(
        event.kind,
        Kind::GitPullRequest | Kind::GitPullRequestUpdate
    ) {
        return false;
    }

    let d_tags = collect_a_tag_d_values(event);
    if d_tags.is_empty() {
        return false;
    }

    for tag in event.tags.iter() {
        let parts = tag.clone().to_vec();
        if parts.first().map(String::as_str) != Some("clone") {
            continue;
        }
        for url in parts.iter().skip(1) {
            if clone_url_names_relays_prs_endpoint(url, &config.domain, &event.pubkey, &d_tags) {
                return true;
            }
        }
    }

    false
}

/// Extract `<d>` from every well-formed `a` tag of the form
/// `30617:<64-hex-pubkey>:<d>` on `event`. Malformed tags are silently
/// skipped — a malformed `a` tag must not crash, it just means the event
/// doesn't qualify on that tag.
fn collect_a_tag_d_values(event: &Event) -> Vec<String> {
    let mut out = Vec::new();
    for tag in event.tags.iter() {
        let parts = tag.clone().to_vec();
        if parts.len() < 2 || parts[0] != "a" {
            continue;
        }
        // `splitn(3, ':')` preserves any `:` inside the d-tag.
        let coord: Vec<&str> = parts[1].splitn(3, ':').collect();
        if coord.len() != 3 {
            continue;
        }
        if coord[0] != "30617" {
            continue;
        }
        if coord[1].len() != 64 || !coord[1].chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        if coord[2].is_empty() {
            continue;
        }
        out.push(coord[2].to_string());
    }
    out
}

/// Strictly check whether `url` is this relay's
/// `/prs/<signer-npub>/<d>.git` endpoint, for some `<d>` in `d_tags`.
///
/// Requirements (any failure → `false`):
///
/// - scheme is `http` or `https` (case-insensitive),
/// - authority (host plus optional port) equals `domain` case-insensitively,
/// - no query string and no fragment,
/// - path is exactly `/prs/<npub-segment>/<repo-segment>` after trimming
///   trailing `/`,
/// - `<repo-segment>` ends in `.git`,
/// - `<npub-segment>` decodes via [`PublicKey::from_bech32`] to `signer`,
/// - the percent-decoded part of `<repo-segment>` before `.git` matches one
///   of `d_tags`.
pub fn clone_url_names_relays_prs_endpoint(
    url: &str,
    domain: &str,
    signer: &PublicKey,
    d_tags: &[String],
) -> bool {
    // Scheme: http or https only, case-insensitive.
    let rest = if let Some(r) = strip_prefix_ignore_ascii_case(url, "http://") {
        r
    } else if let Some(r) = strip_prefix_ignore_ascii_case(url, "https://") {
        r
    } else {
        return false;
    };

    // Reject query strings and fragments outright.
    if rest.contains('?') || rest.contains('#') {
        return false;
    }

    // Split authority and path on the first `/`.
    let slash_idx = match rest.find('/') {
        Some(i) => i,
        None => return false,
    };
    let authority = &rest[..slash_idx];
    let path = &rest[slash_idx..]; // includes leading `/`.

    if !authority.eq_ignore_ascii_case(domain) {
        return false;
    }

    let path = path.trim_end_matches('/');

    let inner = match path.strip_prefix(&format!("/{}/", PRS_URL_PREFIX)) {
        Some(s) => s,
        None => return false,
    };

    // Exactly two segments: `<npub>` and `<repo>.git`.
    let segments: Vec<&str> = inner.split('/').collect();
    if segments.len() != 2 {
        return false;
    }
    let npub_segment = segments[0];
    let repo_segment = segments[1];

    if !npub_segment.starts_with("npub1") {
        return false;
    }
    let url_pubkey = match PublicKey::from_bech32(npub_segment) {
        Ok(pk) => pk,
        Err(_) => return false,
    };
    if url_pubkey != *signer {
        return false;
    }

    let d_encoded = match repo_segment.strip_suffix(".git") {
        Some(s) => s,
        None => return false,
    };
    if d_encoded.is_empty() {
        return false;
    }
    let d_decoded = percent_decode(d_encoded);

    d_tags.contains(&d_decoded)
}

/// Case-insensitive equivalent of `str::strip_prefix` for ASCII prefixes.
fn strip_prefix_ignore_ascii_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() < prefix.len() {
        return None;
    }
    let (head, tail) = s.split_at(prefix.len());
    if head.eq_ignore_ascii_case(prefix) {
        Some(tail)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_domain(domain: &str, enabled: bool) -> Config {
        Config {
            domain: domain.to_string(),
            grasp06_enable: enabled,
            ..Config::for_testing()
        }
    }

    fn pr_event(
        signer: &Keys,
        a_tags: &[(&str, &str)], // (hex_pubkey, identifier)
        clone_urls: &[&str],
        kind: Kind,
    ) -> Event {
        let mut builder = EventBuilder::new(kind, "test");
        for (pk_hex, ident) in a_tags {
            builder = builder.tag(Tag::custom(
                "a",
                vec![format!("30617:{}:{}", pk_hex, ident)],
            ));
        }
        // c tag is required by downstream policy but not by this predicate.
        builder = builder.tag(Tag::custom("c", vec!["0".repeat(40)]));
        if !clone_urls.is_empty() {
            builder = builder.tag(Tag::custom(
                "clone",
                clone_urls.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            ));
        }
        builder.finalize(signer).unwrap()
    }

    #[test]
    fn rejects_when_feature_disabled() {
        let signer = Keys::generate();
        let target_hex = Keys::generate().public_key().to_hex();
        let npub = signer.public_key().to_bech32().unwrap();
        let url = format!("http://relay.example/prs/{}/my-repo.git", npub);
        let event = pr_event(
            &signer,
            &[(&target_hex, "my-repo")],
            &[&url],
            Kind::GitPullRequest,
        );
        let cfg = config_with_domain("relay.example", false);
        assert!(!event_qualifies_for_pr_relaxation(&event, &cfg));
    }

    #[test]
    fn accepts_matching_pr_event() {
        let signer = Keys::generate();
        let target_hex = Keys::generate().public_key().to_hex();
        let npub = signer.public_key().to_bech32().unwrap();
        let url = format!("http://relay.example/prs/{}/my-repo.git", npub);
        let event = pr_event(
            &signer,
            &[(&target_hex, "my-repo")],
            &[&url],
            Kind::GitPullRequest,
        );
        let cfg = config_with_domain("relay.example", true);
        assert!(event_qualifies_for_pr_relaxation(&event, &cfg));
    }

    #[test]
    fn accepts_matching_pr_update_event() {
        let signer = Keys::generate();
        let target_hex = Keys::generate().public_key().to_hex();
        let npub = signer.public_key().to_bech32().unwrap();
        let url = format!("https://relay.example:8080/prs/{}/my-repo.git", npub);
        let event = pr_event(
            &signer,
            &[(&target_hex, "my-repo")],
            &[&url],
            Kind::GitPullRequestUpdate,
        );
        let cfg = config_with_domain("relay.example:8080", true);
        assert!(event_qualifies_for_pr_relaxation(&event, &cfg));
    }

    #[test]
    fn rejects_other_kinds() {
        let signer = Keys::generate();
        let target_hex = Keys::generate().public_key().to_hex();
        let npub = signer.public_key().to_bech32().unwrap();
        let url = format!("http://relay.example/prs/{}/my-repo.git", npub);
        let event = pr_event(
            &signer,
            &[(&target_hex, "my-repo")],
            &[&url],
            Kind::GitPatch,
        );
        let cfg = config_with_domain("relay.example", true);
        assert!(!event_qualifies_for_pr_relaxation(&event, &cfg));
    }

    #[test]
    fn rejects_foreign_host() {
        let signer = Keys::generate();
        let target_hex = Keys::generate().public_key().to_hex();
        let npub = signer.public_key().to_bech32().unwrap();
        let url = format!("https://other-relay.example/prs/{}/my-repo.git", npub);
        let event = pr_event(
            &signer,
            &[(&target_hex, "my-repo")],
            &[&url],
            Kind::GitPullRequest,
        );
        let cfg = config_with_domain("relay.example", true);
        assert!(!event_qualifies_for_pr_relaxation(&event, &cfg));
    }

    #[test]
    fn rejects_mismatched_signer_in_url() {
        let signer = Keys::generate();
        let other_npub = Keys::generate().public_key().to_bech32().unwrap();
        let target_hex = Keys::generate().public_key().to_hex();
        let url = format!("http://relay.example/prs/{}/my-repo.git", other_npub);
        let event = pr_event(
            &signer,
            &[(&target_hex, "my-repo")],
            &[&url],
            Kind::GitPullRequest,
        );
        let cfg = config_with_domain("relay.example", true);
        assert!(!event_qualifies_for_pr_relaxation(&event, &cfg));
    }

    #[test]
    fn rejects_d_not_in_a_tags() {
        let signer = Keys::generate();
        let target_hex = Keys::generate().public_key().to_hex();
        let npub = signer.public_key().to_bech32().unwrap();
        let url = format!("http://relay.example/prs/{}/wrong-repo.git", npub);
        let event = pr_event(
            &signer,
            &[(&target_hex, "my-repo")],
            &[&url],
            Kind::GitPullRequest,
        );
        let cfg = config_with_domain("relay.example", true);
        assert!(!event_qualifies_for_pr_relaxation(&event, &cfg));
    }

    #[test]
    fn rejects_url_with_query_string() {
        let signer = Keys::generate();
        let target_hex = Keys::generate().public_key().to_hex();
        let npub = signer.public_key().to_bech32().unwrap();
        let url = format!("http://relay.example/prs/{}/my-repo.git?foo=bar", npub);
        let event = pr_event(
            &signer,
            &[(&target_hex, "my-repo")],
            &[&url],
            Kind::GitPullRequest,
        );
        let cfg = config_with_domain("relay.example", true);
        assert!(!event_qualifies_for_pr_relaxation(&event, &cfg));
    }

    #[test]
    fn rejects_url_with_extra_path() {
        let signer = Keys::generate();
        let target_hex = Keys::generate().public_key().to_hex();
        let npub = signer.public_key().to_bech32().unwrap();
        let url = format!("http://relay.example/prs/{}/my-repo.git/info/refs", npub);
        let event = pr_event(
            &signer,
            &[(&target_hex, "my-repo")],
            &[&url],
            Kind::GitPullRequest,
        );
        let cfg = config_with_domain("relay.example", true);
        assert!(!event_qualifies_for_pr_relaxation(&event, &cfg));
    }

    #[test]
    fn rejects_when_no_clone_tag() {
        let signer = Keys::generate();
        let target_hex = Keys::generate().public_key().to_hex();
        let event = pr_event(
            &signer,
            &[(&target_hex, "my-repo")],
            &[],
            Kind::GitPullRequest,
        );
        let cfg = config_with_domain("relay.example", true);
        assert!(!event_qualifies_for_pr_relaxation(&event, &cfg));
    }

    #[test]
    fn rejects_when_no_a_tag() {
        let signer = Keys::generate();
        let npub = signer.public_key().to_bech32().unwrap();
        let url = format!("http://relay.example/prs/{}/my-repo.git", npub);
        let event = pr_event(&signer, &[], &[&url], Kind::GitPullRequest);
        let cfg = config_with_domain("relay.example", true);
        assert!(!event_qualifies_for_pr_relaxation(&event, &cfg));
    }

    #[test]
    fn rejects_malformed_a_tag_coord() {
        let signer = Keys::generate();
        let npub = signer.public_key().to_bech32().unwrap();
        let url = format!("http://relay.example/prs/{}/my-repo.git", npub);
        // Wrong kind in coord (30000 instead of 30617).
        let other_hex = Keys::generate().public_key().to_hex();
        let event = EventBuilder::new(Kind::GitPullRequest, "x")
            .tag(Tag::custom(
                "a",
                vec![format!("30000:{}:my-repo", other_hex)],
            ))
            .tag(Tag::custom("c", vec!["0".repeat(40)]))
            .tag(Tag::custom("clone", vec![url]))
            .finalize(&signer)
            .unwrap();
        let cfg = config_with_domain("relay.example", true);
        assert!(!event_qualifies_for_pr_relaxation(&event, &cfg));
    }

    #[test]
    fn accepts_with_trailing_slash_in_url() {
        let signer = Keys::generate();
        let target_hex = Keys::generate().public_key().to_hex();
        let npub = signer.public_key().to_bech32().unwrap();
        let url = format!("http://relay.example/prs/{}/my-repo.git/", npub);
        let event = pr_event(
            &signer,
            &[(&target_hex, "my-repo")],
            &[&url],
            Kind::GitPullRequest,
        );
        let cfg = config_with_domain("relay.example", true);
        assert!(event_qualifies_for_pr_relaxation(&event, &cfg));
    }

    #[test]
    fn accepts_case_insensitive_scheme_and_host() {
        let signer = Keys::generate();
        let target_hex = Keys::generate().public_key().to_hex();
        let npub = signer.public_key().to_bech32().unwrap();
        let url = format!("HTTP://Relay.EXAMPLE/prs/{}/my-repo.git", npub);
        let event = pr_event(
            &signer,
            &[(&target_hex, "my-repo")],
            &[&url],
            Kind::GitPullRequest,
        );
        let cfg = config_with_domain("relay.example", true);
        assert!(event_qualifies_for_pr_relaxation(&event, &cfg));
    }

    #[test]
    fn accepts_percent_encoded_identifier() {
        let signer = Keys::generate();
        let target_hex = Keys::generate().public_key().to_hex();
        let npub = signer.public_key().to_bech32().unwrap();
        // d = "my repo" → URL-encoded as "my%20repo".
        let url = format!("http://relay.example/prs/{}/my%20repo.git", npub);
        let event = pr_event(
            &signer,
            &[(&target_hex, "my repo")],
            &[&url],
            Kind::GitPullRequest,
        );
        let cfg = config_with_domain("relay.example", true);
        assert!(event_qualifies_for_pr_relaxation(&event, &cfg));
    }
}
