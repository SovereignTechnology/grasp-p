//! URL parsing for the GRASP-06 `/prs/` endpoint.
//!
//! Per the spec, the path layout is:
//!
//! ```text
//! /prs/<npub>/<identifier>.git/<subpath>
//! ```
//!
//! The submitter is always supplied as a bech32 `npub1...` — hex pubkeys
//! are rejected per the spec. The identifier is percent-decoded so URLs
//! like `/prs/<npub>/my%20repo.git/info/refs` resolve to the same
//! identifier as the standard endpoint stores on disk.

use nostr_sdk::prelude::*;

use crate::git::{percent_decode, validate_repository_identifier};
use crate::grasp06::paths::PRS_URL_PREFIX;

/// A parsed `/prs/<npub>/<id>.git/<subpath>` URL.
#[derive(Debug, Clone)]
pub struct PrsUrl {
    /// The submitter's public key, decoded from the `npub1...` URL segment.
    pub submitter: PublicKey,
    /// The percent-decoded NIP-34 `d` identifier (no `.git` suffix).
    pub identifier: String,
    /// Everything after `.git/` in the URL path. May be empty.
    pub subpath: String,
}

/// Parse a `/prs/<npub>/<identifier>.git/<subpath>` URL.
///
/// Returns `None` if the path is not in the `/prs/` URL space, if the
/// `<npub>` segment is not a valid bech32 npub, or if the second segment
/// does not end in `.git`. Identifiers are percent-decoded.
///
/// This intentionally rejects hex pubkeys: GRASP-06 specifies the URL
/// uses an `npub`, and accepting hex would silently change the on-disk
/// path layout assumed by [`crate::grasp06::paths::prs_repo_path`].
pub fn parse_prs_url(path: &str) -> Option<PrsUrl> {
    let path = path.strip_prefix('/').unwrap_or(path);

    // Require the literal `prs/` prefix.
    let rest = path.strip_prefix(PRS_URL_PREFIX)?;
    let rest = rest.strip_prefix('/')?;

    // Split off `<npub>/<id>.git/<subpath>` (subpath may be empty).
    let mut parts = rest.splitn(3, '/');
    let npub_segment = parts.next()?;
    let repo_segment = parts.next()?;
    let subpath = parts.next().unwrap_or("").to_string();

    if npub_segment.is_empty() || repo_segment.is_empty() {
        return None;
    }

    // Spec is npub-only: reject hex (and anything else that isn't a
    // valid bech32 npub).
    if !npub_segment.starts_with("npub1") {
        return None;
    }
    let submitter = PublicKey::from_bech32(npub_segment).ok()?;

    // `<identifier>.git` (URL-encoded). Decode then strip the suffix.
    let decoded = percent_decode(repo_segment);
    let identifier = decoded.strip_suffix(".git")?.to_string();
    if !validate_repository_identifier(&identifier) {
        return None;
    }

    Some(PrsUrl {
        submitter,
        identifier,
        subpath,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A valid bech32 npub for use in tests (generated once, deterministic).
    fn sample_npub() -> String {
        let keys = Keys::generate();
        keys.public_key().to_bech32().unwrap()
    }

    #[test]
    fn parses_info_refs() {
        let npub = sample_npub();
        let path = format!("/prs/{}/my-repo.git/info/refs", npub);
        let parsed = parse_prs_url(&path).expect("should parse");
        assert_eq!(parsed.identifier, "my-repo");
        assert_eq!(parsed.subpath, "info/refs");
        assert_eq!(parsed.submitter.to_bech32().unwrap(), npub);
    }

    #[test]
    fn parses_with_empty_subpath() {
        // Tolerate trailing `.git` with no subpath (e.g. `/prs/<npub>/<id>.git/`).
        let npub = sample_npub();
        let path = format!("/prs/{}/my-repo.git/", npub);
        let parsed = parse_prs_url(&path).expect("should parse");
        assert_eq!(parsed.subpath, "");
    }

    #[test]
    fn requires_trailing_dot_git() {
        let npub = sample_npub();
        assert!(parse_prs_url(&format!("/prs/{}/my-repo/info/refs", npub)).is_none());
    }

    #[test]
    fn rejects_hex_pubkey() {
        // 64-hex is a valid pubkey form but the spec wants bech32.
        let hex = "0".repeat(64);
        assert!(parse_prs_url(&format!("/prs/{}/my-repo.git/info/refs", hex)).is_none());
    }

    #[test]
    fn rejects_paths_outside_prs() {
        let npub = sample_npub();
        assert!(parse_prs_url(&format!("/{}/my-repo.git/info/refs", npub)).is_none());
        assert!(parse_prs_url("/").is_none());
        assert!(parse_prs_url("/prs/").is_none());
    }

    #[test]
    fn percent_decodes_identifier() {
        let npub = sample_npub();
        let path = format!("/prs/{}/my%20repo.git/info/refs", npub);
        let parsed = parse_prs_url(&path).expect("should parse");
        assert_eq!(parsed.identifier, "my repo");
    }

    #[test]
    fn rejects_unsafe_identifier_components() {
        let npub = sample_npub();
        for identifier in ["..", "%2E%2E", "a%2Fb", "a%5Cb"] {
            assert!(
                parse_prs_url(&format!("/prs/{npub}/{identifier}.git/info/refs")).is_none(),
                "accepted unsafe identifier {identifier:?}"
            );
        }
    }
}
