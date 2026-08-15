use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use hyper::header::{AUTHORIZATION, WWW_AUTHENTICATE};
use hyper::{Request, Response, StatusCode};
use nostr_sdk::prelude::{Event, EventBuilder, FinalizeEvent, Keys, Kind, Tag};

use crate::config::Config;
use crate::git::{empty_body, GitResponseBody};
use crate::private::PrivateAccess;

const MAX_CLOCK_SKEW_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nip98Error {
    Missing,
    Malformed,
    Invalid,
    Restricted,
}

/// Validate the GRASP-08 repository-scoped NIP-98 credential.
///
/// This deliberately differs from generic NIP-98: the signed method is always
/// GET, the signed URL is the repository root, payload is ignored, and replay
/// is allowed during the 60-second validity window.
pub fn validate_request<B>(
    request: &Request<B>,
    canonical_repository_url: &str,
    access: &PrivateAccess,
) -> Result<(), Nip98Error> {
    let header = request
        .headers()
        .get(AUTHORIZATION)
        .ok_or(Nip98Error::Missing)?
        .to_str()
        .map_err(|_| Nip98Error::Malformed)?;
    let encoded = header
        .strip_prefix("Nostr ")
        .filter(|value| !value.is_empty())
        .ok_or(Nip98Error::Malformed)?;
    let json = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| Nip98Error::Malformed)?;
    let event = Event::from_json(json).map_err(|_| Nip98Error::Malformed)?;

    if event.kind != Kind::HttpAuth || event.verify().is_err() {
        return Err(Nip98Error::Invalid);
    }
    if !access.contains(&event.pubkey) {
        return Err(Nip98Error::Restricted);
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Nip98Error::Invalid)?
        .as_secs();
    if now.abs_diff(event.created_at.as_secs()) > MAX_CLOCK_SKEW_SECS {
        return Err(Nip98Error::Invalid);
    }

    let mut urls = event.tags.iter().filter_map(|tag| {
        let values = tag.clone().to_vec();
        (values.len() == 2 && values[0] == "u").then(|| values[1].clone())
    });
    if urls.next().as_deref() != Some(canonical_repository_url) || urls.next().is_some() {
        return Err(Nip98Error::Invalid);
    }

    let mut methods = event.tags.iter().filter_map(|tag| {
        let values = tag.clone().to_vec();
        (values.len() == 2 && values[0] == "method").then(|| values[1].clone())
    });
    if methods.next().as_deref() != Some("GET") || methods.next().is_some() {
        return Err(Nip98Error::Invalid);
    }

    Ok(())
}

/// Build the outbound Authorization header for a GRASP-08 peer fetch.
///
/// Signs exactly the profile [`validate_request`] checks: kind 27235 with one
/// `u` tag naming the repository root, one `method` tag of `GET`, and a fresh
/// timestamp (the peer allows 60 seconds of skew, so callers generate a new
/// header per subprocess invocation rather than caching one).
pub fn repository_credential_header(
    keys: &Keys,
    repository_root_url: &str,
) -> anyhow::Result<String> {
    let event = EventBuilder::new(Kind::HttpAuth, "")
        .tags([
            Tag::parse(["u", repository_root_url])?,
            Tag::parse(["method", "GET"])?,
        ])
        .finalize(keys)?;
    Ok(format!(
        "Nostr {}",
        base64::engine::general_purpose::STANDARD.encode(event.as_json())
    ))
}

/// Truncate a Smart HTTP fetch URL at the repository root the GRASP-08
/// credential must sign.
///
/// Identifiers may themselves contain `.git`, so like
/// [`canonical_repository_url`] the root ends at the LAST occurrence.
pub fn repository_root_from_fetch_url(url: &str) -> Option<String> {
    let end = url.rfind(".git")?.checked_add(4)?;
    url.get(..end).map(str::to_string)
}

/// Build the canonical absolute root URL signed by Git credentials.
pub fn canonical_repository_url(config: &Config, request_path: &str) -> Option<String> {
    // Identifiers may themselves contain `.git`; the route suffix is the last
    // occurrence before the Smart HTTP subpath.
    let end = request_path.rfind(".git")?.checked_add(4)?;
    let repository_path = request_path.get(..end)?;
    if !config.private_public_origin.trim().is_empty() {
        return Some(format!(
            "{}{repository_path}",
            config.private_public_origin.trim().trim_end_matches('/')
        ));
    }
    let scheme = if is_loopback_domain(&config.domain) {
        "http"
    } else {
        "https"
    };
    Some(format!("{scheme}://{}{repository_path}", config.domain))
}

/// Return the intentionally indistinguishable response for every auth failure.
pub fn unauthorized_response(config: &Config) -> Response<GitResponseBody> {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(
            WWW_AUTHENTICATE,
            format!("Nostr realm=\"{}\", method=\"GET\"", config.domain),
        )
        .body(empty_body())
        .expect("static unauthorized response")
}

fn is_loopback_domain(domain: &str) -> bool {
    let host = domain
        .strip_prefix('[')
        .and_then(|value| value.split_once(']').map(|(host, _)| host))
        .unwrap_or_else(|| domain.split(':').next().unwrap_or(domain));
    host.eq_ignore_ascii_case("localhost")
        || host == "::1"
        || host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| ip.is_loopback())
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD;
    use hyper::Request;
    use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys, Tag, Timestamp};

    use super::*;

    fn credential(
        keys: &Keys,
        url: &str,
        method: &str,
        created_at: Timestamp,
        extra_tags: Vec<Tag>,
    ) -> String {
        let mut tags = vec![
            Tag::parse(["u", url]).unwrap(),
            Tag::parse(["method", method]).unwrap(),
        ];
        tags.extend(extra_tags);
        let event = EventBuilder::new(Kind::HttpAuth, "")
            .tags(tags)
            .custom_created_at(created_at)
            .finalize(keys)
            .unwrap();
        format!("Nostr {}", STANDARD.encode(event.as_json()))
    }

    #[test]
    fn accepts_reusable_get_credential_and_ignores_payload() {
        let keys = Keys::generate();
        let access = PrivateAccess::new([keys.public_key()]);
        let url = "https://private.example/npub/repo.git";
        let auth = credential(
            &keys,
            url,
            "GET",
            Timestamp::now(),
            vec![Tag::parse(["payload", "not-validated"]).unwrap()],
        );
        let request = Request::post("/npub/repo.git/git-receive-pack")
            .header(AUTHORIZATION, auth)
            .body(())
            .unwrap();

        assert_eq!(validate_request(&request, url, &access), Ok(()));
        assert_eq!(validate_request(&request, url, &access), Ok(()));
    }

    #[test]
    fn rejects_wrong_method_url_member_and_duplicate_required_tags() {
        let member = Keys::generate();
        let outsider = Keys::generate();
        let access = PrivateAccess::new([member.public_key()]);
        let url = "https://private.example/npub/repo.git";

        for auth in [
            credential(&member, url, "POST", Timestamp::now(), vec![]),
            credential(
                &member,
                "https://private.example/npub/other.git",
                "GET",
                Timestamp::now(),
                vec![],
            ),
            credential(&outsider, url, "GET", Timestamp::now(), vec![]),
            credential(
                &member,
                url,
                "GET",
                Timestamp::now(),
                vec![Tag::parse(["u", url]).unwrap()],
            ),
        ] {
            let request = Request::get("/")
                .header(AUTHORIZATION, auth)
                .body(())
                .unwrap();
            assert!(validate_request(&request, url, &access).is_err());
        }
    }

    #[test]
    fn outbound_credential_round_trips_through_validation() {
        let keys = Keys::generate();
        let access = PrivateAccess::new([keys.public_key()]);
        let root = repository_root_from_fetch_url(
            "http://127.0.0.1:7334/npub/repo.git/info/refs?service=git-upload-pack",
        )
        .expect("repository root");
        assert_eq!(root, "http://127.0.0.1:7334/npub/repo.git");
        assert_eq!(
            repository_root_from_fetch_url("https://h.example/npub/repo.git-tools.git/info/refs")
                .as_deref(),
            Some("https://h.example/npub/repo.git-tools.git")
        );

        let header = repository_credential_header(&keys, &root).expect("credential header");
        let request = Request::get("/npub/repo.git/info/refs")
            .header(AUTHORIZATION, header)
            .body(())
            .unwrap();
        assert_eq!(validate_request(&request, &root, &access), Ok(()));
        // The same credential must not authorize a different repository root.
        assert!(
            validate_request(&request, "http://127.0.0.1:7334/npub/other.git", &access).is_err()
        );
    }

    #[test]
    fn canonical_url_uses_http_only_for_loopback() {
        let mut config = Config::for_testing();
        config.domain = "127.0.0.1:7334".into();
        assert_eq!(
            canonical_repository_url(&config, "/npub/repo.git/info/refs").as_deref(),
            Some("http://127.0.0.1:7334/npub/repo.git")
        );
        config.domain = "private.example".into();
        assert_eq!(
            canonical_repository_url(&config, "/npub/repo.git/git-upload-pack").as_deref(),
            Some("https://private.example/npub/repo.git")
        );
        config.private_public_origin = "http://10.0.0.5:8080".into();
        assert_eq!(
            canonical_repository_url(&config, "/npub/repo.git/info/refs?service=x").as_deref(),
            Some("http://10.0.0.5:8080/npub/repo.git")
        );
    }

    #[test]
    fn canonical_url_preserves_git_inside_identifier() {
        let mut config = Config::for_testing();
        config.private_public_origin = "https://private.example".into();
        assert_eq!(
            canonical_repository_url(&config, "/npub/repository.git-tools.git/info/refs")
                .as_deref(),
            Some("https://private.example/npub/repository.git-tools.git")
        );
    }

    #[test]
    fn every_failure_response_is_empty_401_with_challenge() {
        let config = Config::for_testing();
        let response = unauthorized_response(&config);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers()[WWW_AUTHENTICATE],
            "Nostr realm=\"localhost:7334\", method=\"GET\""
        );
    }
}
