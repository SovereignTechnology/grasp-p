//! GRASP-P Phase-4b A3: exact-host matching between URL-bearing values and
//! the node's configured domain.
//!
//! The Phase-1 checks were substring `contains` matches, so both
//! `"wss://evil.com/x?example.com"` (domain smuggled into the query) and
//! `"example.com.attacker.tld"` (domain as a leading label of a hostile
//! host) passed as "listing this node". The checks here parse the value as
//! an absolute ws/wss/http/https URL and compare the HOST exactly.
//!
//! A node served under a mount path is named by its host and that path
//! together; [`url_denotes_service`] is the comparison for that, and at the
//! root of a domain it is the host comparison unchanged.

use url::Url;

/// Does `value` (expected to be an absolute ws/wss/http/https URL) denote
/// the node's configured `domain`?
///
/// Exact HOST equality — case-insensitive, trailing-dot normalized — against
/// the host part of `domain`; no subdomain wildcards. When `domain` carries
/// an explicit port (e.g. a `127.0.0.1:7334` test node), the URL's effective
/// port (explicit or scheme default) must also match; a port-less `domain`
/// matches on host alone. Scheme-less or otherwise unparseable values, and
/// non-ws/http schemes, never match (conservative reject).
pub fn url_denotes_domain(value: &str, domain: &str) -> bool {
    let Ok(url) = Url::parse(value.trim()) else {
        return false;
    };
    let default_port = match url.scheme() {
        "ws" | "http" => 80,
        "wss" | "https" => 443,
        _ => return false,
    };
    let Some(url_host) = url.host_str() else {
        return false;
    };
    let (domain_host, domain_port) = split_authority(domain);
    if normalize_host(url_host) != normalize_host(&domain_host) {
        return false;
    }
    match domain_port {
        None => true,
        Some(port) => url.port_or_known_default().unwrap_or(default_port) == port,
    }
}

/// Does `value` denote THIS service, mount path included?
///
/// `service_address` is the node's address without a scheme: the domain,
/// followed by the mount path when the node is served under one
/// (`Config::service_address`). The authority is compared exactly as
/// [`url_denotes_domain`] compares it. A node at the root of its domain
/// answers every path there, so the URL's path is not looked at. A node
/// under a mount path answers only below it: a URL naming the bare host, or
/// another path on the same host, reaches a different service or none, and
/// two services sharing a host must not take each other for themselves. So
/// there the URL's path, without trailing slashes, has to equal the mount
/// path. A query or a fragment does not change which service a URL reaches
/// and is not compared.
pub fn url_denotes_service(value: &str, service_address: &str) -> bool {
    if !url_denotes_domain(value, service_address) {
        return false;
    }
    let mount = mount_path(service_address);
    if mount.is_empty() {
        return true;
    }
    // The base path is validated at start-up to be in the form the URL
    // parser produces, so the two sides compare as text.
    Url::parse(value.trim()).is_ok_and(|url| url.path().trim_end_matches('/') == mount)
}

/// The mount path of a service address: everything from the first `/` after
/// the authority, without trailing slashes. Empty for a node at the root.
/// A path written into the domain setting itself is read as a mount path
/// too, since the node advertises its blob routes under it.
fn mount_path(service_address: &str) -> &str {
    let s = service_address.trim().trim_end_matches('/');
    let s = s.split_once("://").map_or(s, |(_, rest)| rest);
    s.find('/').map_or("", |at| &s[at..])
}

/// Split the configured domain (an authority: `host`, `host:port`, or
/// `[v6]:port`) into (host, port). Liberal on this side: trims whitespace,
/// trailing slashes, a stray scheme prefix, and any path suffix — the URL
/// side stays strict.
fn split_authority(domain: &str) -> (String, Option<u16>) {
    let d = domain.trim().trim_end_matches('/');
    let d = d.rsplit("://").next().unwrap_or(d);
    let d = d.split('/').next().unwrap_or(d);
    if let Some(rest) = d.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = &rest[..end];
            let port = rest[end + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse::<u16>().ok());
            return (host.to_string(), port);
        }
    }
    match d.rsplit_once(':') {
        Some((host, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (host.to_string(), p.parse::<u16>().ok())
        }
        _ => (d.to_string(), None),
    }
}

/// Case-insensitive, trailing-dot-normalized host comparison form. The
/// brackets of an IPv6 literal go too: a parsed URL keeps them and
/// `split_authority` drops them, and the two sides have to meet.
fn normalize_host(host: &str) -> String {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smuggled_domain_in_query_is_rejected() {
        assert!(!url_denotes_domain(
            "wss://evil.com/x?example.com",
            "example.com"
        ));
        assert!(!url_denotes_domain(
            "wss://evil.com/example.com",
            "example.com"
        ));
        assert!(!url_denotes_domain(
            "https://user:example.com@evil.com",
            "example.com"
        ));
    }

    #[test]
    fn attacker_suffix_host_is_rejected() {
        assert!(!url_denotes_domain(
            "example.com.attacker.tld",
            "example.com"
        ));
        assert!(!url_denotes_domain(
            "wss://example.com.attacker.tld",
            "example.com"
        ));
        // No subdomain wildcards: even legitimate subdomains do not match.
        assert!(!url_denotes_domain(
            "wss://relay.example.com",
            "example.com"
        ));
    }

    #[test]
    fn exact_host_is_accepted() {
        assert!(url_denotes_domain("wss://example.com", "example.com"));
        assert!(url_denotes_domain("https://example.com", "example.com"));
        assert!(url_denotes_domain("ws://example.com", "example.com"));
        assert!(url_denotes_domain("http://example.com", "example.com"));
        // Paths and explicit default ports do not matter — only the host.
        assert!(url_denotes_domain("wss://example.com/", "example.com"));
        assert!(url_denotes_domain(
            "wss://example.com:443/some/path",
            "example.com"
        ));
    }

    #[test]
    fn host_matching_is_case_and_trailing_dot_insensitive() {
        assert!(url_denotes_domain("wss://EXAMPLE.COM", "example.com"));
        assert!(url_denotes_domain("wss://example.com.", "example.com"));
        assert!(url_denotes_domain("wss://Example.Com.", "example.com"));
        assert!(url_denotes_domain("wss://example.com", "Example.Com."));
    }

    #[test]
    fn scheme_less_values_are_rejected() {
        assert!(!url_denotes_domain("example.com", "example.com"));
        assert!(!url_denotes_domain("example.com:443", "example.com:443"));
        assert!(!url_denotes_domain("//example.com", "example.com"));
        // Other schemes are not ws/wss/http/https references.
        assert!(!url_denotes_domain("ftp://example.com", "example.com"));
    }

    #[test]
    fn ported_domain_requires_the_same_effective_port() {
        // Exact host + port match.
        assert!(url_denotes_domain("ws://localhost:7334", "localhost:7334"));
        assert!(url_denotes_domain(
            "http://127.0.0.1:8080",
            "127.0.0.1:8080"
        ));
        // Same host, different port: a DIFFERENT node (loopback test pairs
        // rely on this — each node is host:port-distinct).
        assert!(!url_denotes_domain("ws://127.0.0.1:2222", "127.0.0.1:1111"));
        // Scheme-default port counts as the effective port.
        assert!(url_denotes_domain("wss://example.com", "example.com:443"));
        assert!(!url_denotes_domain("wss://example.com", "example.com:8443"));
        assert!(url_denotes_domain("ws://example.com:80", "example.com:80"));
    }

    #[test]
    fn ipv6_literal_domain_is_matched_without_its_brackets() {
        assert!(url_denotes_domain("https://[::1]:7334", "[::1]:7334"));
        assert!(!url_denotes_domain("https://[::2]:7334", "[::1]:7334"));
        assert!(!url_denotes_domain("https://[::1]:7335", "[::1]:7334"));
    }

    #[test]
    fn trailing_slash_and_whitespace_are_trimmed() {
        assert!(url_denotes_domain("wss://example.com/", "example.com/"));
        assert!(url_denotes_domain("  wss://example.com  ", "example.com"));
    }

    #[test]
    fn service_at_the_root_ignores_the_path() {
        for value in [
            "wss://example.com",
            "wss://example.com/",
            "https://example.com/grasp",
            "https://example.com:443/any/path?x=1",
        ] {
            assert!(url_denotes_service(value, "example.com"), "{value}");
            assert_eq!(
                url_denotes_service(value, "example.com"),
                url_denotes_domain(value, "example.com"),
                "{value}"
            );
        }
        // A trailing slash on the address is still the root.
        assert!(url_denotes_service("wss://example.com/x", "example.com/"));
        assert!(!url_denotes_service("wss://other.example", "example.com"));
        assert!(!url_denotes_service("example.com", "example.com"));
    }

    #[test]
    fn service_under_a_mount_path_requires_that_path() {
        let service = "example.com/grasp";
        assert!(url_denotes_service("wss://example.com/grasp", service));
        assert!(url_denotes_service("https://example.com/grasp", service));
        // The bare host is another service, or none.
        assert!(!url_denotes_service("wss://example.com", service));
        assert!(!url_denotes_service("wss://example.com/", service));
        // So is any other path on the same host: a sibling, a longer name
        // with the same start, a child, the same name in another case.
        assert!(!url_denotes_service("wss://example.com/other", service));
        assert!(!url_denotes_service("wss://example.com/graspy", service));
        assert!(!url_denotes_service("wss://example.com/grasp/x", service));
        assert!(!url_denotes_service("wss://example.com/Grasp", service));
        assert!(!url_denotes_service(
            "wss://example.com/x/../other",
            service
        ));
        // Dot segments are resolved before the comparison, as a client
        // resolves them before it connects.
        assert!(url_denotes_service("wss://example.com/x/../grasp", service));
    }

    #[test]
    fn mount_path_comparison_trims_trailing_slashes() {
        assert!(url_denotes_service(
            "wss://example.com/grasp/",
            "example.com/grasp"
        ));
        assert!(url_denotes_service(
            "wss://example.com/grasp//",
            "example.com/grasp"
        ));
        assert!(url_denotes_service(
            "wss://example.com/grasp",
            "example.com/grasp/"
        ));
        assert!(url_denotes_service(
            "wss://example.com/services/grasp/",
            "example.com/services/grasp"
        ));
        assert!(!url_denotes_service(
            "wss://example.com/services",
            "example.com/services/grasp"
        ));
        // A query does not change which service the URL reaches.
        assert!(url_denotes_service(
            "wss://example.com/grasp?x=1",
            "example.com/grasp"
        ));
    }

    #[test]
    fn mounted_service_still_compares_host_and_port() {
        assert!(!url_denotes_service(
            "wss://other.example/grasp",
            "example.com/grasp"
        ));
        assert!(!url_denotes_service(
            "wss://example.com.attacker.tld/grasp",
            "example.com/grasp"
        ));
        assert!(!url_denotes_service(
            "wss://evil.example/x?example.com/grasp",
            "example.com/grasp"
        ));
        assert!(url_denotes_service(
            "ws://127.0.0.1:7334/grasp",
            "127.0.0.1:7334/grasp"
        ));
        assert!(!url_denotes_service(
            "ws://127.0.0.1:7335/grasp",
            "127.0.0.1:7334/grasp"
        ));
        assert!(url_denotes_service(
            "wss://example.com/grasp",
            "example.com:443/grasp"
        ));
        assert!(!url_denotes_service(
            "wss://example.com/grasp",
            "example.com:8443/grasp"
        ));
        assert!(url_denotes_service(
            "https://[::1]:7334/grasp",
            "[::1]:7334/grasp"
        ));
        assert!(!url_denotes_service(
            "example.com/grasp",
            "example.com/grasp"
        ));
        assert!(!url_denotes_service(
            "ftp://example.com/grasp",
            "example.com/grasp"
        ));
    }

    #[test]
    fn mount_path_is_read_from_the_service_address() {
        assert_eq!(mount_path("example.com"), "");
        assert_eq!(mount_path("example.com/"), "");
        assert_eq!(mount_path("example.com:8443"), "");
        assert_eq!(mount_path("example.com/grasp"), "/grasp");
        assert_eq!(mount_path("example.com/grasp/"), "/grasp");
        assert_eq!(mount_path("127.0.0.1:7334/a/b"), "/a/b");
        assert_eq!(mount_path("[::1]:7334/grasp"), "/grasp");
        assert_eq!(mount_path("https://example.com/grasp"), "/grasp");
    }
}
