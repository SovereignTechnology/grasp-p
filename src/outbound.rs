//! Outbound target policy for event-directed network connections.
//!
//! Repository announcements, state events, and PR events are untrusted input:
//! anyone can publish them. Their `relays` and `clone` tags feed the proactive
//! sync subsystem, which opens WebSocket connections and spawns `git fetch`
//! subprocesses toward the listed URLs. Without a policy, a crafted event can
//! direct a public relay at loopback, private, link-local, or otherwise
//! non-globally-reachable infrastructure (SSRF). This was observed in
//! production: event-directed sync attempted connections to
//! `ws://localhost:3334`, `ws://127.0.0.1:7334`, and `ws://100.125.184.46:7334`
//! (a CGNAT/tailnet address).
//!
//! This module provides one fail-closed policy that every outbound sink calls
//! immediately before connecting or fetching:
//!
//! - [`OutboundTargetPolicy::authorize`] - syntactic authorization: scheme
//!   allowlist per target kind, no credentials, no local hostnames, and
//!   globally reachable IP literals.
//! - [`OutboundTargetPolicy::authorize_resolved`] - the same checks plus DNS
//!   resolution: every resolved address must be globally reachable. The
//!   resolved addresses are returned so callers that can pin them (git via
//!   `http.curloptResolve`) avoid a second, unchecked DNS lookup.
//!
//! Operator-configured targets (the bootstrap relay, the relay's own bind
//! address) are trusted and bypass the reachability requirement via
//! [`RelayTargetSource::OperatorConfigured`]. Event-provided URLs never
//! inherit that exception, even when they resemble the configured value:
//! trust is carried by the source of the URL, not by URL comparison.
//!
//! The module also provides [`url_matches_service_domain`] for service
//! ownership checks (GRASP-01 admission and don't-fetch-from-ourselves
//! filtering). It compares parsed host and port semantics so that
//! `gitnostr.com.attacker.example` or `https://evil.example/gitnostr.com/`
//! cannot satisfy a check for `gitnostr.com`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// The `url` crate is re-exported wholesale by `nostr` (types::url does
// `pub use url::*`), so no direct dependency is needed.
use nostr::types::url::{Host, ParseError, Url};

/// What kind of outbound connection an event-directed URL is about to make.
///
/// The kind selects the scheme allowlist; all other checks are shared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboundTargetKind {
    /// WebSocket relay connection (`ws://` / `wss://`).
    EventRelay,
    /// Git smart-HTTP fetch (`http://` / `https://`).
    EventGit,
}

/// Who supplied a relay URL, and therefore how much it is trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayTargetSource {
    /// The operator configured this exact target (e.g. the bootstrap relay).
    /// It may point at local infrastructure; that is the operator's call.
    OperatorConfigured,
    /// The target came from an untrusted Nostr event and must satisfy the
    /// outbound target policy before every connection attempt.
    EventDirected,
}

/// Fail-closed policy for event-directed outbound targets.
#[derive(Debug, Clone, Copy, Default)]
pub struct OutboundTargetPolicy {
    /// Permit targets that are not globally reachable (loopback, private,
    /// link-local addresses and local hostnames) and skip DNS vetting.
    ///
    /// This exists for integration tests and closed development networks
    /// (`NGIT_SYNC_ALLOW_NON_GLOBAL_TARGETS`). Production relays must leave
    /// it disabled. Scheme and credential checks still apply.
    pub allow_non_global: bool,
}

/// An event-directed URL that passed syntactic authorization.
#[derive(Debug, Clone)]
pub struct AuthorizedTarget {
    /// Lowercased hostname without trailing dot, or the literal IP text.
    pub host: String,
    /// Effective port (explicit or the scheme default).
    pub port: u16,
    /// The literal IP address when the host is an IP literal.
    pub ip_literal: Option<IpAddr>,
}

/// An authorized target whose DNS answers (if any) have been vetted.
#[derive(Debug, Clone)]
pub struct ResolvedTarget {
    pub target: AuthorizedTarget,
    /// Globally reachable addresses the host resolved to. Empty when the
    /// policy is permissive (`allow_non_global`) and no vetting occurred.
    pub addresses: Vec<IpAddr>,
}

impl OutboundTargetPolicy {
    /// Syntactically authorize an event-directed URL.
    ///
    /// Rejects unsupported schemes, credentials in the URL, local hostnames,
    /// and IP literals that are not globally reachable. Does not touch DNS.
    pub fn authorize(
        &self,
        kind: OutboundTargetKind,
        raw_url: &str,
    ) -> Result<AuthorizedTarget, String> {
        let url = Url::parse(raw_url).map_err(|error| format!("invalid URL: {error}"))?;

        let scheme = url.scheme();
        let scheme_allowed = match kind {
            OutboundTargetKind::EventRelay => scheme == "ws" || scheme == "wss",
            OutboundTargetKind::EventGit => scheme == "http" || scheme == "https",
        };
        if !scheme_allowed {
            return Err(format!("scheme '{scheme}' is not allowed for this target"));
        }

        if !url.username().is_empty() || url.password().is_some() {
            return Err("URLs with embedded credentials are not allowed".to_string());
        }

        let port = url
            .port_or_known_default()
            .ok_or_else(|| "URL has no usable port".to_string())?;

        match url.host() {
            None => Err("URL has no host".to_string()),
            Some(Host::Domain(name)) => {
                let host = normalize_host(name);
                if !self.allow_non_global {
                    if let Some(reason) = local_hostname_reason(&host) {
                        return Err(reason);
                    }
                }
                Ok(AuthorizedTarget {
                    host,
                    port,
                    ip_literal: None,
                })
            }
            Some(Host::Ipv4(address)) => {
                self.check_ip_literal(IpAddr::V4(address))
                    .map(|()| AuthorizedTarget {
                        host: address.to_string(),
                        port,
                        ip_literal: Some(IpAddr::V4(address)),
                    })
            }
            Some(Host::Ipv6(address)) => {
                self.check_ip_literal(IpAddr::V6(address))
                    .map(|()| AuthorizedTarget {
                        host: address.to_string(),
                        port,
                        ip_literal: Some(IpAddr::V6(address)),
                    })
            }
        }
    }

    /// Authorize an event-directed URL and vet its DNS answers.
    ///
    /// This is the final gate before an outbound connection or fetch. When the
    /// host is a name, every resolved address must be globally reachable;
    /// resolution failure fails closed. Callers that can pin addresses should
    /// use [`ResolvedTarget::addresses`] to avoid a second unchecked lookup.
    pub async fn authorize_resolved(
        &self,
        kind: OutboundTargetKind,
        raw_url: &str,
    ) -> Result<ResolvedTarget, String> {
        let target = self.authorize(kind, raw_url)?;

        if self.allow_non_global {
            return Ok(ResolvedTarget {
                target,
                addresses: Vec::new(),
            });
        }

        if let Some(address) = target.ip_literal {
            return Ok(ResolvedTarget {
                addresses: vec![address],
                target,
            });
        }

        let addresses: Vec<IpAddr> = tokio::net::lookup_host((target.host.as_str(), target.port))
            .await
            .map_err(|error| format!("DNS resolution failed: {error}"))?
            .map(|socket_address| socket_address.ip())
            .collect();

        if addresses.is_empty() {
            return Err("DNS resolution returned no addresses".to_string());
        }
        if let Some(address) = addresses
            .iter()
            .find(|address| !is_globally_reachable(**address))
        {
            return Err(format!(
                "host resolved to non-globally-reachable address {address}"
            ));
        }

        Ok(ResolvedTarget { target, addresses })
    }

    fn check_ip_literal(&self, address: IpAddr) -> Result<(), String> {
        if !self.allow_non_global && !is_globally_reachable(address) {
            return Err(format!("IP address {address} is not globally reachable"));
        }
        Ok(())
    }
}

/// Lowercase a hostname and strip one trailing dot.
fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

/// Why a hostname is considered local-use, or `None` when it looks public.
///
/// Rejects `localhost`, IANA special-use suffixes, and single-label names
/// (which resolve through local search domains, mDNS, or NetBIOS rather than
/// public DNS).
fn local_hostname_reason(host: &str) -> Option<String> {
    if host.is_empty() {
        return Some("empty hostname".to_string());
    }
    if host == "localhost" || host.ends_with(".localhost") {
        return Some("localhost is not an allowed target".to_string());
    }
    if !host.contains('.') {
        return Some(format!("single-label hostname '{host}' is a local name"));
    }
    const LOCAL_SUFFIXES: [&str; 7] = [
        ".local",
        ".localdomain",
        ".internal",
        ".home.arpa",
        ".onion",
        ".test",
        ".invalid",
    ];
    for suffix in LOCAL_SUFFIXES {
        if host.ends_with(suffix) {
            return Some(format!(
                "hostname '{host}' uses local-use suffix '{suffix}'"
            ));
        }
    }
    None
}

/// Whether an address is plausibly reachable on the public internet.
///
/// Follows the special-purpose address registries (mirroring unstable
/// `IpAddr::is_global`): loopback, private, shared/CGNAT, link-local,
/// documentation, benchmarking, multicast, reserved, and unique-local ranges
/// are all non-global.
pub fn is_globally_reachable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => is_ipv4_globally_reachable(v4),
        IpAddr::V6(v6) => is_ipv6_globally_reachable(v6),
    }
}

fn is_ipv4_globally_reachable(address: Ipv4Addr) -> bool {
    let octets = address.octets();
    !(octets[0] == 0 // "this network" (includes 0.0.0.0)
        || address.is_private()
        || address.is_loopback()
        || address.is_link_local()
        // shared address space / CGNAT 100.64.0.0/10 (RFC 6598)
        || (octets[0] == 100 && (octets[1] & 0b1100_0000) == 0b0100_0000)
        // IETF protocol assignments 192.0.0.0/24 (RFC 6890)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
        || address.is_documentation()
        // benchmarking 198.18.0.0/15 (RFC 2544)
        || (octets[0] == 198 && (octets[1] & 0xfe) == 18)
        // deprecated 6to4 relay anycast 192.88.99.0/24 (RFC 7526)
        || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99)
        || address.is_multicast()
        || address.is_broadcast()
        // reserved 240.0.0.0/4 (RFC 1112)
        || octets[0] >= 240)
}

fn is_ipv6_globally_reachable(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return is_ipv4_globally_reachable(mapped);
    }

    let segments = address.segments();
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        // link-local unicast fe80::/10
        || (segments[0] & 0xffc0) == 0xfe80
        // deprecated site-local fec0::/10
        || (segments[0] & 0xffc0) == 0xfec0
        // unique local fc00::/7
        || (segments[0] & 0xfe00) == 0xfc00
        // discard-only 100::/64 (RFC 6666)
        || (segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0)
        // documentation 2001:db8::/32 (RFC 3849) and 3fff::/20 (RFC 9637)
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
        || (segments[0] == 0x3fff && segments[1] <= 0x0fff)
        // benchmarking 2001:2::/48 (RFC 5180)
        || (segments[0] == 0x2001 && segments[1] == 0x0002 && segments[2] == 0)
        // deprecated IPv4-compatible ::a.b.c.d (first 96 bits zero)
        || (segments[..6].iter().all(|segment| *segment == 0)))
}

/// Whether a URL's authority is exactly the given service domain.
///
/// `service` is a bare authority such as `gitnostr.com` or `127.0.0.1:7334`
/// (an optional scheme prefix and trailing slash are tolerated). The URL
/// matches only when its parsed host equals the service host and its
/// effective port agrees: an explicit service port must match the URL's
/// effective port, while a service without a port requires the URL to use its
/// scheme's default port.
///
/// Substring tricks - `gitnostr.com.attacker.example`,
/// `https://evil.example/gitnostr.com/x.git`, `user@gitnostr.com` credentials
/// pointing elsewhere - do not match, unlike the `contains()` checks this
/// replaces.
pub fn url_matches_service_domain(url: &str, service: &str) -> bool {
    let Some((service_host, service_port)) = parse_service_authority(service) else {
        return false;
    };
    let Ok(parsed) = parse_lenient_url(url) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    if normalize_host(host) != service_host {
        return false;
    }
    match service_port {
        Some(port) => parsed.port_or_known_default() == Some(port),
        // url::Url normalizes an explicit default port to None, so a bare
        // service domain matches exactly the scheme-default port.
        None => parsed.port().is_none(),
    }
}

/// Parse a configured service authority into (host, optional port).
fn parse_service_authority(service: &str) -> Option<(String, Option<u16>)> {
    let trimmed = service.trim().trim_end_matches('/');
    let without_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);
    if without_scheme.is_empty() {
        return None;
    }
    // Borrow the url parser for authority handling (IPv6 brackets, ports).
    let parsed = Url::parse(&format!("http://{without_scheme}")).ok()?;
    let host = normalize_host(parsed.host_str()?);
    Some((host, parsed.port()))
}

/// Parse a URL, assuming `https://` when no scheme is present.
fn parse_lenient_url(url: &str) -> Result<Url, ParseError> {
    if url.contains("://") {
        Url::parse(url)
    } else {
        Url::parse(&format!("https://{url}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn public_relay_and_git_targets_are_authorized() {
        for url in ["wss://relay.damus.io", "ws://relay.example.com:8080/path"] {
            strict()
                .authorize(OutboundTargetKind::EventRelay, url)
                .unwrap_or_else(|reason| panic!("{url} should be allowed: {reason}"));
        }
        for url in [
            "https://github.com/example/repo.git",
            "http://git.example.com/x.git",
        ] {
            strict()
                .authorize(OutboundTargetKind::EventGit, url)
                .unwrap_or_else(|reason| panic!("{url} should be allowed: {reason}"));
        }
    }

    #[test]
    fn scheme_allowlist_is_per_target_kind() {
        // A git URL must not be dialled as a relay and vice versa.
        assert!(strict()
            .authorize(OutboundTargetKind::EventRelay, "https://example.com")
            .is_err());
        assert!(strict()
            .authorize(OutboundTargetKind::EventGit, "wss://example.com")
            .is_err());
        // No escape hatches to other protocols.
        for url in [
            "file:///etc/passwd",
            "ssh://git@example.com/x.git",
            "ftp://example.com/x",
            "git://example.com/x.git",
        ] {
            assert!(
                strict()
                    .authorize(OutboundTargetKind::EventGit, url)
                    .is_err(),
                "{url} must be rejected"
            );
            assert!(
                strict()
                    .authorize(OutboundTargetKind::EventRelay, url)
                    .is_err(),
                "{url} must be rejected"
            );
        }
    }

    #[test]
    fn loopback_and_local_names_are_rejected() {
        for url in [
            "ws://127.0.0.1:7334",
            "ws://localhost:3334",
            "wss://sub.localhost",
            "ws://[::1]:7000",
            "ws://relay.local",
            "ws://relay.internal",
            "ws://intranet",
            "ws://printer.home.arpa",
            "ws://hidden.onion",
        ] {
            assert!(
                strict()
                    .authorize(OutboundTargetKind::EventRelay, url)
                    .is_err(),
                "{url} must be rejected"
            );
        }
        assert!(strict()
            .authorize(
                OutboundTargetKind::EventGit,
                "http://127.0.0.1:8080/repo.git"
            )
            .is_err());
    }

    #[test]
    fn non_global_ip_literals_are_rejected() {
        for url in [
            "ws://10.0.0.1:7334",
            "ws://172.16.5.5:7334",
            "ws://192.168.1.1:7334",
            "ws://169.254.10.10:7334",
            "ws://100.125.184.46:7334", // CGNAT address seen in production logs
            "ws://0.0.0.0:7334",
            "ws://224.0.0.1:7334",
            "ws://255.255.255.255:7334",
            "ws://240.1.2.3:7334",
            "ws://192.0.2.10:7334",
            "ws://[fe80::1]:7334",
            "ws://[fc00::1]:7334",
            "ws://[::ffff:127.0.0.1]:7334",
            "ws://[2001:db8::1]:7334",
        ] {
            assert!(
                strict()
                    .authorize(OutboundTargetKind::EventRelay, url)
                    .is_err(),
                "{url} must be rejected"
            );
        }
    }

    #[test]
    fn credentials_are_rejected_even_for_public_hosts() {
        for url in [
            "wss://user:secret@relay.example.com",
            "wss://user@relay.example.com",
            "https://user:secret@git.example.com/x.git",
        ] {
            let kind = if url.starts_with("http") {
                OutboundTargetKind::EventGit
            } else {
                OutboundTargetKind::EventRelay
            };
            assert!(
                strict().authorize(kind, url).is_err(),
                "{url} must be rejected"
            );
        }
    }

    #[test]
    fn permissive_policy_still_enforces_scheme_and_credentials() {
        permissive()
            .authorize(OutboundTargetKind::EventRelay, "ws://127.0.0.1:7334")
            .expect("loopback allowed when non-global targets are permitted");
        assert!(permissive()
            .authorize(OutboundTargetKind::EventRelay, "https://example.com")
            .is_err());
        assert!(permissive()
            .authorize(
                OutboundTargetKind::EventRelay,
                "ws://user:pw@127.0.0.1:7334"
            )
            .is_err());
    }

    #[tokio::test]
    async fn resolved_authorization_passes_global_ip_literals_through() {
        let resolved = strict()
            .authorize_resolved(OutboundTargetKind::EventRelay, "ws://1.1.1.1:7334")
            .await
            .expect("globally reachable literal must pass");
        assert_eq!(
            resolved.addresses,
            vec!["1.1.1.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(resolved.target.port, 7334);
    }

    #[tokio::test]
    async fn resolved_authorization_rejects_loopback_literals() {
        assert!(strict()
            .authorize_resolved(OutboundTargetKind::EventGit, "http://127.0.0.1:8080/x.git")
            .await
            .is_err());
    }

    #[test]
    fn global_reachability_matrix() {
        let non_global = [
            "0.0.0.0",
            "10.1.2.3",
            "100.125.184.46",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.0.0.5",
            "192.0.2.1",
            "192.88.99.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:10.0.0.1",
            "::1.2.3.4",
            "100::1",
            "2001:2::1",
            "2001:db8::1",
            "3fff::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "fec0::1",
            "ff02::1",
        ];
        for address in non_global {
            assert!(
                !is_globally_reachable(address.parse().unwrap()),
                "{address} must not be globally reachable"
            );
        }

        let global = [
            "1.1.1.1",
            "8.8.8.8",
            "100.63.255.255",
            "100.128.0.0",
            "104.16.0.1",
            "198.20.0.1",
            "2606:4700::1111",
            "2a00:1450::1",
        ];
        for address in global {
            assert!(
                is_globally_reachable(address.parse().unwrap()),
                "{address} must be globally reachable"
            );
        }
    }

    #[test]
    fn service_domain_matching_is_exact() {
        // Plain domain, default ports.
        assert!(url_matches_service_domain(
            "https://gitnostr.com/npub/repo.git",
            "gitnostr.com"
        ));
        assert!(url_matches_service_domain(
            "wss://gitnostr.com",
            "gitnostr.com"
        ));
        assert!(url_matches_service_domain(
            "wss://gitnostr.com/",
            "gitnostr.com/"
        ));
        assert!(url_matches_service_domain(
            "WSS://GITNOSTR.COM",
            "gitnostr.com"
        ));
        // Explicit default port is still the default port.
        assert!(url_matches_service_domain(
            "https://gitnostr.com:443/x.git",
            "gitnostr.com"
        ));
        // Schemeless clone URL is tolerated.
        assert!(url_matches_service_domain(
            "gitnostr.com/npub/repo.git",
            "gitnostr.com"
        ));

        // Host suffix/prefix and path tricks must not match.
        for url in [
            "https://gitnostr.com.attacker.example/x.git",
            "https://attacker-gitnostr.com/x.git",
            "https://sub.gitnostr.com/x.git",
            "https://evil.example/gitnostr.com/x.git",
            "https://evil.example/?d=gitnostr.com",
            "https://evil.example#gitnostr.com",
            "https://gitnostr.com@evil.example/x.git",
            "https://gitnostr.com:8443/x.git",
        ] {
            assert!(
                !url_matches_service_domain(url, "gitnostr.com"),
                "{url} must not match gitnostr.com"
            );
        }
    }

    #[test]
    fn service_domain_matching_with_explicit_port() {
        let service = "127.0.0.1:7334";
        assert!(url_matches_service_domain("ws://127.0.0.1:7334", service));
        assert!(url_matches_service_domain(
            "http://127.0.0.1:7334/npub/repo.git",
            service
        ));
        assert!(!url_matches_service_domain("ws://127.0.0.1:7335", service));
        assert!(!url_matches_service_domain("ws://127.0.0.1", service));
        assert!(!url_matches_service_domain(
            "http://evil.example/127.0.0.1:7334/x.git",
            service
        ));
    }
}
