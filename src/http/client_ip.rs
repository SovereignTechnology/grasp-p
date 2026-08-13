use std::net::{IpAddr, SocketAddr};

use hyper::header::{HeaderMap, FORWARDED};
use ipnet::IpNet;

const X_FORWARDED_FOR: &str = "x-forwarded-for";
const X_REAL_IP: &str = "x-real-ip";

/// Resolve the address used for WebSocket accounting and relay connection
/// policy without allowing arbitrary direct peers to spoof forwarding headers.
pub(super) fn resolve_client_addr(
    peer: SocketAddr,
    headers: &HeaderMap,
    trusted_proxies: &[IpNet],
) -> SocketAddr {
    if !is_trusted(peer.ip(), trusted_proxies) {
        return peer;
    }

    // Prefer X-Forwarded-For because common reverse proxies (including Caddy)
    // append the TCP source to that chain while an inbound RFC Forwarded
    // header may otherwise pass through untouched.
    let client_ip = if headers.contains_key(X_FORWARDED_FOR) {
        parse_x_forwarded_for(headers)
            .map(|chain| resolve_chain(peer.ip(), &chain, trusted_proxies))
    } else if headers.contains_key(FORWARDED) {
        parse_forwarded(headers).map(|chain| resolve_chain(peer.ip(), &chain, trusted_proxies))
    } else if headers.contains_key(X_REAL_IP) {
        parse_x_real_ip(headers)
    } else {
        None
    };

    client_ip
        .map(|ip| SocketAddr::new(ip, peer.port()))
        .unwrap_or(peer)
}

/// Walk from the TCP peer towards the originating client. Each forwarding hop
/// is consumed only while the current hop is trusted, so client-supplied
/// entries to the left of the first untrusted address cannot take effect.
fn resolve_chain(peer: IpAddr, forwarded: &[IpAddr], trusted_proxies: &[IpNet]) -> IpAddr {
    let mut current = peer;

    for forwarded_ip in forwarded.iter().rev() {
        if !is_trusted(current, trusted_proxies) {
            break;
        }
        current = *forwarded_ip;
    }

    current
}

fn is_trusted(ip: IpAddr, trusted_proxies: &[IpNet]) -> bool {
    trusted_proxies.iter().any(|network| network.contains(&ip))
}

fn parse_forwarded(headers: &HeaderMap) -> Option<Vec<IpAddr>> {
    let mut addresses = Vec::new();

    for value in headers.get_all(FORWARDED) {
        let value = value.to_str().ok()?;
        for element in value.split(',') {
            let mut address = None;
            for parameter in element.split(';') {
                let (name, value) = parameter.trim().split_once('=')?;
                if name.trim().eq_ignore_ascii_case("for") {
                    if address.is_some() {
                        return None;
                    }
                    address = parse_forwarded_address(value.trim());
                    address?;
                }
            }
            addresses.push(address?);
        }
    }

    (!addresses.is_empty()).then_some(addresses)
}

fn parse_forwarded_address(value: &str) -> Option<IpAddr> {
    let value = match (value.strip_prefix('"'), value.strip_suffix('"')) {
        (Some(_), None) | (None, Some(_)) => return None,
        (Some(without_prefix), Some(_)) => without_prefix.strip_suffix('"')?,
        (None, None) => value,
    };

    if value.is_empty() || value.eq_ignore_ascii_case("unknown") || value.starts_with('_') {
        return None;
    }

    value
        .parse::<IpAddr>()
        .ok()
        .or_else(|| value.parse::<SocketAddr>().ok().map(|addr| addr.ip()))
        .or_else(|| {
            value
                .strip_prefix('[')?
                .strip_suffix(']')?
                .parse::<IpAddr>()
                .ok()
        })
}

fn parse_x_forwarded_for(headers: &HeaderMap) -> Option<Vec<IpAddr>> {
    let mut addresses = Vec::new();

    for value in headers.get_all(X_FORWARDED_FOR) {
        let value = value.to_str().ok()?;
        for address in value.split(',') {
            addresses.push(address.trim().parse().ok()?);
        }
    }

    (!addresses.is_empty()).then_some(addresses)
}

fn parse_x_real_ip(headers: &HeaderMap) -> Option<IpAddr> {
    let mut values = headers.get_all(X_REAL_IP).iter();
    let address = values.next()?.to_str().ok()?.trim().parse().ok()?;
    values.next().is_none().then_some(address)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::header::{HeaderValue, FORWARDED};

    fn address(value: &str) -> SocketAddr {
        value.parse().unwrap()
    }

    fn networks(values: &[&str]) -> Vec<IpNet> {
        values.iter().map(|value| value.parse().unwrap()).collect()
    }

    #[test]
    fn ignores_spoofed_headers_from_an_untrusted_peer() {
        let peer = address("198.51.100.20:4242");
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, HeaderValue::from_static("203.0.113.9"));

        assert_eq!(
            resolve_client_addr(peer, &headers, &networks(&["127.0.0.1/32"])),
            peer
        );
    }

    #[test]
    fn uses_the_tcp_peer_without_forwarding_headers() {
        let peer = address("127.0.0.1:4242");

        assert_eq!(
            resolve_client_addr(peer, &HeaderMap::new(), &networks(&["127.0.0.1/32"])),
            peer
        );
    }

    #[test]
    fn resolves_a_client_behind_one_trusted_proxy() {
        let peer = address("127.0.0.1:4242");
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, HeaderValue::from_static("198.51.100.20"));

        assert_eq!(
            resolve_client_addr(peer, &headers, &networks(&["127.0.0.1/32"])).ip(),
            "198.51.100.20".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn walks_a_chain_of_trusted_proxies_from_the_peer_inward() {
        let peer = address("10.0.0.3:4242");
        let mut headers = HeaderMap::new();
        headers.insert(
            X_FORWARDED_FOR,
            HeaderValue::from_static("198.51.100.20, 10.0.0.2"),
        );

        assert_eq!(
            resolve_client_addr(peer, &headers, &networks(&["10.0.0.0/24"])).ip(),
            "198.51.100.20".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn stops_before_client_supplied_entries_left_of_the_first_untrusted_hop() {
        let peer = address("10.0.0.3:4242");
        let mut headers = HeaderMap::new();
        headers.insert(
            X_FORWARDED_FOR,
            HeaderValue::from_static("203.0.113.9, 198.51.100.20"),
        );

        assert_eq!(
            resolve_client_addr(peer, &headers, &networks(&["10.0.0.0/24"])).ip(),
            "198.51.100.20".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn fails_closed_on_a_malformed_forwarding_chain() {
        let peer = address("127.0.0.1:4242");
        let mut headers = HeaderMap::new();
        headers.insert(
            X_FORWARDED_FOR,
            HeaderValue::from_static("198.51.100.20, invalid"),
        );
        headers.insert(X_REAL_IP, HeaderValue::from_static("198.51.100.20"));

        assert_eq!(
            resolve_client_addr(peer, &headers, &networks(&["127.0.0.1/32"])),
            peer
        );
    }

    #[test]
    fn parses_forwarded_ipv6_addresses_and_ports() {
        let peer = address("127.0.0.1:4242");
        let mut headers = HeaderMap::new();
        headers.insert(
            FORWARDED,
            HeaderValue::from_static("for=\"[2001:db8::7]:4711\";proto=https"),
        );

        assert_eq!(
            resolve_client_addr(peer, &headers, &networks(&["127.0.0.1/32"])).ip(),
            "2001:db8::7".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn prefers_a_proxy_appended_x_forwarded_for_chain() {
        let peer = address("127.0.0.1:4242");
        let mut headers = HeaderMap::new();
        headers.insert(X_FORWARDED_FOR, HeaderValue::from_static("198.51.100.20"));
        headers.insert(FORWARDED, HeaderValue::from_static("for=203.0.113.9"));

        assert_eq!(
            resolve_client_addr(peer, &headers, &networks(&["127.0.0.1/32"])).ip(),
            "198.51.100.20".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn uses_x_real_ip_when_no_chain_header_is_present() {
        let peer = address("127.0.0.1:4242");
        let mut headers = HeaderMap::new();
        headers.insert(X_REAL_IP, HeaderValue::from_static("198.51.100.20"));

        assert_eq!(
            resolve_client_addr(peer, &headers, &networks(&["127.0.0.1/32"])).ip(),
            "198.51.100.20".parse::<IpAddr>().unwrap()
        );
    }
}
