//! The DNS resolver of the blob mirror's HTTP client.
//!
//! The mirror vetted a peer's name and then let reqwest look it up again
//! to connect, so the name could answer a public address to the check and
//! an internal one to the connection (DNS rebinding). With this resolver on
//! the client, the lookup whose answer is vetted is the one the connection
//! uses: hyper-util connects to the addresses returned here and to no
//! other, and nothing falls through to the system resolver.
//!
//! A host that is an IP literal never reaches a resolver: hyper-util
//! connects to it as written. The mirror's early check (`peer_allowed`)
//! covers that case.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;

/// What reqwest takes from a resolver as its error.
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// The answer of one lookup, as socket addresses: an IPv6 link-local
/// answer keeps its scope, which a bare address would lose.
pub(super) type LookupFuture =
    Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>;

/// How a name is looked up: the system's resolver on a node, an answer
/// chosen by the test in a test.
pub(super) type Lookup = Arc<dyn Fn(String) -> LookupFuture + Send + Sync>;

/// A lookup answer the mirror does not connect to, because one of its
/// addresses is not one the mirror may reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct BlockedTarget {
    pub(super) host: String,
    pub(super) address: IpAddr,
}

impl std::fmt::Display for BlockedTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} resolved to {}, which the blob mirror does not connect to",
            self.host, self.address
        )
    }
}

impl std::error::Error for BlockedTarget {}

/// The resolver of the mirror's client.
pub(super) struct VettedResolver {
    /// `NGIT_GRASP_P_MIRROR_ALLOW_PRIVATE_IPS`: the operator said the
    /// pair's link is private, so an internal answer is what is expected.
    allow_private: bool,
    lookup: Lookup,
}

impl VettedResolver {
    /// The resolver a node runs with: the system's lookup.
    pub(super) fn system(allow_private: bool) -> Self {
        Self::with_lookup(allow_private, Arc::new(system_lookup))
    }

    /// A resolver that asks `lookup`. Tests pass the answer they need, so
    /// no test depends on what a name resolves to where it runs.
    pub(super) fn with_lookup(allow_private: bool, lookup: Lookup) -> Self {
        Self {
            allow_private,
            lookup,
        }
    }
}

impl reqwest::dns::Resolve for VettedResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        let answer = (self.lookup)(host.clone());
        Box::pin(resolve_vetted(answer, host, self.allow_private))
    }
}

/// Wait for the answer, vet it, and hand on exactly the addresses vetted.
///
/// An answer without an address is refused like a failed lookup, and is
/// no [`BlockedTarget`]: nothing was refused, the name led nowhere, and the
/// mirror retries that soon rather than at its longest interval.
async fn resolve_vetted(
    answer: LookupFuture,
    host: String,
    allow_private: bool,
) -> Result<reqwest::dns::Addrs, BoxError> {
    let mut answer = answer.await?;
    if answer.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{host} resolved to no address"),
        )
        .into());
    }
    let ips: Vec<IpAddr> = answer.iter().map(SocketAddr::ip).collect();
    vet_answer(&host, &ips, allow_private)?;
    // Port 0 leaves the port to the URL, or to its scheme: hyper-util keeps
    // a resolver's port when the URL names none.
    for address in &mut answer {
        address.set_port(0);
    }
    // The lookup's own addresses go on, so a link-local answer keeps its
    // scope.
    let addresses: reqwest::dns::Addrs = Box::new(answer.into_iter());
    Ok(addresses)
}

/// Refuse the whole answer when any of its addresses may not be reached.
///
/// The whole answer and not the good part of it: a name that answers an
/// internal address next to a public one is pointed at the internal one on
/// purpose, and its owner is not a peer to fetch from until that changes.
/// Under `allow_private` every address passes.
fn vet_answer(host: &str, answer: &[IpAddr], allow_private: bool) -> Result<(), BlockedTarget> {
    if allow_private {
        return Ok(());
    }
    match answer.iter().find(|address| !reachable(**address)) {
        Some(address) => Err(BlockedTarget {
            host: host.to_string(),
            address: *address,
        }),
        None => Ok(()),
    }
}

/// Whether the mirror may connect to `address`: upstream's list of global
/// ranges, then the check a GRASP-P node's relay dial adds to it
/// (`mirror::wraps_non_global`). That check adds the mirror's own list, and
/// refuses a NAT64 or 6to4 form that wraps an address either list refuses,
/// and the local-use NAT64 prefix whatever it carries: upstream counts both
/// prefixes as global. It also refuses IPv6 space outside `2000::/3` or
/// inside `2001::/23` (Teredo, SIIT, SRv6).
fn reachable(address: IpAddr) -> bool {
    crate::outbound::is_globally_reachable(address) && !super::mirror::wraps_non_global(&address)
}

/// The refusal of this resolver that made a request fail, if one did.
///
/// reqwest keeps a resolver's error as a source: its own DNS error wraps
/// it, hyper-util's connect error wraps that, and the client error that
/// reqwest returns wraps the connect error.
pub(super) fn blocked_target(error: &reqwest::Error) -> Option<&BlockedTarget> {
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        if let Some(blocked) = cause.downcast_ref::<BlockedTarget>() {
            return Some(blocked);
        }
        source = cause.source();
    }
    None
}

/// The system's answer for `host`, as the connection would have had it
/// without this resolver.
fn system_lookup(host: String) -> LookupFuture {
    Box::pin(ask_the_system(host))
}

async fn ask_the_system(host: String) -> std::io::Result<Vec<SocketAddr>> {
    Ok(tokio::net::lookup_host((host.as_str(), 0_u16))
        .await?
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::dns::Resolve;
    use std::net::{Ipv4Addr, SocketAddrV6};
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A name under `.test`, which no resolver answers: only the injected
    /// lookup can give it an address.
    const PEER: &str = "peer.mirror.test";

    fn ip(text: &str) -> IpAddr {
        text.parse().expect("an address")
    }

    /// A lookup's answer, ready at once.
    fn ready(answer: std::io::Result<Vec<SocketAddr>>) -> LookupFuture {
        Box::pin(std::future::ready(answer))
    }

    /// A lookup that answers `addresses` for every name.
    fn answering(addresses: Vec<IpAddr>) -> Lookup {
        Arc::new(move |_host: String| {
            ready(Ok(addresses
                .iter()
                .map(|address| SocketAddr::new(*address, 0))
                .collect()))
        })
    }

    /// Ask `resolver` for `name` as the client's connector does.
    async fn ask(resolver: &VettedResolver, name: &str) -> Result<Vec<SocketAddr>, BoxError> {
        let name: reqwest::dns::Name = name.parse().expect("a name");
        resolver
            .resolve(name)
            .await
            .map(|addresses| addresses.collect())
    }

    /// An answer of global addresses only passes, and is handed on whole,
    /// with no port of its own.
    #[tokio::test]
    async fn resolver_hands_on_an_all_global_answer() {
        let answer = vec![
            ip("8.8.8.8"),
            ip("2606:4700:4700::1111"),
            // 6to4 around a public address.
            ip("2002:808:808::"),
            // 2001::/16 past the protocol assignments, and an IPv4-mapped
            // public address.
            ip("2001:4860:4860::8888"),
            ip("::ffff:8.8.8.8"),
        ];
        let resolver = VettedResolver::with_lookup(false, answering(answer.clone()));

        let addresses = ask(&resolver, PEER).await.expect("a global answer");

        let expected: Vec<SocketAddr> = answer
            .into_iter()
            .map(|address| SocketAddr::new(address, 0))
            .collect();
        assert_eq!(addresses, expected);
    }

    /// No address is refused, whatever the operator allows, and is not
    /// taken for a refusal of an address.
    #[tokio::test]
    async fn resolver_refuses_an_empty_answer() {
        for allow_private in [false, true] {
            let resolver = VettedResolver::with_lookup(allow_private, answering(Vec::new()));

            let error = ask(&resolver, PEER)
                .await
                .expect_err("an empty answer must be refused");

            assert!(error.downcast_ref::<BlockedTarget>().is_none(), "{error}");
            let io = error
                .downcast_ref::<std::io::Error>()
                .expect("refused as a lookup that found nothing");
            assert_eq!(io.kind(), std::io::ErrorKind::NotFound);
            assert!(io.to_string().contains(PEER), "{io}");
        }
    }

    /// One address that may not be reached refuses the whole answer, and the
    /// refusal names the host and that address. Both lists are applied, and
    /// so is what an address wraps: 198.18.0.1 is known to upstream's list
    /// only, a NAT64 or 6to4 form around an internal address to the mirror's
    /// only, the same forms around 198.18.0.1 or 240.0.0.1 to neither bare,
    /// the local-use NAT64 prefix is refused whatever it carries, and so are
    /// Teredo, SIIT and SRv6.
    #[tokio::test]
    async fn resolver_refuses_a_mixed_answer_whole() {
        for (answer, refused) in [
            (vec![ip("8.8.8.8"), ip("127.0.0.1")], ip("127.0.0.1")),
            (vec![ip("10.0.0.5"), ip("8.8.8.8")], ip("10.0.0.5")),
            (vec![ip("8.8.8.8"), ip("198.18.0.1")], ip("198.18.0.1")),
            // NAT64 around the cloud metadata address.
            (
                vec![ip("2606:4700:4700::1111"), ip("64:ff9b::a9fe:a9fe")],
                ip("64:ff9b::a9fe:a9fe"),
            ),
            // 6to4 around 10.0.0.5.
            (vec![ip("2002:a00:5::")], ip("2002:a00:5::")),
            (vec![ip("::1")], ip("::1")),
            // NAT64 around 198.18.0.1 (benchmarking), next to a public
            // address, and 6to4 around it.
            (
                vec![ip("8.8.8.8"), ip("64:ff9b::c612:1")],
                ip("64:ff9b::c612:1"),
            ),
            (vec![ip("2002:c612:1::")], ip("2002:c612:1::")),
            // 6to4 around 240.0.0.1 (reserved).
            (vec![ip("2002:f000:1::1")], ip("2002:f000:1::1")),
            // The local-use NAT64 prefix, around 10.0.0.5.
            (
                vec![ip("2606:4700:4700::1111"), ip("64:ff9b:1::a00:5")],
                ip("64:ff9b:1::a00:5"),
            ),
            // Teredo next to a public address, SIIT, and SRv6.
            (
                vec![
                    ip("2001:4860:4860::8888"),
                    ip("2001:0:4136:e378:8000:63bf:3fff:fdd2"),
                ],
                ip("2001:0:4136:e378:8000:63bf:3fff:fdd2"),
            ),
            (vec![ip("::ffff:0:a00:5")], ip("::ffff:0:a00:5")),
            (vec![ip("5f00::1")], ip("5f00::1")),
        ] {
            let resolver = VettedResolver::with_lookup(false, answering(answer.clone()));

            let error = ask(&resolver, PEER)
                .await
                .expect_err("an answer with an internal address must be refused");

            assert_eq!(
                error.downcast_ref::<BlockedTarget>(),
                Some(&BlockedTarget {
                    host: PEER.to_string(),
                    address: refused,
                }),
                "{answer:?}"
            );
            let message = error.to_string();
            assert!(
                message.contains(PEER) && message.contains(&refused.to_string()),
                "{message}"
            );
            assert_eq!(
                vet_answer(PEER, &answer, false).map_err(|refusal| refusal.address),
                Err(refused)
            );
        }
    }

    /// On a private link every answer is what the operator expects, and is
    /// handed on as it came.
    #[tokio::test]
    async fn resolver_on_a_private_link_passes_every_answer() {
        let answer = vec![
            ip("127.0.0.1"),
            ip("10.0.0.5"),
            ip("64:ff9b::a9fe:a9fe"),
            ip("8.8.8.8"),
        ];
        let resolver = VettedResolver::with_lookup(true, answering(answer.clone()));

        let addresses = ask(&resolver, PEER).await.expect("allowed");

        let ips: Vec<IpAddr> = addresses.iter().map(SocketAddr::ip).collect();
        assert_eq!(ips, answer);
        assert!(vet_answer(PEER, &answer, true).is_ok());
    }

    /// A link-local answer on a private link keeps its scope, so the
    /// connection leaves through the interface the lookup named.
    #[tokio::test]
    async fn resolver_keeps_the_scope_of_a_link_local_answer() {
        let scoped = SocketAddr::V6(SocketAddrV6::new(
            "fe80::1".parse().expect("an address"),
            0,
            0,
            3,
        ));
        let lookup: Lookup = Arc::new(move |_host: String| ready(Ok(vec![scoped])));
        let resolver = VettedResolver::with_lookup(true, lookup);

        let addresses = ask(&resolver, PEER).await.expect("allowed");

        assert_eq!(addresses, vec![scoped], "the scope is part of the address");
    }

    /// Every connection asks the lookup again, and every answer is vetted:
    /// a name that answers a public address first and loopback next is
    /// refused the second time. Without this resolver the second answer is
    /// the one reqwest would have connected to.
    #[tokio::test]
    async fn resolver_refuses_a_rebound_answer() {
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&calls);
        let lookup: Lookup = Arc::new(move |_host: String| {
            let address = if counted.fetch_add(1, Ordering::SeqCst) == 0 {
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
            } else {
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            };
            ready(Ok(vec![SocketAddr::new(address, 0)]))
        });
        let resolver = VettedResolver::with_lookup(false, lookup);

        assert!(ask(&resolver, PEER).await.is_ok());
        let error = ask(&resolver, PEER)
            .await
            .expect_err("the second answer must be refused");
        assert_eq!(
            error
                .downcast_ref::<BlockedTarget>()
                .map(|refusal| refusal.address),
            Some(IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// The lookup is asked for the name the client connects to, and a
    /// lookup that fails is passed on as it failed, not as a refusal.
    #[tokio::test]
    async fn resolver_asks_for_the_name_and_passes_a_failed_lookup_on() {
        let asked = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let record = Arc::clone(&asked);
        let lookup: Lookup = Arc::new(move |host: String| {
            record.lock().expect("lock").push(host);
            ready(Err(std::io::Error::other("no such name")))
        });
        let resolver = VettedResolver::with_lookup(false, lookup);

        let error = ask(&resolver, PEER)
            .await
            .expect_err("a failed lookup is an error");

        assert!(error.downcast_ref::<BlockedTarget>().is_none(), "{error}");
        assert!(error.downcast_ref::<std::io::Error>().is_some(), "{error}");
        assert_eq!(*asked.lock().expect("lock"), vec![PEER.to_string()]);
    }
}
