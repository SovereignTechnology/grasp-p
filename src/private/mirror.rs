//! GRASP-P Phase 2 blob mirror (pull-only).
//!
//! On any accepted kind-30641 the referenced manifest/pack blobs must exist
//! locally. On the origin node they already do (the client PUT them before
//! publishing); on the replicating node they are missing and are pulled here
//! over the peer's EXISTING public `GET /<sha256>` route — no new inbound
//! surface.
//!
//! Design invariants:
//! - Streamed to a temp file through the Phase-1 [`UploadSink`], which caps
//!   bytes at `min(declared, max_blob_bytes)` mid-stream (a hostile peer
//!   cannot stream unbounded), verifies the SHA-256 against the requested
//!   hash, fsyncs + renames, and claims + charges the replicated tenant's
//!   ledger atomically (same GC-TOCTOU-safe path as a client upload).
//! - Over quota / global budget → skip; the blob stays missing and is
//!   reflected in the `ngit_private_mirror_lag_blobs` gauge (alert on
//!   sustained > 0 — silent-desync lesson F1).
//! - Idempotent: a job whose blob is already local is a no-op; repair scans
//!   re-derive want sets from blob claims (which 30641 handling maintains),
//!   so a restart or a transiently unreachable peer heals automatically.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use nostr::Event;
use tokio::sync::mpsc::unbounded_channel;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use super::blob_store::UploadSink;
use super::{BlobError, PrivateService};

/// One blob a mirror job wants locally.
#[derive(Debug, Clone)]
pub struct WantBlob {
    pub sha256: String,
    /// Declared size from the 30641 tag / blob claim (upload-sink cap +
    /// in-flight reservation size).
    pub size: u64,
}

/// A mirror work item: pull `want` for (tenant, alias) from `peer_servers`.
#[derive(Debug, Clone)]
pub struct MirrorJob {
    pub tenant_hex: String,
    pub alias: String,
    pub want: Vec<WantBlob>,
    /// Peer blob-server base URLs (this node's own domain already excluded).
    pub peer_servers: Vec<String>,
}

/// Normalize a `server` tag value / configured peer URL into an HTTP base
/// URL: keeps explicit http:// (tests) and https:// schemes, defaults bare
/// host[:port] values to https://, and trims trailing slashes.
fn server_base_url(value: &str) -> Option<String> {
    let v = value.trim().trim_end_matches('/');
    if v.is_empty() {
        return None;
    }
    if v.starts_with("http://") || v.starts_with("https://") {
        Some(v.to_string())
    } else {
        Some(format!("https://{v}"))
    }
}

/// Extract an embedded IPv4 address from the IPv6 transition/translation forms
/// that carry a v4 payload in their low bits: IPv4-mapped (::ffff:0:0/96),
/// NAT64 (64:ff9b::/96), 6to4 (2002::/16, embedded v4 in bytes 2..6), and
/// IPv4-compatible (::/96). Any of these can smuggle an internal v4 (e.g.
/// 169.254.169.254) past a v6-only guard, so we must decode and re-check them.
fn embedded_ipv4(v6: &Ipv6Addr) -> Option<Ipv4Addr> {
    // IPv4-mapped ::ffff:a.b.c.d
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }
    let o = v6.octets();
    // NAT64 well-known prefix 64:ff9b::/96 → embedded v4 in the low 32 bits.
    if o[0] == 0x00
        && o[1] == 0x64
        && o[2] == 0xff
        && o[3] == 0x9b
        && o[4..12].iter().all(|b| *b == 0)
    {
        return Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    // 6to4 2002::/16 → embedded v4 in bytes 2..6.
    if o[0] == 0x20 && o[1] == 0x02 {
        return Some(Ipv4Addr::new(o[2], o[3], o[4], o[5]));
    }
    // IPv4-compatible ::/96 (deprecated) → embedded v4 in the low 32 bits, but
    // only when it is a genuine embedded address, not :: / ::1 (those are
    // already rejected as unspecified/loopback by the caller).
    if o[0..12].iter().all(|b| *b == 0) && !(o[12] == 0 && o[13] == 0 && o[14] == 0) {
        return Some(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
    }
    None
}

/// True for IPs the mirror must never fetch from in production: loopback,
/// RFC1918 private, CGNAT shared, link-local, unspecified, broadcast,
/// multicast, documentation, IPv6 ULA/link-local, and any embedded-IPv4
/// transition form (IPv4-mapped, NAT64, 6to4, IPv4-compatible) wrapping one
/// of these.
fn is_disallowed_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                // CGNAT shared address space 100.64.0.0/10
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // unique local fc00::/7
                || (v6.octets()[0] & 0xfe) == 0xfc
                // link-local fe80::/10
                || (v6.octets()[0] == 0xfe && (v6.octets()[1] & 0xc0) == 0x80)
                // Embedded-IPv4 transition forms (IPv4-mapped / NAT64 / 6to4 /
                // IPv4-compatible) — decode and re-check the embedded v4 so an
                // internal address cannot be smuggled through a v6 wrapper.
                || embedded_ipv4(v6)
                    .map(|v4| is_disallowed_ip(&IpAddr::V4(v4)))
                    .unwrap_or(false)
        }
    }
}

/// SSRF guard for a peer base URL. With `allow_private` (tests) any peer is
/// allowed. Otherwise: require https, resolve the host, and reject if it does
/// not resolve or if ANY resolved address is a disallowed (internal) IP. This
/// defeats the trivial literal-IP / static-hostname SSRF via a hostile 30640
/// `server` tag; DNS-rebinding at connection time remains a documented residual
/// (production should set NGIT_PRIVATE_MIRROR_PEER_URLS to the known peer).
async fn peer_allowed(peer_base: &str, allow_private: bool) -> bool {
    if allow_private {
        return true;
    }
    let Some(rest) = peer_base.strip_prefix("https://") else {
        // Plaintext http is only permitted under allow_private (loopback tests).
        return false;
    };
    host_resolves_public_only(rest).await
}

/// SSRF guard for a private-sync peer relay URL. Same policy as
/// [`peer_allowed`] but for WebSocket peers: with `allow_private` (tests)
/// any peer is allowed; otherwise require wss:// (plain ws:// rejected),
/// resolve the host, and reject if it does not resolve or if ANY resolved
/// address is a disallowed (internal) IP.
pub(crate) async fn relay_peer_allowed(relay_url: &str, allow_private: bool) -> bool {
    if allow_private {
        return true;
    }
    let Some(rest) = relay_url.strip_prefix("wss://") else {
        // Plaintext ws is only permitted under allow_private (loopback tests).
        return false;
    };
    host_resolves_public_only(rest).await
}

/// Resolve the host of `rest` (a URL with scheme stripped) and require every
/// resolved address to be a public, allowed IP.
async fn host_resolves_public_only(rest: &str) -> bool {
    let hostport = rest.split('/').next().unwrap_or(rest);
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => {
            (h, p.parse::<u16>().unwrap_or(443))
        }
        _ => (hostport, 443u16),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    match tokio::net::lookup_host((host, port)).await {
        Ok(addrs) => {
            let mut resolved_any = false;
            for a in addrs {
                resolved_any = true;
                if is_disallowed_ip(&a.ip()) {
                    return false;
                }
            }
            resolved_any
        }
        Err(_) => false,
    }
}

/// Peer servers for an alias: the configured override when present,
/// otherwise the registration's `server` tags minus this node's own domain.
fn peer_servers_for(svc: &PrivateService, registration_servers: &[String]) -> Vec<String> {
    let own = svc.cfg.domain.trim_end_matches('/');
    let candidates: Vec<&String> = match svc.cfg.mirror_peer_urls {
        Some(ref configured) => configured.iter().collect(),
        None => registration_servers
            .iter()
            .filter(|v| !v.trim_end_matches('/').contains(own))
            .collect(),
    };
    let mut out = Vec::new();
    for value in candidates {
        if let Some(base) = server_base_url(value) {
            if !out.contains(&base) {
                out.push(base);
            }
        }
    }
    out
}

/// Enqueue a mirror job for an accepted 30641. No-op when the mirror worker
/// is not running (mirroring disabled) or when the event/registration cannot
/// be resolved (the periodic repair scan is the safety net).
pub(crate) fn enqueue_for_state_root(svc: &PrivateService, event: &Event) {
    let Some(tx) = svc.mirror_tx.get() else {
        return;
    };

    let mut alias: Option<String> = None;
    let mut want: Vec<WantBlob> = Vec::new();
    for tag in event.tags.iter() {
        let v = tag.clone().to_vec();
        if v.len() < 2 {
            continue;
        }
        match v[0].as_str() {
            "d" => {
                if alias.is_none() {
                    alias = Some(v[1].clone());
                }
            }
            "m" | "pack" => {
                if v.len() >= 3 && super::blossom_auth::is_lower_hex_64(&v[1]) {
                    if let Ok(size) = v[2].parse::<u64>() {
                        want.push(WantBlob {
                            sha256: v[1].clone(),
                            size,
                        });
                    }
                }
            }
            _ => {}
        }
    }
    let Some(alias) = alias else { return };
    if want.is_empty() {
        return;
    }

    // Skip blobs already local (client-push path on the origin node).
    want.retain(|w| !svc.blobs.exists(&w.sha256) && !svc.is_denylisted(&w.sha256));
    if want.is_empty() {
        return;
    }

    let record = {
        let Ok(txn) = svc.meta.read_txn() else { return };
        match svc.meta.get_registration(&txn, &alias) {
            Ok(Some(record)) if record.tombstoned_at.is_none() => record,
            _ => return,
        }
    };

    let job = MirrorJob {
        tenant_hex: record.tenant_hex.clone(),
        alias,
        want,
        peer_servers: peer_servers_for(svc, &record.servers),
    };
    let _ = tx.send(job);
}

/// Repair scan: derive mirror jobs for every referenced-but-missing blob
/// from the blob-claim table, and update the mirror lag gauge. Covers boot
/// (want sets re-derived from retained 30641 state), missed enqueues, and
/// retries after peer failures.
fn scan_missing(svc: &PrivateService) -> Vec<MirrorJob> {
    let mut jobs: Vec<MirrorJob> = Vec::new();
    let mut lag = 0_u64;

    let Ok(txn) = svc.meta.read_txn() else {
        return jobs;
    };
    let Ok(claims) = svc.meta.all_blob_claims(&txn) else {
        return jobs;
    };

    for (sha, claim) in claims {
        if claim.aliases.is_empty() || svc.blobs.exists(&sha) || svc.is_denylisted(&sha) {
            continue;
        }
        lag += 1;

        // First claiming alias with a live (non-tombstoned) registration.
        let mut resolved = None;
        for alias in &claim.aliases {
            if let Ok(Some(record)) = svc.meta.get_registration(&txn, alias) {
                if record.tombstoned_at.is_none() {
                    resolved = Some((alias.clone(), record));
                    break;
                }
            }
        }
        let Some((alias, record)) = resolved else {
            continue;
        };

        let want = WantBlob {
            sha256: sha,
            size: claim.size,
        };
        if let Some(job) = jobs
            .iter_mut()
            .find(|j| j.alias == alias && j.tenant_hex == record.tenant_hex)
        {
            job.want.push(want);
        } else {
            jobs.push(MirrorJob {
                tenant_hex: record.tenant_hex.clone(),
                alias,
                want: vec![want],
                peer_servers: peer_servers_for(svc, &record.servers),
            });
        }
    }

    crate::metrics::set_private_mirror_lag_blobs(lag);
    jobs
}

/// Recompute + publish the lag gauge (referenced-but-missing blob count).
fn update_lag(svc: &PrivateService) {
    let Ok(txn) = svc.meta.read_txn() else { return };
    let Ok(claims) = svc.meta.all_blob_claims(&txn) else {
        return;
    };
    let lag = claims
        .iter()
        .filter(|(sha, claim)| {
            !claim.aliases.is_empty() && !svc.blobs.exists(sha) && !svc.is_denylisted(sha)
        })
        .count() as u64;
    crate::metrics::set_private_mirror_lag_blobs(lag);
}

/// Fetch one blob from one peer through the Phase-1 upload sink.
async fn fetch_from_peer(
    svc: &Arc<PrivateService>,
    client: &reqwest::Client,
    job: &MirrorJob,
    blob: &WantBlob,
    peer_base: &str,
) -> Result<(), String> {
    // SSRF guard: never let a tenant-controlled `server` tag point our fetch at
    // an internal host. Checked before any reservation/connection.
    if !peer_allowed(peer_base, svc.cfg.mirror_allow_private_ips).await {
        return Err("blocked".to_string());
    }

    // Reserve in-flight capacity + open the temp-file sink (mirrors a client
    // PUT: reservation → sink → stream → finish). finish() releases any
    // pending speculative charge before its quota check, so the reserve nets
    // it too (FF).
    let pending = svc
        .pending_spec_release(&blob.sha256)
        .map_err(|e| format!("reserve: {}", e.reason()))?;
    let reservation = svc.reserve_upload(blob.size, pending).map_err(|e| match e {
        BlobError::QuotaExceeded => "quota".to_string(),
        other => format!("reserve: {}", other.reason()),
    })?;
    let mut sink = UploadSink::create(
        svc.meta.clone(),
        svc.blobs.clone(),
        svc.cfg.clone(),
        job.tenant_hex.clone(),
        job.alias.clone(),
        blob.sha256.clone(),
        blob.size,
        reservation,
    )
    .await
    .map_err(|e| format!("sink: {}", e.reason()))?;

    let url = format!("{}/{}", peer_base, blob.sha256);
    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("network: {e}"))?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(format!("http_status: {}", response.status().as_u16()));
    }

    let mut response = response;
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                // write_chunk enforces min(declared, max_blob_bytes) and
                // aborts mid-stream on overrun (hostile peer protection).
                sink.write_chunk(&chunk).await.map_err(|e| match e {
                    BlobError::TooLarge => "too_large".to_string(),
                    other => format!("write: {}", other.reason()),
                })?;
            }
            Ok(None) => break,
            Err(e) => return Err(format!("network: {e}")),
        }
    }

    // finish() verifies streamed-bytes == declared size and the SHA-256
    // against the requested hash; on mismatch the temp file is deleted and
    // nothing is stored (no poisoned blob).
    sink.finish().await.map_err(|e| match e {
        BlobError::QuotaExceeded => "quota".to_string(),
        BlobError::BadRequest(reason) => format!("verify: {reason}"),
        other => format!("store: {}", other.reason()),
    })?;
    Ok(())
}

/// Fetch one blob, trying each peer in order. Success is sticky (idempotent
/// no-op when the blob landed via a concurrent job).
async fn fetch_blob(svc: &Arc<PrivateService>, client: &reqwest::Client, job: &MirrorJob, blob: &WantBlob) {
    if svc.blobs.exists(&blob.sha256) || svc.is_denylisted(&blob.sha256) {
        return;
    }
    if job.peer_servers.is_empty() {
        crate::metrics::record_private_mirror_failed("no_peer");
        tracing::warn!(
            alias = %job.alias,
            sha256 = %blob.sha256,
            "private mirror: no peer server available for blob"
        );
        return;
    }

    let mut last_error = String::new();
    for peer in &job.peer_servers {
        match fetch_from_peer(svc, client, job, blob, peer).await {
            Ok(()) => {
                crate::metrics::record_private_mirror_fetched();
                svc.refresh_gauges();
                tracing::info!(
                    alias = %job.alias,
                    sha256 = %blob.sha256,
                    peer = %peer,
                    size = blob.size,
                    "private mirror: blob fetched from peer"
                );
                return;
            }
            Err(reason) => {
                tracing::debug!(
                    alias = %job.alias,
                    sha256 = %blob.sha256,
                    peer = %peer,
                    reason = %reason,
                    "private mirror: fetch attempt failed"
                );
                last_error = reason;
            }
        }
    }

    let reason_label = last_error
        .split(':')
        .next()
        .unwrap_or("unknown")
        .to_string();
    crate::metrics::record_private_mirror_failed(&reason_label);
    tracing::warn!(
        alias = %job.alias,
        sha256 = %blob.sha256,
        reason = %last_error,
        "private mirror: blob fetch failed on all peers (will retry on repair scan)"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn disallowed_ip_covers_internal_ranges() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.0.1",
            "172.16.5.5",
            "169.254.169.254", // cloud metadata
            "100.64.0.1",      // CGNAT
            "0.0.0.0",
            "224.0.0.1",
        ] {
            let ip: IpAddr = IpAddr::V4(ip.parse::<Ipv4Addr>().unwrap());
            assert!(is_disallowed_ip(&ip), "{ip} should be disallowed");
        }
        assert!(is_disallowed_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_disallowed_ip(&IpAddr::V6("fe80::1".parse().unwrap())));
        assert!(is_disallowed_ip(&IpAddr::V6("fc00::1".parse().unwrap())));
        assert!(is_disallowed_ip(&IpAddr::V6("::ffff:127.0.0.1".parse().unwrap())));
    }

    #[test]
    fn embedded_ipv4_transition_forms_are_disallowed() {
        // NAT64 64:ff9b::/96 wrapping cloud-metadata 169.254.169.254.
        let nat64: Ipv6Addr = "64:ff9b::a9fe:a9fe".parse().unwrap();
        assert_eq!(
            embedded_ipv4(&nat64),
            Some(Ipv4Addr::new(169, 254, 169, 254))
        );
        assert!(is_disallowed_ip(&IpAddr::V6(nat64)));

        // 6to4 2002::/16 wrapping internal 10.0.0.5 (v4 in bytes 2..6).
        let sixtofour: Ipv6Addr = "2002:a00:5::".parse().unwrap();
        assert_eq!(embedded_ipv4(&sixtofour), Some(Ipv4Addr::new(10, 0, 0, 5)));
        assert!(is_disallowed_ip(&IpAddr::V6(sixtofour)));

        // IPv4-compatible ::/96 wrapping 169.254.169.254.
        let compat: Ipv6Addr = "::a9fe:a9fe".parse().unwrap();
        assert_eq!(embedded_ipv4(&compat), Some(Ipv4Addr::new(169, 254, 169, 254)));
        assert!(is_disallowed_ip(&IpAddr::V6(compat)));

        // A transition form wrapping a *public* v4 stays allowed.
        let public_6to4: Ipv6Addr = "2002:808:808::".parse().unwrap();
        assert_eq!(embedded_ipv4(&public_6to4), Some(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_disallowed_ip(&IpAddr::V6(public_6to4)));
    }

    #[test]
    fn public_ip_allowed() {
        assert!(!is_disallowed_ip(&IpAddr::V4("8.8.8.8".parse().unwrap())));
        assert!(!is_disallowed_ip(&IpAddr::V4("93.184.216.34".parse().unwrap())));
        assert!(!is_disallowed_ip(&IpAddr::V6("2606:4700:4700::1111".parse().unwrap())));
    }

    #[tokio::test]
    async fn peer_allowed_blocks_internal_and_http() {
        // allow_private short-circuits (tests / loopback pairs).
        assert!(peer_allowed("http://127.0.0.1:9999", true).await);
        // Plaintext http rejected in production mode.
        assert!(!peer_allowed("http://example.com", false).await);
        // Literal internal IP rejected.
        assert!(!peer_allowed("https://169.254.169.254", false).await);
        assert!(!peer_allowed("https://127.0.0.1:8080", false).await);
        assert!(!peer_allowed("https://10.0.0.5", false).await);
        // Unresolvable host rejected (fails closed).
        assert!(!peer_allowed("https://nonexistent.invalid", false).await);
    }

    #[tokio::test]
    async fn relay_peer_allowed_blocks_internal_and_ws() {
        // allow_private short-circuits (tests / loopback pairs).
        assert!(relay_peer_allowed("ws://127.0.0.1:9999", true).await);
        // Plaintext ws rejected in production mode.
        assert!(!relay_peer_allowed("ws://example.com", false).await);
        // Literal internal IP rejected.
        assert!(!relay_peer_allowed("wss://169.254.169.254", false).await);
        assert!(!relay_peer_allowed("wss://127.0.0.1:8080", false).await);
        assert!(!relay_peer_allowed("wss://10.0.0.5", false).await);
        // Unresolvable host rejected (fails closed).
        assert!(!relay_peer_allowed("wss://nonexistent.invalid", false).await);
    }
}

/// Spawn the mirror worker. Called once from `RelayServer::start` when
/// private repos AND mirroring are enabled.
pub(crate) fn spawn(svc: Arc<PrivateService>) -> JoinHandle<()> {
    let (tx, mut rx) = unbounded_channel::<MirrorJob>();
    let _ = svc.mirror_tx.set(tx);

    let fetch_timeout = Duration::from_secs(svc.cfg.mirror_fetch_timeout_secs.max(1));
    let max_concurrency = svc.cfg.mirror_max_concurrency.max(1) as usize;
    let repair_interval = if std::env::var("NGIT_TEST").as_deref() == Ok("1") {
        Duration::from_secs(1)
    } else {
        Duration::from_secs(60)
    };

    tokio::spawn(async move {
        let client = match reqwest::Client::builder()
            .timeout(fetch_timeout)
            // No redirect-chasing — a peer must not bounce us to an internal host.
            .redirect(reqwest::redirect::Policy::none())
            .build()
        {
            Ok(client) => client,
            Err(e) => {
                tracing::error!("private mirror: failed to build HTTP client: {e}");
                return;
            }
        };
        let semaphore = Arc::new(Semaphore::new(max_concurrency));
        // Blobs currently being fetched — dedups queue jobs vs repair scans.
        let inflight: Arc<parking_lot::Mutex<HashSet<String>>> =
            Arc::new(parking_lot::Mutex::new(HashSet::new()));

        tracing::info!(
            max_concurrency = max_concurrency,
            fetch_timeout_secs = fetch_timeout.as_secs(),
            repair_interval_secs = repair_interval.as_secs(),
            "private blob mirror worker started"
        );

        let mut repair = tokio::time::interval(repair_interval);
        // First tick fires immediately → boot repair pass re-enqueues
        // missing blobs for all live 30641-referenced claims.
        loop {
            let jobs: Vec<MirrorJob> = tokio::select! {
                job = rx.recv() => match job {
                    Some(job) => vec![job],
                    None => break,
                },
                _ = repair.tick() => scan_missing(&svc),
            };

            for job in jobs {
                let job = Arc::new(job);
                let mut handles = Vec::new();
                for blob in job.want.clone() {
                    if svc.blobs.exists(&blob.sha256) || svc.is_denylisted(&blob.sha256) {
                        continue;
                    }
                    if !inflight.lock().insert(blob.sha256.clone()) {
                        continue; // already being fetched
                    }
                    let permit = match semaphore.clone().acquire_owned().await {
                        Ok(permit) => permit,
                        Err(_) => return, // semaphore closed — shutting down
                    };
                    let svc = svc.clone();
                    let client = client.clone();
                    let job = job.clone();
                    let inflight = inflight.clone();
                    handles.push(tokio::spawn(async move {
                        let _permit = permit;
                        fetch_blob(&svc, &client, &job, &blob).await;
                        inflight.lock().remove(&blob.sha256);
                    }));
                }
                // B5: recompute the lag gauge ONCE per job after all its blob
                // fetches finish, instead of once per blob. `update_lag` scans
                // the whole blob_claims table, so the per-blob call turned a
                // full-table scan into a hot loop under load. A join task keeps
                // the main loop free to accept the next job/repair tick.
                if !handles.is_empty() {
                    let svc = svc.clone();
                    tokio::spawn(async move {
                        for handle in handles {
                            let _ = handle.await;
                        }
                        update_lag(&svc);
                    });
                }
            }
        }
    })
}
