//! The metrics endpoint of a GRASP-P node.
//!
//! Upstream answers `/metrics` on the public listener, to anyone, with a
//! wildcard CORS header. On a node that hosts private repositories the scrape
//! carries figures that are not public: how many private repositories there
//! are, how many bytes they hold, how many takedowns and reports came in. So
//! with GRASP-P enabled the public listener answers `/metrics` like any
//! unknown path (the seam is in `src/http/mod.rs`), and the scrape is served
//! here instead, by a listener of its own that binds a loopback address only.
//!
//! The listener exists only when `NGIT_GRASP_P_METRICS_BIND` is set. Without
//! it the metrics are still collected, exactly as upstream collects them, and
//! served nowhere. Collection is left alone because the server uses the same
//! object for more than the scrape: the warning about one address holding too
//! many connections is logged from it.
//!
//! Loopback is not authentication: every process on the host can connect.
//! The peer check in the accept loop is a second line behind the bind
//! address, not a credential.

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::header::{HeaderValue, CONTENT_TYPE, HOST};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};

use crate::config::Config;
use crate::metrics::Metrics;

/// The setting that turns the endpoint on, as error messages name it.
pub const SETTING: &str = "NGIT_GRASP_P_METRICS_BIND";

/// Start of the startup log line; the address the listener really got
/// follows it and ends the line. Public because the test fixture binds port
/// 0 and finds the port from this line, so the wording cannot change on one
/// side only.
pub const LISTENING_LOG: &str = "Private metrics endpoint listening on ";

/// Start of the startup log line of a GRASP-P node that collects metrics and
/// has no endpoint. Public for the same reason: a test that expects no
/// endpoint looks for this line first, and only then trusts that the other
/// one is absent.
pub const NOT_SERVED_LOG: &str = "Private metrics are collected and served nowhere";

/// The content type of the text format, as the encoder that renders the
/// scrape names it.
const SCRAPE_CONTENT_TYPE: &str = prometheus::TEXT_FORMAT;

/// A failing `accept` usually means the process is out of file descriptors.
/// Waiting keeps the loop from spinning until some are free again.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(250);

/// Read a value of `NGIT_GRASP_P_METRICS_BIND`.
///
/// It has to be an IP address and a port. A host name is refused even when it
/// would resolve to loopback today: what a name resolves to is decided
/// outside this process, and can change after the check. An IPv4-mapped IPv6
/// address is refused as well, since it is not a loopback address of the
/// IPv6 stack.
pub fn parse_bind(value: &str) -> Result<SocketAddr, String> {
    let address: SocketAddr = value.trim().parse().map_err(|_| {
        format!(
            "{SETTING} must be an IP address and a port, such as 127.0.0.1:9464 or \
             [::1]:9464, and never a host name; got '{value}'"
        )
    })?;
    if !address.ip().is_loopback() {
        return Err(format!(
            "{SETTING} must be a loopback address (127.0.0.1 or [::1]): the scrape of a \
             node with private repositories is not public; got '{address}'"
        ));
    }
    Ok(address)
}

/// Bind the endpoint and start serving it, when this node is to have one.
///
/// Returns `None` on a node without GRASP-P, which keeps upstream's public
/// route, and on a GRASP-P node with no bind address. The socket is bound
/// before this returns, so an address that is taken or cannot be bound is an
/// error the caller can stop startup on, and not a warning from a task that
/// nobody reads while the node runs without its alerts.
///
/// The returned task owns the listener and every open connection. Aborting
/// it closes them all.
pub async fn start(
    config: &Config,
    metrics: Option<&Arc<Metrics>>,
) -> Result<Option<JoinHandle<()>>> {
    if !config.private_repos_enable {
        return Ok(None);
    }
    let Some(address) = config.private_metrics_bind_addr()? else {
        if metrics.is_some() {
            tracing::info!(
                "{NOT_SERVED_LOG}: with GRASP-P enabled the public listener does not answer \
                 /metrics. Set {SETTING} to a loopback address, such as 127.0.0.1:9464, to \
                 serve them there"
            );
        }
        return Ok(None);
    };
    let Some(metrics) = metrics else {
        // Config validation refuses this pair first. Checked again here so
        // that this function cannot bind a listener with nothing to serve.
        bail!("{SETTING} is set while NGIT_METRICS_ENABLED=false: there are no metrics to serve");
    };
    let listener = bind(address).await?;
    let local_address = listener
        .local_addr()
        .with_context(|| format!("{SETTING}: the listener on {address} has no local address"))?;
    tracing::info!("{LISTENING_LOG}{local_address}");
    Ok(Some(tokio::spawn(serve(listener, metrics.clone()))))
}

async fn bind(address: SocketAddr) -> Result<TcpListener> {
    TcpListener::bind(address)
        .await
        .with_context(|| format!("{SETTING}: cannot listen on {address}"))
}

/// Accept connections until the task is aborted.
async fn serve(listener: TcpListener, metrics: Arc<Metrics>) {
    // The connections live in this task, so that aborting it at shutdown
    // drops the set and with it every connection still open.
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, peer)) if peer.ip().is_loopback() => {
                        connections.spawn(serve_connection(stream, metrics.clone()));
                    }
                    Ok((_, peer)) => {
                        // The bind address already keeps other hosts out.
                        // This holds if the socket is ever reached some
                        // other way. The connection is closed unanswered.
                        tracing::warn!(
                            %peer,
                            "Private metrics endpoint closed a connection that did not come \
                             from a loopback address"
                        );
                    }
                    Err(error) => {
                        tracing::warn!(
                            %error,
                            "Private metrics endpoint could not accept a connection"
                        );
                        tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                    }
                }
            }
            // Take finished connections out of the set, or it would grow by
            // one entry for every scrape.
            _ = connections.join_next(), if !connections.is_empty() => {}
        }
    }
}

async fn serve_connection(stream: TcpStream, metrics: Arc<Metrics>) {
    let service = service_fn(move |request: Request<Incoming>| {
        let wanted = if host_is_local(request.headers().get(HOST)) {
            route(request.method(), request.uri().path())
        } else {
            Route::NotFound
        };
        let metrics = metrics.clone();
        async move { Ok::<_, Infallible>(respond(wanted, &metrics).await) }
    });
    if let Err(error) = http1::Builder::new()
        // Without a timer hyper never gives up on a client that sends no
        // request head, and each such connection holds a descriptor the
        // public listener also needs. With one, its default of 30 seconds
        // applies, to an idle kept-alive connection as well.
        .timer(TokioTimer::new())
        .serve_connection(TokioIo::new(stream), service)
        .await
    {
        tracing::debug!(%error, "Private metrics endpoint connection ended with an error");
    }
}

/// What a request is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    Scrape,
    NotFound,
}

/// Only `GET /metrics` is the scrape. Nothing else has a meaning here, so
/// nothing else is answered with more than a status.
fn route(method: &Method, path: &str) -> Route {
    if method == Method::GET && path == "/metrics" {
        Route::Scrape
    } else {
        Route::NotFound
    }
}

/// Whether `Host` names this endpoint the way a local client does: a
/// loopback address or `localhost`, with or without a port. A page from
/// another site can point its own name at 127.0.0.1 and then read the scrape
/// as same-origin, with no CORS header needed; its requests still carry that
/// name here. A request with no `Host` cannot come from a browser.
fn host_is_local(host: Option<&HeaderValue>) -> bool {
    let Some(host) = host else {
        return true;
    };
    let Ok(host) = host.to_str() else {
        return false;
    };
    let address = host
        .parse::<SocketAddr>()
        .map(|address| address.ip())
        .or_else(|_| {
            host.trim_start_matches('[')
                .trim_end_matches(']')
                .parse::<IpAddr>()
        });
    match address {
        Ok(ip) => ip.is_loopback(),
        Err(_) => host
            .rsplit_once(':')
            .map_or(host, |(name, _)| name)
            .eq_ignore_ascii_case("localhost"),
    }
}

async fn respond(wanted: Route, metrics: &Metrics) -> Response<Full<Bytes>> {
    match wanted {
        Route::Scrape => match metrics.render_async().await {
            Ok(text) => scrape_response(Some(text)),
            Err(error) => {
                tracing::error!(%error, "Metrics render worker failed");
                scrape_response(None)
            }
        },
        Route::NotFound => not_found(),
    }
}

/// The answer to a scrape: the rendered text, or a 500 when rendering failed.
///
/// No response of this endpoint carries a CORS header. Upstream's public
/// route sends a wildcard, which lets any web page a local browser has open
/// read the scrape of a server on the same machine.
fn scrape_response(rendered: Option<String>) -> Response<Full<Bytes>> {
    match rendered {
        Some(text) => {
            let mut response = Response::new(Full::new(Bytes::from(text)));
            response
                .headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static(SCRAPE_CONTENT_TYPE));
            response
        }
        None => {
            let mut response = Response::new(Full::new(Bytes::from_static(
                b"Metrics temporarily unavailable",
            )));
            *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            response
        }
    }
}

fn not_found() -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::new()));
    *response.status_mut() = StatusCode::NOT_FOUND;
    response
}

#[cfg(test)]
mod tests {
    use http_body_util::BodyExt;

    use super::*;

    async fn body_of(response: Response<Full<Bytes>>) -> Bytes {
        response
            .into_body()
            .collect()
            .await
            .expect("a full body cannot fail")
            .to_bytes()
    }

    fn cors_headers(response: &Response<Full<Bytes>>) -> Vec<String> {
        response
            .headers()
            .keys()
            .map(|name| name.as_str().to_string())
            .filter(|name| name.starts_with("access-control-"))
            .collect()
    }

    #[test]
    fn metrics_bind_accepts_loopback_only() {
        for accepted in [
            "127.0.0.1:9464",
            "[::1]:9464",
            "127.0.0.1:0",
            " 127.0.0.1:9464 ",
        ] {
            let address = parse_bind(accepted)
                .unwrap_or_else(|error| panic!("{accepted:?} must be accepted: {error}"));
            assert!(address.ip().is_loopback(), "{accepted:?}");
        }
        for refused in [
            "0.0.0.0:9464",
            "[::]:9464",
            "10.0.0.1:9464",
            "192.0.2.7:9464",
            "localhost:9464",
            "[::ffff:127.0.0.1]:9464",
            "127.0.0.1",
            "9464",
            "",
        ] {
            let error = parse_bind(refused).expect_err(refused);
            assert!(
                error.contains(SETTING),
                "the refusal of {refused:?} must name the setting: {error}"
            );
        }
    }

    #[test]
    fn route_serves_only_get_metrics() {
        assert_eq!(route(&Method::GET, "/metrics"), Route::Scrape);
        for (method, path) in [
            (Method::POST, "/metrics"),
            (Method::HEAD, "/metrics"),
            (Method::PUT, "/metrics"),
            (Method::DELETE, "/metrics"),
            (Method::OPTIONS, "/metrics"),
            (Method::GET, "/"),
            (Method::GET, "/metrics/"),
            (Method::GET, "/metrics/extra"),
            (Method::GET, "//metrics"),
            (Method::GET, "/Metrics"),
            (Method::GET, "/upload"),
            (Method::GET, "/grasp/metrics"),
        ] {
            assert_eq!(route(&method, path), Route::NotFound, "{method} {path}");
        }
    }

    #[test]
    fn scrape_is_answered_only_to_a_local_host_name() {
        assert!(
            host_is_local(None),
            "a request with no Host is not from a browser"
        );
        for local in [
            "127.0.0.1:9464",
            "127.0.0.1",
            "[::1]:9464",
            "[::1]",
            "localhost:9464",
            "LOCALHOST",
        ] {
            assert!(
                host_is_local(Some(&HeaderValue::from_static(local))),
                "{local} names the endpoint as a local client does"
            );
        }
        for foreign in [
            "example.com",
            "example.com:9464",
            "10.0.0.1:9464",
            "[2001:db8::1]:9464",
            "127.0.0.1.example.com:9464",
            "localhost.example.com",
            "",
        ] {
            assert!(
                !host_is_local(Some(&HeaderValue::from_static(foreign))),
                "{foreign:?} is not a local name"
            );
        }
        let opaque = HeaderValue::from_bytes(b"\xff").expect("a legal header value");
        assert!(!host_is_local(Some(&opaque)), "a Host that is not text");
    }

    #[tokio::test]
    async fn metrics_response_has_no_cors_headers() {
        let scrape = scrape_response(Some("ngit_uptime_seconds 1\n".to_string()));
        assert_eq!(scrape.status(), StatusCode::OK);
        let content_type = scrape
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .expect("the scrape states its content type")
            .to_string();
        assert_eq!(content_type, "text/plain; version=0.0.4");
        assert!(cors_headers(&scrape).is_empty(), "{:?}", scrape.headers());
        assert_eq!(body_of(scrape).await, "ngit_uptime_seconds 1\n");

        let failed = scrape_response(None);
        assert_eq!(failed.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(cors_headers(&failed).is_empty(), "{:?}", failed.headers());

        let missing = not_found();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        assert!(missing.headers().is_empty(), "{:?}", missing.headers());
        assert!(body_of(missing).await.is_empty());
    }

    #[tokio::test]
    async fn endpoint_refuses_a_port_in_use() {
        let taken = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
        let address = taken.local_addr().expect("local address");

        let error = bind(address)
            .await
            .expect_err("an address another listener holds cannot be bound again");
        let message = format!("{error:#}");
        assert!(
            message.contains(SETTING) && message.contains(&address.to_string()),
            "the error must name the setting and the address: {message}"
        );

        // The same call binds an address nobody holds, so the refusal above
        // was about the listener in the way. Port 0 and not the port just
        // tested: releasing that one to bind it again would race every other
        // test that asks the kernel for a port.
        let free: SocketAddr = "127.0.0.1:0".parse().expect("test address");
        let listener = bind(free).await.expect("a free loopback port binds");
        let bound = listener.local_addr().expect("local address");
        assert!(bound.ip().is_loopback() && bound.port() != 0, "{bound}");
        assert_ne!(bound, address);
        drop(taken);
    }

    #[tokio::test]
    async fn no_endpoint_without_grasp_p_or_without_a_bind() {
        // Without GRASP-P the setting is not even read: the node keeps
        // upstream's public route.
        let off = Config {
            private_metrics_bind: Some("not an address".to_string()),
            ..Config::for_testing()
        };
        assert!(start(&off, None).await.expect("ignored").is_none());

        for unset in [None, Some(String::new()), Some("  ".to_string())] {
            let config = Config {
                private_repos_enable: true,
                private_metrics_bind: unset.clone(),
                ..Config::for_testing()
            };
            assert!(
                start(&config, None)
                    .await
                    .expect("no bind is not an error")
                    .is_none(),
                "{unset:?} must start no endpoint"
            );
        }

        // A bind address with metrics off has nothing to serve. Validation
        // says so first; this function must not bind either.
        let nothing_to_serve = Config {
            private_repos_enable: true,
            private_metrics_bind: Some("127.0.0.1:0".to_string()),
            ..Config::for_testing()
        };
        let error = start(&nothing_to_serve, None)
            .await
            .expect_err("a bind without metrics is refused");
        assert!(error.to_string().contains(SETTING), "{error}");
    }
}
