use std::borrow::Cow;
use std::net::SocketAddr;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use nostr_sdk::local_relay::LocalRelay;
use nostr_sdk::prelude::{
    nip42, ClientMessage, Kind, PublicKey, RelayMessage, RelayUrl, SubscriptionId, Timestamp,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::private::PrivateAccess;

const AUTH_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_AUTH_ATTEMPTS: usize = 3;
const DUPLEX_BUFFER_BYTES: usize = 64 * 1024;

/// Authenticate a public upgraded WebSocket before attaching it to LocalRelay.
pub async fn authenticate_and_bridge<S>(
    stream: S,
    addr: SocketAddr,
    relay: LocalRelay,
    relay_domain: &str,
    access: PrivateAccess,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut public = WebSocketStream::from_raw_socket(stream, Role::Server, None).await;
    let challenge = SubscriptionId::generate().to_string();
    send_relay_message(
        &mut public,
        RelayMessage::Auth {
            challenge: Cow::Borrowed(&challenge),
        },
    )
    .await?;

    let authenticated = tokio::time::timeout(
        AUTH_TIMEOUT,
        authenticate(&mut public, relay_domain, &challenge, &access),
    )
    .await
    .map_err(|_| "NIP-42 authentication timed out".to_string())??;

    bridge(public, addr, relay, authenticated, access).await
}

async fn authenticate<S>(
    public: &mut WebSocketStream<S>,
    relay_domain: &str,
    challenge: &str,
    access: &PrivateAccess,
) -> Result<PublicKey, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let relay_urls = relay_url_candidates(relay_domain)?;
    let mut attempts = 0;

    while let Some(message) = public.next().await {
        let message = message.map_err(|e| e.to_string())?;
        match message {
            Message::Text(json) => {
                let parsed = ClientMessage::from_json(json.as_bytes());
                match parsed {
                    Ok(ClientMessage::Auth(event)) => {
                        attempts += 1;
                        let valid = event.kind == Kind::Authentication
                            && event.verify().is_ok()
                            && Timestamp::now()
                                .as_secs()
                                .abs_diff(event.created_at.as_secs())
                                <= 120
                            && relay_urls
                                .iter()
                                .any(|url| nip42::is_valid_auth_event(&event, url, challenge));

                        if valid && access.contains(&event.pubkey) {
                            send_relay_message(
                                public,
                                RelayMessage::Ok {
                                    event_id: event.id,
                                    status: true,
                                    message: Cow::Borrowed(""),
                                },
                            )
                            .await?;
                            return Ok(event.pubkey);
                        }

                        let message = if valid {
                            "restricted: authenticated pubkey is not whitelisted"
                        } else {
                            "auth-required: invalid NIP-42 authentication"
                        };
                        send_relay_message(
                            public,
                            RelayMessage::Ok {
                                event_id: event.id,
                                status: false,
                                message: Cow::Borrowed(message),
                            },
                        )
                        .await?;
                        if valid || attempts >= MAX_AUTH_ATTEMPTS {
                            let _ = public.close(None).await;
                            return Err(message.to_string());
                        }
                    }
                    Ok(other) => send_auth_required(public, &other).await?,
                    Err(_) => {
                        send_relay_message(
                            public,
                            RelayMessage::Notice(Cow::Borrowed(
                                "auth-required: authenticate before sending relay messages",
                            )),
                        )
                        .await?;
                    }
                }
            }
            Message::Ping(payload) => public
                .send(Message::Pong(payload))
                .await
                .map_err(|e| e.to_string())?,
            Message::Close(_) => return Err("connection closed before authentication".into()),
            Message::Binary(_) | Message::Pong(_) | Message::Frame(_) => {}
        }
    }

    Err("connection closed before authentication".into())
}

async fn send_auth_required<S>(
    public: &mut WebSocketStream<S>,
    message: &ClientMessage<'_>,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match message {
        ClientMessage::Event(event) => {
            send_relay_message(
                public,
                RelayMessage::Ok {
                    event_id: event.id,
                    status: false,
                    message: Cow::Borrowed("auth-required: authenticate before publishing"),
                },
            )
            .await
        }
        ClientMessage::Req {
            subscription_id, ..
        }
        | ClientMessage::Count {
            subscription_id, ..
        } => {
            send_relay_message(
                public,
                RelayMessage::Closed {
                    subscription_id: Cow::Owned(subscription_id.clone().into_owned()),
                    message: Cow::Borrowed("auth-required: authenticate before reading"),
                },
            )
            .await
        }
        ClientMessage::NegOpen {
            subscription_id, ..
        } => {
            send_relay_message(
                public,
                RelayMessage::NegErr {
                    subscription_id: Cow::Owned(subscription_id.clone().into_owned()),
                    message: Cow::Borrowed("auth-required: authenticate before syncing"),
                },
            )
            .await
        }
        _ => {
            send_relay_message(
                public,
                RelayMessage::Notice(Cow::Borrowed(
                    "auth-required: authenticate before sending relay messages",
                )),
            )
            .await
        }
    }
}

async fn bridge<S>(
    mut public: WebSocketStream<S>,
    addr: SocketAddr,
    relay: LocalRelay,
    authenticated: PublicKey,
    access: PrivateAccess,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (proxy_stream, relay_stream) = tokio::io::duplex(DUPLEX_BUFFER_BYTES);
    let relay_task = tokio::spawn(async move { relay.take_connection(relay_stream, addr).await });
    let mut internal = WebSocketStream::from_raw_socket(proxy_stream, Role::Client, None).await;
    let mut membership = access.subscribe();

    loop {
        tokio::select! {
            changed = membership.changed() => {
                if changed.is_err() || !access.contains(&authenticated) {
                    let _ = public.close(None).await;
                    let _ = internal.close(None).await;
                    break;
                }
            }
            message = public.next() => {
                match message {
                    Some(Ok(message)) if access.contains(&authenticated) => {
                        internal.send(message).await.map_err(|e| e.to_string())?;
                    }
                    Some(Ok(_)) => break,
                    Some(Err(e)) => return Err(e.to_string()),
                    None => break,
                }
            }
            message = internal.next() => {
                match message {
                    Some(Ok(message)) if access.contains(&authenticated) => {
                        public.send(message).await.map_err(|e| e.to_string())?;
                    }
                    Some(Ok(_)) => break,
                    Some(Err(e)) => return Err(e.to_string()),
                    None => break,
                }
            }
        }
    }

    relay_task.abort();
    Ok(())
}

async fn send_relay_message<S>(
    socket: &mut WebSocketStream<S>,
    message: RelayMessage<'_>,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    socket
        .send(Message::Text(message.as_json().into()))
        .await
        .map_err(|e| e.to_string())
}

fn relay_url_candidates(domain: &str) -> Result<[RelayUrl; 2], String> {
    let secure = format!("wss://{domain}");
    let insecure = format!("ws://{domain}");
    Ok([
        RelayUrl::parse(&secure).map_err(|e| e.to_string())?,
        RelayUrl::parse(&insecure).map_err(|e| e.to_string())?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_secure_and_loopback_relay_candidates() {
        let urls = relay_url_candidates("private.example").unwrap();
        assert_eq!(urls[0].as_str(), "wss://private.example");
        assert_eq!(urls[1].as_str(), "ws://private.example");
    }
}
