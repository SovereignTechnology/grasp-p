//! In-process WebSocket transport to our own embedded relay.
//!
//! The self-subscription feed is a conversation the service has with itself.
//! Routing it over the public listener means dialling our own socket, which a
//! private instance's NIP-42 gate ([`crate::private::ws_auth`]) correctly
//! refuses: the gate runs in the HTTP layer, ahead of
//! [`LocalRelay::take_connection`], and cannot distinguish us from any other
//! anonymous dialler.
//!
//! This transport hands the relay one end of an in-memory duplex pair and
//! keeps the other, so the subscriber attaches directly to `LocalRelay` with
//! the same framing, subscription handling, and post-save broadcast semantics
//! a network session gets — minus the listener, the auth gate, and the
//! network round trip. The service trusting its own process is not an
//! authentication decision; it is the absence of a remote party.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};

use async_wsocket::message::CloseFrame;
use async_wsocket::Message;
use futures_util::stream::SplitSink;
use futures_util::{Sink, StreamExt};
use nostr_sdk::local_relay::LocalRelay;
use nostr_sdk::prelude::Url;
use nostr_sdk::transport::websocket::{WebSocketSink, WebSocketStream, WebSocketTransport};
use tokio::io::DuplexStream;
use tokio_tungstenite::tungstenite::protocol::{CloseFrame as WsCloseFrame, Role};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::WebSocketStream as TungsteniteStream;

type SdkError = nostr_sdk::error::Error;

/// Duplex capacity for one direction of the in-process pair.
///
/// Matches the private-mode bridge buffer: large enough for the biggest
/// relay frames the subscriber sees without letting a slow consumer buffer
/// unboundedly.
const DUPLEX_BUFFER_BYTES: usize = 64 * 1024;

/// Peer address reported for the in-process session.
///
/// The subscriber only ever reads, so this address never reaches write-policy
/// admission; it exists because `take_connection` requires one.
const IN_PROCESS_PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

/// Connects a [`nostr_sdk::Client`] straight to an embedded [`LocalRelay`].
#[derive(Debug, Clone)]
pub struct InProcessRelayTransport {
    relay: LocalRelay,
}

impl InProcessRelayTransport {
    /// Wrap the embedded relay this service runs.
    pub fn new(relay: LocalRelay) -> Self {
        Self { relay }
    }
}

impl WebSocketTransport for InProcessRelayTransport {
    fn support_ping(&self) -> bool {
        // An in-memory duplex has no idle timeout or half-open state to
        // detect: the stream ends when the relay session task ends.
        false
    }

    fn connect<'a>(
        &'a self,
        _url: &'a Url,
        _proxy: Option<SocketAddr>,
    ) -> Pin<Box<dyn Future<Output = Result<(WebSocketSink, WebSocketStream), SdkError>> + Send + 'a>>
    {
        let relay = self.relay.clone();
        Box::pin(async move {
            let (client_side, relay_side) = tokio::io::duplex(DUPLEX_BUFFER_BYTES);

            // The relay drives its own session; when the subscriber drops its
            // end, `take_connection` observes the closed duplex and returns.
            tokio::spawn(async move {
                if let Err(error) = relay.take_connection(relay_side, IN_PROCESS_PEER).await {
                    tracing::debug!(
                        error = %error,
                        "In-process self-subscription session ended"
                    );
                }
            });

            // `Role::Client` because the relay side applies `Role::Server`:
            // both ends speak ordinary WebSocket framing over the duplex, so
            // no HTTP upgrade handshake is involved on either side.
            let stream = TungsteniteStream::from_raw_socket(client_side, Role::Client, None).await;
            let (sink, stream) = stream.split();

            let sink: WebSocketSink = Box::pin(InProcessSink(sink));
            let stream: WebSocketStream = Box::pin(stream.filter_map(|message| async move {
                match message {
                    Ok(message) => from_ws_message(message).map(Ok),
                    Err(error) => Some(Err(SdkError::transport(error))),
                }
            }));

            Ok((sink, stream))
        })
    }
}

/// Sink adapter translating transport messages into WebSocket frames.
///
/// Written as an explicit [`Sink`] rather than `sink_map_err`, which upstream
/// documents as panic-prone in this position.
struct InProcessSink(SplitSink<TungsteniteStream<DuplexStream>, WsMessage>);

impl Sink<Message> for InProcessSink {
    type Error = SdkError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0)
            .poll_ready(cx)
            .map_err(SdkError::transport)
    }

    fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
        Pin::new(&mut self.0)
            .start_send(into_ws_message(item))
            .map_err(SdkError::transport)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0)
            .poll_flush(cx)
            .map_err(SdkError::transport)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.0)
            .poll_close(cx)
            .map_err(SdkError::transport)
    }
}

/// Convert a transport message into a WebSocket frame.
///
/// Converted by hand rather than through `async_wsocket`'s `From` impl, which
/// targets that crate's own `tokio-tungstenite` version.
fn into_ws_message(message: Message) -> WsMessage {
    match message {
        Message::Text(text) => WsMessage::Text(text.into()),
        Message::Binary(data) => WsMessage::Binary(data.into()),
        Message::Ping(data) => WsMessage::Ping(data.into()),
        Message::Pong(data) => WsMessage::Pong(data.into()),
        Message::Close(frame) => WsMessage::Close(frame.map(|frame| WsCloseFrame {
            code: frame.code.into(),
            reason: frame.reason.into(),
        })),
    }
}

/// Convert a received WebSocket frame into a transport message.
///
/// Raw `Frame` values are never produced while reading a stream, so they are
/// dropped rather than surfaced as a transport failure.
fn from_ws_message(message: WsMessage) -> Option<Message> {
    match message {
        WsMessage::Text(text) => Some(Message::Text(text.to_string())),
        WsMessage::Binary(data) => Some(Message::Binary(data.to_vec())),
        WsMessage::Ping(data) => Some(Message::Ping(data.to_vec())),
        WsMessage::Pong(data) => Some(Message::Pong(data.to_vec())),
        WsMessage::Close(frame) => Some(Message::Close(frame.map(|frame| CloseFrame {
            code: frame.code.into(),
            reason: frame.reason.to_string(),
        }))),
        WsMessage::Frame(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use nostr_sdk::prelude::*;

    use super::*;

    /// The subscriber's live feed must work against a relay that was never
    /// bound to a listener: no port, no auth gate, no network.
    #[tokio::test]
    async fn in_process_client_receives_events_without_a_listener() {
        let database = Arc::new(nostr_memory::MemoryDatabase::unbounded());
        let relay = LocalRelay::builder().database(database).build();

        let client = Client::builder()
            .websocket_transport(InProcessRelayTransport::new(relay.clone()))
            .build();
        client
            .add_relay("ws://in-process.invalid")
            .await
            .expect("add in-process relay");
        client.connect().await;
        client
            .subscribe(Filter::new().kind(Kind::TextNote))
            .await
            .expect("subscribe over the in-process transport");

        let mut notifications = client.notifications();
        let keys = Keys::generate();
        let note = EventBuilder::new(Kind::TextNote, "accepted at runtime")
            .finalize(&keys)
            .expect("signed note");

        // Publishing through the relay exercises the same save-then-broadcast
        // path a client EVENT takes.
        let published = tokio::spawn({
            let relay = relay.clone();
            let note = note.clone();
            async move {
                // Retry until the subscription is registered relay-side;
                // `subscribe` returns once sent, not once processed.
                loop {
                    relay.add_event(note.clone()).await.expect("save event");
                    relay.notify_event(note.clone());
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        });

        let received = tokio::time::timeout(Duration::from_secs(10), async {
            while let Some(notification) = notifications.next().await {
                if let ClientNotification::Event { event, .. } = notification {
                    if event.id == note.id {
                        return;
                    }
                }
            }
        })
        .await;

        published.abort();
        client.disconnect().await;
        assert!(
            received.is_ok(),
            "in-process subscriber must receive relay events"
        );
    }
}
