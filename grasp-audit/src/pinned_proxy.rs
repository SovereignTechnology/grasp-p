use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};

/// A loopback-only SOCKS5 proxy that connects exclusively to pre-resolved
/// addresses for one expected origin.
pub(crate) struct PinnedSocksProxy {
    address: SocketAddr,
    task: JoinHandle<()>,
}

impl PinnedSocksProxy {
    pub(crate) async fn start(
        expected_host: String,
        expected_port: u16,
        addresses: Vec<SocketAddr>,
    ) -> io::Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let address = listener.local_addr()?;
        let expected_host: Arc<str> = expected_host.into();
        let addresses = Arc::new(addresses);
        let task = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else {
                            break;
                        };
                        let expected_host = Arc::clone(&expected_host);
                        let addresses = Arc::clone(&addresses);
                        connections.spawn(async move {
                            let _ = proxy_connection(
                                stream,
                                &expected_host,
                                expected_port,
                                &addresses,
                            )
                            .await;
                        });
                    }
                    Some(_) = connections.join_next(), if !connections.is_empty() => {}
                }
            }
        });

        Ok(Self { address, task })
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }
}

impl Drop for PinnedSocksProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn proxy_connection(
    mut client: TcpStream,
    expected_host: &str,
    expected_port: u16,
    addresses: &[SocketAddr],
) -> io::Result<()> {
    let mut greeting = [0_u8; 2];
    client.read_exact(&mut greeting).await?;
    if greeting[0] != 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported SOCKS version",
        ));
    }

    let mut methods = vec![0_u8; greeting[1] as usize];
    client.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        client.write_all(&[5, 0xff]).await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS client did not offer no-auth",
        ));
    }
    client.write_all(&[5, 0]).await?;

    let mut request = [0_u8; 4];
    client.read_exact(&mut request).await?;
    if request[..3] != [5, 1, 0] {
        send_reply(&mut client, 7).await?;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported SOCKS request",
        ));
    }

    let requested_host = match request[3] {
        1 => {
            let mut octets = [0_u8; 4];
            client.read_exact(&mut octets).await?;
            IpAddr::from(octets).to_string()
        }
        3 => {
            let length = client.read_u8().await? as usize;
            let mut bytes = vec![0_u8; length];
            client.read_exact(&mut bytes).await?;
            String::from_utf8(bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid SOCKS domain"))?
        }
        4 => {
            let mut octets = [0_u8; 16];
            client.read_exact(&mut octets).await?;
            IpAddr::from(octets).to_string()
        }
        _ => {
            send_reply(&mut client, 8).await?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported SOCKS address type",
            ));
        }
    };
    let requested_port = client.read_u16().await?;

    if !requested_host.eq_ignore_ascii_case(expected_host) || requested_port != expected_port {
        send_reply(&mut client, 2).await?;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS target does not match hardened relay",
        ));
    }

    let mut upstream = None;
    for address in addresses {
        if let Ok(stream) = TcpStream::connect(address).await {
            upstream = Some(stream);
            break;
        }
    }
    let Some(mut upstream) = upstream else {
        send_reply(&mut client, 5).await?;
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "all pinned relay addresses failed",
        ));
    };

    send_reply(&mut client, 0).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

async fn send_reply(stream: &mut TcpStream, status: u8) -> io::Result<()> {
    stream.write_all(&[5, status, 0, 1, 0, 0, 0, 0, 0, 0]).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connects_only_to_the_pinned_address() {
        let upstream = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let upstream_address = upstream.local_addr().unwrap();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let byte = stream.read_u8().await.unwrap();
            stream.write_u8(byte + 1).await.unwrap();
        });

        let proxy = PinnedSocksProxy::start("relay.example".into(), 443, vec![upstream_address])
            .await
            .unwrap();
        let mut client = TcpStream::connect(proxy.address()).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [5, 0]);

        let host = b"relay.example";
        client
            .write_all(&[5, 1, 0, 3, host.len() as u8])
            .await
            .unwrap();
        client.write_all(host).await.unwrap();
        client.write_u16(443).await.unwrap();
        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0);

        client.write_u8(41).await.unwrap();
        assert_eq!(client.read_u8().await.unwrap(), 42);
        upstream_task.await.unwrap();
    }

    #[tokio::test]
    async fn rejects_a_different_origin() {
        let proxy = PinnedSocksProxy::start(
            "relay.example".into(),
            443,
            vec!["127.0.0.1:9".parse().unwrap()],
        )
        .await
        .unwrap();
        let mut client = TcpStream::connect(proxy.address()).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut method = [0_u8; 2];
        client.read_exact(&mut method).await.unwrap();

        let host = b"metadata.internal";
        client
            .write_all(&[5, 1, 0, 3, host.len() as u8])
            .await
            .unwrap();
        client.write_all(host).await.unwrap();
        client.write_u16(443).await.unwrap();
        let mut reply = [0_u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 2);
    }
}
