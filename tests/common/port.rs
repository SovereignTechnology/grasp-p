//! Bound listener ownership for test fixtures.
//!
//! Reserving a port and dropping its listener before the server binds leaves
//! a race with every other concurrent test. Instead, retain the listener and
//! transfer it directly to an in-process fixture or through the subprocess
//! listener handoff protocol. Retain a clone across server restarts.
//!
//! [`UnavailableEndpoint`] accepts and closes connections while retaining the
//! address. Recovery stops that accept loop before handing the same listener
//! to the recovered service, so another test can never claim the port.

use std::net::TcpListener;

/// A port that the kernel has assigned to us via `:0` bind, held open by
/// a live `TcpListener` so that no other [`reserve_port`] call in this
/// process can be handed the same number.
///
/// Transfer it with [`PortReservation::into_std_listener`] to start a service
/// without releasing its address. Dropping it relinquishes the address, so a
/// reservation must be transferred, not dropped, to start a service on it.
#[derive(Debug)]
pub struct PortReservation {
    port: u16,
    /// The listener whose binding holds the port. Dropped on
    /// [`Self::release`] or when the reservation goes out of scope.
    _listener: TcpListener,
}

/// Reserve a specific loopback port.
///
/// Fails while another listener owns the address. Restart flows should retain
/// and transfer their existing listener rather than binding again.
pub fn reserve_specific(port: u16) -> std::io::Result<PortReservation> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    Ok(PortReservation {
        port,
        _listener: listener,
    })
}

impl PortReservation {
    /// The kernel-assigned loopback port number held by this reservation.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Transfer the bound listener without making its port available again.
    pub fn into_std_listener(self) -> TcpListener {
        self._listener
    }

    /// Wrap a listener retained across a subprocess restart.
    pub fn from_listener(listener: TcpListener) -> Self {
        Self {
            port: listener
                .local_addr()
                .expect("reserved listener address")
                .port(),
            _listener: listener,
        }
    }
}

/// Bind `127.0.0.1:0`, capture the assigned port, and **keep the listener
/// bound** inside the returned [`PortReservation`] until the caller
/// transfers or drops it.
///
/// While the reservation is live, no other `reserve_port` call in this
/// process will be handed the same port. See module docs for why this
/// matters.
pub fn reserve_port() -> PortReservation {
    let listener =
        TcpListener::bind("127.0.0.1:0").expect("Failed to bind 127.0.0.1:0 for port reservation");
    let port = listener
        .local_addr()
        .expect("Failed to read local_addr from bound listener")
        .port();
    PortReservation {
        port,
        _listener: listener,
    }
}

/// A continuously reserved endpoint that rejects protocol connections until
/// its listener is transferred to a recovered service.
pub struct UnavailableEndpoint {
    listener: Option<TcpListener>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Default for UnavailableEndpoint {
    fn default() -> Self {
        Self::new()
    }
}

impl UnavailableEndpoint {
    pub fn new() -> Self {
        Self::from_listener(reserve_port().into_std_listener())
    }

    pub fn from_listener(listener: TcpListener) -> Self {
        listener
            .set_nonblocking(true)
            .expect("nonblocking unavailable endpoint");
        let accepting = tokio::net::TcpListener::from_std(
            listener.try_clone().expect("retain unavailable listener"),
        )
        .expect("register unavailable listener");
        let task = tokio::spawn(async move {
            loop {
                let (stream, _) = accepting
                    .accept()
                    .await
                    .expect("accept unavailable connection");
                drop(stream);
            }
        });
        Self {
            listener: Some(listener),
            task: Some(task),
        }
    }

    pub fn port(&self) -> u16 {
        self.listener
            .as_ref()
            .expect("owned unavailable listener")
            .local_addr()
            .expect("unavailable address")
            .port()
    }

    pub async fn into_listener(mut self) -> TcpListener {
        if let Some(task) = self.task.take() {
            task.abort();
            match tokio::time::timeout(std::time::Duration::from_secs(5), task)
                .await
                .expect("unavailable accept loop should stop before recovery")
            {
                Err(error) if error.is_cancelled() => {}
                result => panic!("unavailable accept loop ended unexpectedly: {result:?}"),
            }
        }
        self.listener.take().expect("transfer unavailable listener")
    }
}

impl Drop for UnavailableEndpoint {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two reservations held simultaneously must return distinct ports.
    /// This is the core same-process guarantee the reservation pattern
    /// provides — and exactly what the naive "bind, drop, return" pattern
    /// fails to give under parallel load.
    #[test]
    fn parallel_reservations_get_distinct_ports() {
        let a = reserve_port();
        let b = reserve_port();
        let c = reserve_port();
        assert_ne!(a.port(), b.port());
        assert_ne!(b.port(), c.port());
        assert_ne!(a.port(), c.port());
    }

    #[tokio::test]
    async fn unavailable_endpoint_preserves_address_through_recovery() {
        use tokio::io::AsyncReadExt;
        let endpoint = UnavailableEndpoint::new();
        let address = endpoint.listener.as_ref().unwrap().local_addr().unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
            let mut byte = [0];
            match client.read(&mut byte).await {
                Ok(0) => {}
                Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
                result => panic!("unavailable endpoint should close clients: {result:?}"),
            }
        })
        .await
        .expect("unavailable endpoint should reject connections");

        let listener = endpoint.into_listener().await;
        assert_eq!(listener.local_addr().unwrap(), address);
        assert_eq!(
            TcpListener::bind(address).unwrap_err().kind(),
            std::io::ErrorKind::AddrInUse
        );
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let client = tokio::net::TcpStream::connect(address).await.unwrap();
            let (_, peer) = listener.accept().await.unwrap();
            assert_eq!(peer, client.local_addr().unwrap());
        })
        .await
        .expect("recovered listener should own every new connection");
    }
}
