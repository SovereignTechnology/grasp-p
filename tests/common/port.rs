//! Race-free port reservation for test fixtures.
//!
//! ## The race
//!
//! The naive pattern — bind `127.0.0.1:0`, read the kernel-assigned port,
//! drop the listener, hand the bare `u16` to whoever wants it — has a
//! TOCTOU window between drop and the consumer's actual `bind`. During
//! that window, anything else in the process (or, more rarely, another
//! process) can be handed the same port by the kernel.
//!
//! The race is rare on lightly-loaded hardware but has been observed in
//! CI and during development, and the failure mode
//! (`Address already in use (os error 98)`) is a hard test fail with no
//! useful information for the next debugger. The hazard is sharply worse
//! in patterns that reserve a port well in advance of binding (e.g.
//! pre-allocating a port to embed in an announcement event before
//! starting the relay that will host it).
//!
//! Our in-process fixtures ([`MockRelay`], [`SmartGitServer`]) avoid the
//! race entirely by **keeping the listener bound** and handing it
//! straight to their tokio accept loop. That trick doesn't work for the
//! [`TestRelay`] subprocess — `ngit-grasp` binds itself from
//! `NGIT_BIND_ADDRESS`, and inheriting the pre-bound fd would require
//! Unix-specific `pre_exec` plumbing we'd rather not own in the test
//! harness.
//!
//! ## The reservation pattern
//!
//! Instead, [`reserve_port`] returns a [`PortReservation`] that **holds the
//! bound `TcpListener`** until the caller is about to start the real
//! service. While any reservation is live, no other call to
//! `reserve_port` in this process can be handed the same port — the
//! kernel won't reissue a port that is currently bound.
//!
//! The caller drops the reservation immediately before the real bind,
//! shrinking the TOCTOU window from "however long the fixture takes to
//! spawn" (or, worse, "however long the test takes to build the
//! announcement event") to "a few microseconds inside the start
//! function". The retry loop in [`crate::common::relay::TestRelay`]
//! covers that residual window — defense-in-depth that has never been
//! observed to fire in local stress runs.
//!
//! [`MockRelay`]: crate::common::mock_relay::MockRelay
//! [`SmartGitServer`]: crate::common::git_server::SmartGitServer
//! [`TestRelay`]: crate::common::relay::TestRelay

use std::net::TcpListener;

/// A port that the kernel has assigned to us via `:0` bind, held open by
/// a live `TcpListener` so that no other [`reserve_port`] call in this
/// process can be handed the same number.
///
/// The reservation is released by:
///
/// - calling [`PortReservation::release`] to consume the reservation and
///   return the port number (preferred — makes the release explicit at the
///   call site), or
/// - simply dropping the value (also fine, but the release point is then
///   tied to lexical scope).
///
/// The caller should release **immediately** before the consuming service
/// performs its own `bind` so that the TOCTOU window between
/// reservation-release and service-bind is as small as possible.
#[derive(Debug)]
pub struct PortReservation {
    port: u16,
    /// The listener whose binding holds the port. Dropped on
    /// [`Self::release`] or when the reservation goes out of scope.
    _listener: TcpListener,
}

/// Reserve a specific loopback port.
///
/// Used by restart flows that must reuse an address already embedded in
/// published events (e.g. a repository announcement naming the relay's
/// domain). Fails while the port is still bound — callers should wait
/// for the previous holder to exit and retry within a bounded deadline.
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

    /// Consume the reservation, dropping the underlying listener and
    /// returning the port number. The port is now free for the caller's
    /// real service to bind. Prefer this over relying on lexical drop —
    /// it makes the release point explicit at the call site.
    pub fn release(self) -> u16 {
        let port = self.port;
        // `self` is consumed; the listener inside is dropped here.
        drop(self);
        port
    }
}

/// Bind `127.0.0.1:0`, capture the assigned port, and **keep the listener
/// bound** inside the returned [`PortReservation`] until the caller
/// releases it.
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

    // Note: there is intentionally no "released port is immediately
    // bindable" unit test. Once released, the port re-enters the
    // kernel's free pool, and under heavy parallel test load (where
    // dozens of `reserve_port` / `TcpListener::bind("127.0.0.1:0")`
    // calls are racing each other) another test can be handed that
    // port number before this one rebinds. That race is exactly what
    // `reserve_port` exists to suppress for the held-reservation
    // window; once released, it is by design out of scope. The
    // "bindable after release" property is implicitly exercised by
    // every passing `TestRelay::start*` integration test.
}
