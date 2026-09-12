//! Private listener handoff protocol for subprocess test fixtures.

use std::os::fd::{FromRawFd, RawFd};

use anyhow::{bail, Context, Result};
use tokio::net::TcpListener;

pub(crate) fn from_env() -> Result<Option<TcpListener>> {
    let Some(fd) = std::env::var_os("NGIT_TEST_LISTENER_FD") else {
        return Ok(None);
    };
    if std::env::var("NGIT_TEST").as_deref() != Ok("1") {
        bail!("NGIT_TEST_LISTENER_FD is available only with NGIT_TEST=1");
    }
    let fd: RawFd = fd
        .to_str()
        .context("listener descriptor is not UTF-8")?
        .parse()
        .context("listener descriptor is not an integer")?;
    listener_from_fd(fd).map(Some)
}

fn listener_from_fd(fd: RawFd) -> Result<TcpListener> {
    if fd < 3 {
        bail!("test listener must not use a standard stream descriptor");
    }
    // dup validates the descriptor and gives this function its own ownership.
    // The inherited descriptor remains open until the test subprocess exits.
    let owned = unsafe { libc::dup(fd) };
    if owned < 0 {
        return Err(std::io::Error::last_os_error()).context("duplicate test listener");
    }
    // SAFETY: dup returned a fresh owned descriptor, consumed exactly once.
    let listener = unsafe { std::net::TcpListener::from_raw_fd(owned) };
    // Do not leak either copy into Git/SSH children spawned by the relay.
    for descriptor in [fd, owned] {
        if unsafe { libc::fcntl(descriptor, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(std::io::Error::last_os_error()).context("protect test listener from exec");
        }
    }
    let mut accepting: libc::c_int = 0;
    let mut length = std::mem::size_of_val(&accepting) as libc::socklen_t;
    // SAFETY: both pointers reference live, correctly sized writable values.
    let result = unsafe {
        libc::getsockopt(
            owned,
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            (&mut accepting as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error()).context("inspect test listener");
    }
    if accepting == 0 || !listener.local_addr()?.ip().is_loopback() {
        bail!("test listener must be a listening loopback TCP socket");
    }
    listener.set_nonblocking(true)?;
    TcpListener::from_std(listener).context("adopt test listener")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[tokio::test]
    async fn adoption_preserves_the_reserved_address() {
        let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = reserved.local_addr().unwrap();
        let listener = listener_from_fd(reserved.as_raw_fd()).unwrap();
        drop(reserved);
        assert_eq!(listener.local_addr().unwrap(), address);
        assert_eq!(
            std::net::TcpListener::bind(address).unwrap_err().kind(),
            std::io::ErrorKind::AddrInUse
        );
        let client = tokio::net::TcpStream::connect(address).await.unwrap();
        let (_, peer) = tokio::time::timeout(std::time::Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(peer, client.local_addr().unwrap());
    }

    #[tokio::test]
    async fn adoption_rejects_non_listener_descriptors() {
        let file = std::fs::File::open("/dev/null").unwrap();
        assert!(listener_from_fd(file.as_raw_fd()).is_err());
        assert!(listener_from_fd(-1).is_err());
    }
}
