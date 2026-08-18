//! Tokio adapters for the runtime-neutral driver traits.

use core::net::SocketAddr;

use embedded_hal_async::delay::DelayNs;
use embedded_nal_async::UnconnectedUdp;
use tokio::net::UdpSocket;

use crate::{DtlsServer, DtlsServerSession, Error, Result, driver::DriverError};

/// Tokio UDP socket implementing the runtime-neutral datagram trait.
#[derive(Debug)]
pub struct TokioUdpTransport {
    socket: UdpSocket,
}

impl TokioUdpTransport {
    /// Wraps a bound Tokio UDP socket.
    pub const fn new(socket: UdpSocket) -> Self {
        Self { socket }
    }

    /// Returns the wrapped socket.
    pub const fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Unwraps the socket.
    pub fn into_inner(self) -> UdpSocket {
        self.socket
    }
}

impl UnconnectedUdp for TokioUdpTransport {
    type Error = std::io::Error;

    async fn send(
        &mut self,
        _local: SocketAddr,
        remote: SocketAddr,
        data: &[u8],
    ) -> core::result::Result<(), Self::Error> {
        self.socket.send_to(data, remote).await.map(|_| ())
    }

    async fn receive_into(
        &mut self,
        buffer: &mut [u8],
    ) -> core::result::Result<(usize, SocketAddr, SocketAddr), Self::Error> {
        let (length, remote) = self.socket.recv_from(buffer).await?;
        Ok((length, self.socket.local_addr()?, remote))
    }
}

#[derive(Debug)]
pub(crate) struct BorrowedTokioUdpTransport<'a> {
    socket: &'a UdpSocket,
}

impl<'a> BorrowedTokioUdpTransport<'a> {
    pub(crate) const fn new(socket: &'a UdpSocket) -> Self {
        Self { socket }
    }
}

impl UnconnectedUdp for BorrowedTokioUdpTransport<'_> {
    type Error = std::io::Error;

    async fn send(
        &mut self,
        _local: SocketAddr,
        _remote: SocketAddr,
        data: &[u8],
    ) -> core::result::Result<(), Self::Error> {
        self.socket.send(data).await.map(|_| ())
    }

    async fn receive_into(
        &mut self,
        buffer: &mut [u8],
    ) -> core::result::Result<(usize, SocketAddr, SocketAddr), Self::Error> {
        let (length, remote) = self.socket.recv_from(buffer).await?;
        Ok((length, self.socket.local_addr()?, remote))
    }
}

/// Tokio timer implementing the runtime-neutral delay trait.
#[derive(Debug, Clone, Copy, Default)]
pub struct TokioDelay;

impl DelayNs for TokioDelay {
    async fn delay_ns(&mut self, nanoseconds: u32) {
        tokio::time::sleep(core::time::Duration::from_nanos(u64::from(nanoseconds))).await;
    }
}

impl From<DriverError<std::io::Error>> for Error {
    fn from(error: DriverError<std::io::Error>) -> Self {
        match error {
            DriverError::Protocol(error) => error,
            DriverError::Transport(error) => Self::Io(error),
            DriverError::Timeout => Self::Timeout("DTLS receive timed out"),
        }
    }
}

impl DtlsServer<TokioUdpTransport, TokioDelay> {
    /// Binds a Tokio UDP socket and creates a single-peer DTLS acceptor.
    pub async fn bind(address: impl tokio::net::ToSocketAddrs) -> Result<Self> {
        let socket = UdpSocket::bind(address).await?;
        let local = socket.local_addr()?;
        Ok(Self::new(TokioUdpTransport::new(socket), TokioDelay, local))
    }

    /// Creates a DTLS acceptor from an already-bound Tokio UDP socket.
    pub fn from_socket(socket: UdpSocket) -> Result<Self> {
        let local = socket.local_addr()?;
        Ok(Self::new(TokioUdpTransport::new(socket), TokioDelay, local))
    }

    /// Accepts the first cookie-validated peer using OS randomness.
    pub async fn accept(
        self,
        pskc: &[u8],
        timeout: core::time::Duration,
    ) -> Result<DtlsServerSession<TokioUdpTransport, TokioDelay>> {
        let mut rng = rand_core::OsRng;
        self.accept_with_rng(&mut rng, pskc, timeout)
            .await
            .map_err(Error::from)
    }
}
