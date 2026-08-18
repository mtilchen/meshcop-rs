//! `embedded-nal-async` adapter for OpenThread's native UDP socket.

use core::{
    fmt,
    net::{SocketAddr, SocketAddrV6},
};

use embedded_io_async::ErrorKind;
use embedded_nal_async::UnconnectedUdp;
use openthread::{OtError, UdpSocket};

/// Maximum DTLS datagram accepted by the `mesh50-dtls` embedded driver.
pub(crate) const UDP_RX_BUFFER_SIZE: usize = 4_096;

/// An unconnected UDP transport backed by an OpenThread native UDP socket.
pub(crate) struct ThreadUdp<'a> {
    socket: UdpSocket<'a>,
    bound_port: u16,
    rx_buffer: [u8; UDP_RX_BUFFER_SIZE],
}

impl<'a> ThreadUdp<'a> {
    /// Creates an adapter for a socket already bound to `bound_port`.
    pub(crate) const fn new(socket: UdpSocket<'a>, bound_port: u16) -> Self {
        Self {
            socket,
            bound_port,
            rx_buffer: [0; UDP_RX_BUFFER_SIZE],
        }
    }
}

/// Errors raised at the OpenThread UDP adapter boundary.
#[derive(Debug)]
pub(crate) enum ThreadUdpError {
    /// OpenThread rejected a native UDP operation.
    OpenThread(OtError),
    /// `mesh50-dtls` supplied an IPv4 address to this IPv6-only transport.
    Ipv4Unsupported,
    /// A send requested a local port different from the bound socket.
    LocalPortMismatch { requested: u16, bound: u16 },
}

impl fmt::Display for ThreadUdpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenThread(error) => write!(formatter, "OpenThread UDP error: {error}"),
            Self::Ipv4Unsupported => formatter.write_str("OpenThread transport requires IPv6"),
            Self::LocalPortMismatch { requested, bound } => write!(
                formatter,
                "local UDP port {requested} does not match bound port {bound}"
            ),
        }
    }
}

impl core::error::Error for ThreadUdpError {}

impl embedded_io_async::Error for ThreadUdpError {
    fn kind(&self) -> ErrorKind {
        match self {
            Self::OpenThread(_) => ErrorKind::Other,
            Self::Ipv4Unsupported | Self::LocalPortMismatch { .. } => ErrorKind::InvalidInput,
        }
    }
}

impl From<OtError> for ThreadUdpError {
    fn from(error: OtError) -> Self {
        Self::OpenThread(error)
    }
}

impl UnconnectedUdp for &mut ThreadUdp<'_> {
    type Error = ThreadUdpError;

    async fn send(
        &mut self,
        local: SocketAddr,
        remote: SocketAddr,
        data: &[u8],
    ) -> Result<(), Self::Error> {
        let local = ipv6(local)?;
        let remote = ipv6(remote)?;

        if local.port() != 0 && local.port() != self.bound_port {
            return Err(ThreadUdpError::LocalPortMismatch {
                requested: local.port(),
                bound: self.bound_port,
            });
        }

        let source = if local.ip().is_unspecified() {
            None
        } else {
            Some(SocketAddrV6::new(
                *local.ip(),
                self.bound_port,
                local.flowinfo(),
                local.scope_id(),
            ))
        };

        self.socket.send(data, source.as_ref(), &remote).await?;
        Ok(())
    }

    async fn receive_into(
        &mut self,
        buffer: &mut [u8],
    ) -> Result<(usize, SocketAddr, SocketAddr), Self::Error> {
        let (length, local, remote) = self.socket.recv(&mut self.rx_buffer).await?;
        let copied = length.min(buffer.len());
        buffer[..copied].copy_from_slice(&self.rx_buffer[..copied]);

        Ok((length, SocketAddr::V6(local), SocketAddr::V6(remote)))
    }
}

fn ipv6(address: SocketAddr) -> Result<SocketAddrV6, ThreadUdpError> {
    match address {
        SocketAddr::V6(address) => Ok(address),
        SocketAddr::V4(_) => Err(ThreadUdpError::Ipv4Unsupported),
    }
}
