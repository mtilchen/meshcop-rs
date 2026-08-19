//! Tokio-backed DTLS client session preserving the original public API.

use alloc::vec::Vec;
use core::time::Duration;

use tokio::net::UdpSocket;

use crate::{
    Result, ThreadDtlsKeyMaterial, client_driver,
    driver::{SessionRole, SessionState, recv_application_data, send_records},
    tokio_transport::{BorrowedTokioUdpTransport, TokioDelay},
};

/// Established Thread DTLS commissioner session.
#[derive(Debug)]
pub struct DtlsSession {
    state: SessionState,
}

impl DtlsSession {
    /// Creates a session from already-derived key material.
    pub fn new(key_material: ThreadDtlsKeyMaterial) -> Self {
        Self {
            state: SessionState::new(key_material, SessionRole::Client),
        }
    }

    /// Returns the derived key material.
    pub const fn key_material(&self) -> &ThreadDtlsKeyMaterial {
        self.state.key_material()
    }

    /// Runs the Thread PSKc/ECJPAKE DTLS handshake over a connected UDP socket.
    pub async fn connect(socket: &UdpSocket, pskc: &[u8], timeout: Duration) -> Result<Self> {
        let mut rng = rand_core::OsRng;
        Self::connect_with_rng(&mut rng, socket, pskc, timeout).await
    }

    /// Runs the handshake using cryptographic randomness supplied by the caller.
    pub async fn connect_with_rng(
        rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
        socket: &UdpSocket,
        pskc: &[u8],
        timeout: Duration,
    ) -> Result<Self> {
        let local = socket.local_addr()?;
        let peer = socket.peer_addr()?;
        let mut transport = BorrowedTokioUdpTransport::new(socket);
        let mut delay = TokioDelay;
        let state = client_driver::connect_with_rng(
            rng,
            &mut transport,
            &mut delay,
            local,
            peer,
            pskc,
            timeout,
        )
        .await
        .map_err(crate::Error::from)?;
        Ok(Self { state })
    }

    /// Sends protected application data and waits for the next protected application record.
    pub async fn request_application_data(
        &mut self,
        socket: &UdpSocket,
        plaintext: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        self.send_application_data(socket, plaintext).await?;
        self.recv_application_data(socket, timeout).await
    }

    /// Sends one protected application-data record.
    pub async fn send_application_data(
        &mut self,
        socket: &UdpSocket,
        plaintext: &[u8],
    ) -> Result<()> {
        let local = socket.local_addr()?;
        let peer = socket.peer_addr()?;
        let record = self.state.protect_application_data(plaintext)?;
        let mut transport = BorrowedTokioUdpTransport::new(socket);
        send_records(&mut transport, local, peer, &[record])
            .await
            .map_err(crate::Error::from)
    }

    /// Receives and opens the next protected application-data record.
    pub async fn recv_application_data(
        &mut self,
        socket: &UdpSocket,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        let peer = socket.peer_addr()?;
        let mut transport = BorrowedTokioUdpTransport::new(socket);
        let mut delay = TokioDelay;
        recv_application_data(&mut self.state, &mut transport, &mut delay, peer, timeout)
            .await
            .map_err(crate::Error::from)
    }
}
