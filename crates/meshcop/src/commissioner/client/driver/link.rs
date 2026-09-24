//! The driver's connection to the border agent: a live DTLS session, or the
//! scripted transport in tests.

use std::net::SocketAddr;

use tokio::net::UdpSocket;

use crate::{Result, crypto::Pskc, error::Error, meshcop::CoapMessage};
use meshcop_dtls::DtlsSession;

#[cfg(any(test, feature = "test-support"))]
use super::super::super::harness::{ScriptedIncoming, ScriptedMeshcopTransport};
use super::super::{DTLS_HANDSHAKE_TIMEOUT, commissioner_trace};

/// Receive window passed to the DTLS layer. The driver's own timers decide
/// when to stop waiting; this only bounds one call, which is then repeated.
const RECEIVE_WINDOW: std::time::Duration = std::time::Duration::from_secs(3600);

pub(in super::super) enum Link {
    /// Boxed: the DTLS session state is much larger than the scripted link.
    Live(Box<LiveLink>),
    #[cfg(any(test, feature = "test-support"))]
    Scripted {
        transport: ScriptedMeshcopTransport,
        open: bool,
    },
}

pub(in super::super) struct LiveLink {
    border_agent: SocketAddr,
    pskc: Pskc,
    session: Option<(UdpSocket, DtlsSession)>,
}

impl Link {
    /// Opens a DTLS session with the border agent.
    pub(in super::super) async fn connect(border_agent: SocketAddr, pskc: &Pskc) -> Result<Self> {
        let session = handshake(border_agent, pskc).await?;
        Ok(Self::Live(Box::new(LiveLink {
            border_agent,
            pskc: pskc.clone(),
            session: Some(session),
        })))
    }

    /// Returns whether a session is open for sending and receiving.
    pub(super) fn is_open(&self) -> bool {
        match self {
            Self::Live(live) => live.session.is_some(),
            #[cfg(any(test, feature = "test-support"))]
            Self::Scripted { open, .. } => *open,
        }
    }

    /// Drops the DTLS session, if any.
    pub(super) fn close(&mut self) {
        match self {
            Self::Live(live) => live.session = None,
            #[cfg(any(test, feature = "test-support"))]
            Self::Scripted { open, .. } => *open = false,
        }
    }

    /// Opens a new DTLS session, from a new local port, after the border agent
    /// closed the previous one.
    pub(super) async fn reopen(&mut self) -> Result<()> {
        match self {
            Self::Live(live) => {
                live.session = None;
                live.session = Some(handshake(live.border_agent, &live.pskc).await?);
                Ok(())
            }
            #[cfg(any(test, feature = "test-support"))]
            Self::Scripted { open, .. } => {
                *open = true;
                Ok(())
            }
        }
    }

    /// Sends a request for the first time.
    ///
    /// The scripted transport treats this as the start of a scripted exchange;
    /// on the live link it is the same as [`Link::send`].
    pub(super) async fn send_request(&mut self, message: &CoapMessage) -> Result<()> {
        match self {
            Self::Live(_) => self.send(message).await,
            #[cfg(any(test, feature = "test-support"))]
            Self::Scripted { transport, .. } => transport.exchange(message),
        }
    }

    /// Sends a message that does not start an exchange: an acknowledgement,
    /// a retransmission, or a relayed joiner record.
    pub(super) async fn send(&mut self, message: &CoapMessage) -> Result<()> {
        match self {
            Self::Live(live) => {
                let (socket, session) = live
                    .session
                    .as_mut()
                    .ok_or(Error::InvalidState("DTLS session is not established"))?;
                let wire = message.encode()?;
                session
                    .send_application_data(socket, &wire)
                    .await
                    .map_err(Error::from)
            }
            #[cfg(any(test, feature = "test-support"))]
            Self::Scripted { transport, .. } => transport.record_sent(message.clone()),
        }
    }

    /// Receives the next protected datagram's plaintext.
    ///
    /// Cancel-safe: the only suspension point is the socket receive. Never
    /// completes while no session is open.
    pub(super) async fn recv(&mut self) -> Result<Vec<u8>> {
        match self {
            Self::Live(live) => {
                let Some((socket, session)) = live.session.as_mut() else {
                    return core::future::pending().await;
                };
                loop {
                    match session.recv_application_data(socket, RECEIVE_WINDOW).await {
                        Err(meshcop_dtls::Error::Timeout(_)) => continue,
                        result => return result.map_err(Error::from),
                    }
                }
            }
            #[cfg(any(test, feature = "test-support"))]
            Self::Scripted { transport, open } => {
                if !*open {
                    return core::future::pending().await;
                }
                match transport.next_incoming() {
                    Some(ScriptedIncoming::Message(message)) => message.encode(),
                    Some(ScriptedIncoming::PeerClosed) => {
                        Err(Error::Dtls(meshcop_dtls::Error::PeerClosed))
                    }
                    Some(ScriptedIncoming::TransportFailure) => Err(Error::Io(
                        std::io::Error::other("scripted transport failure"),
                    )),
                    None => core::future::pending().await,
                }
            }
        }
    }
}

async fn handshake(border_agent: SocketAddr, pskc: &Pskc) -> Result<(UdpSocket, DtlsSession)> {
    let bind_addr = if border_agent.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    socket.connect(border_agent).await?;
    // Boxed: the EC J-PAKE handshake future is large, and callers of
    // `Commissioner::connect` would otherwise carry it on their stack.
    let session = tokio::time::timeout(
        DTLS_HANDSHAKE_TIMEOUT,
        Box::pin(DtlsSession::connect(
            &socket,
            pskc.as_bytes(),
            DTLS_HANDSHAKE_TIMEOUT,
        )),
    )
    .await
    .map_err(|_| Error::Timeout("DTLS handshake timed out"))??;
    commissioner_trace(format_args!("DTLS session established with {border_agent}"));
    Ok((socket, session))
}
