//! Async commissioner client.
//!
//! [`Commissioner`] is the connected handle. Its operations are grouped into
//! sibling modules that each `impl Commissioner`: [`datasets`] (operational and
//! commissioner dataset get/set), [`commands`] (announce/scan/PAN-ID and the
//! managed-device commands), [`diagnostics`] (network-diagnostic queries),
//! [`relay`] (joiner relay handling), and [`transport`] (the DTLS session,
//! request/response routing, and UDP-proxy encapsulation). This module holds
//! the struct, the session lifecycle, and the small shared helpers.

use std::{
    collections::{HashMap, VecDeque},
    net::{Ipv6Addr, SocketAddr},
    time::Duration,
};

use tokio::net::UdpSocket;

use crate::{
    Result,
    error::Error,
    meshcop::{self, CommissionerOperation, MeshcopState},
};
use mesh50_dtls::DtlsSession;

#[cfg(any(test, feature = "test-support"))]
use super::harness::ScriptedMeshcopTransport;
use super::{
    config::CommissionerConfig,
    joiner::{JoinerHandler, JoinerSession},
    types::{CommissionerEvent, CommissionerState, PetitionResponse, ResultCode},
};

mod commands;
mod datasets;
mod diagnostics;
mod relay;
mod transport;

/// How a MeshCoP request reaches its destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MeshcopRoute {
    /// Sent directly to the border agent over the commissioner DTLS session.
    Direct,
    /// Encapsulated in UDP_TX.ntf and forwarded to a mesh destination.
    Proxied {
        destination: Ipv6Addr,
        destination_port: u16,
    },
}

/// Connected commissioner handle.
#[derive(Debug)]
pub struct Commissioner {
    config: CommissionerConfig,
    border_agent: SocketAddr,
    socket: UdpSocket,
    state: CommissionerState,
    session_id: Option<u16>,
    dtls_session: Option<DtlsSession>,
    #[cfg(any(test, feature = "test-support"))]
    scripted_transport: Option<ScriptedMeshcopTransport>,
    next_message_id: u16,
    events: VecDeque<CommissionerEvent>,
    mesh_local_prefix: Option<[u8; 8]>,
    joiner_handler: Option<Box<dyn JoinerHandler>>,
    joiner_sessions: HashMap<[u8; 8], JoinerSession>,
}

impl Commissioner {
    /// Connects a UDP socket to a Thread border agent.
    pub async fn connect(config: CommissionerConfig, border_agent: SocketAddr) -> Result<Self> {
        config.validate()?;
        if config.enable_ccm {
            return Err(Error::Unsupported("CCM is reserved but deferred"));
        }
        let bind_addr = if border_agent.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(border_agent).await?;
        Ok(Self {
            config,
            border_agent,
            socket,
            state: CommissionerState::Connected,
            session_id: None,
            dtls_session: None,
            #[cfg(any(test, feature = "test-support"))]
            scripted_transport: None,
            next_message_id: 0,
            events: VecDeque::new(),
            mesh_local_prefix: None,
            joiner_handler: None,
            joiner_sessions: HashMap::new(),
        })
    }

    /// Installs the handler that provides joiner PSKds and finalization
    /// decisions, enabling joiner commissioning sessions.
    ///
    /// Without a handler, relayed joiner traffic surfaces as raw
    /// [`CommissionerEvent::JoinerMessage`] events.
    pub fn set_joiner_handler(&mut self, handler: impl JoinerHandler + 'static) {
        self.joiner_handler = Some(Box::new(handler));
    }

    /// Removes the joiner handler and drops in-progress joiner sessions.
    pub fn clear_joiner_handler(&mut self) {
        self.joiner_handler = None;
        self.joiner_sessions.clear();
    }

    /// Returns the commissioner state.
    pub const fn state(&self) -> CommissionerState {
        self.state
    }

    /// Returns the active commissioner session ID, when known.
    pub const fn session_id(&self) -> Option<u16> {
        self.session_id
    }

    /// Returns the configured border-agent address.
    pub const fn border_agent(&self) -> SocketAddr {
        self.border_agent
    }

    /// Returns the commissioner config.
    pub const fn config(&self) -> &CommissionerConfig {
        &self.config
    }

    /// Returns a reference to the connected UDP socket.
    pub const fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Petitions to become the active commissioner.
    pub async fn petition(&mut self) -> Result<PetitionResponse> {
        self.ensure_can_petition()?;
        self.state = CommissionerState::Petitioning;
        let (message_id, token) = self.next_request_identity();
        let request = meshcop::petition_request(message_id, token, &self.config.commissioner_id)?;
        let response = match self
            .execute_meshcop(CommissionerOperation::Petition, request)
            .await
        {
            Ok(response) => response,
            Err(err) => {
                self.state = CommissionerState::Connected;
                return Err(err);
            }
        };
        let petition = match meshcop::parse_petition_response(&response) {
            Ok(petition) => petition,
            Err(err) => {
                self.state = CommissionerState::Connected;
                return Err(err);
            }
        };
        match petition.state {
            MeshcopState::Accept => {
                let Some(session_id) = petition.session_id else {
                    self.state = CommissionerState::Connected;
                    return Err(Error::InvalidState(
                        "petition accepted without a session ID",
                    ));
                };
                self.session_id = Some(session_id);
                self.state = CommissionerState::Active;
                Ok(PetitionResponse {
                    session_id,
                    existing_commissioner_id: petition.existing_commissioner_id,
                })
            }
            MeshcopState::Pending => {
                self.state = CommissionerState::Connected;
                Err(Error::InvalidState("petition response is pending"))
            }
            MeshcopState::Reject => {
                self.state = CommissionerState::Connected;
                Err(Error::PetitionRejected {
                    existing_commissioner_id: petition.existing_commissioner_id,
                })
            }
        }
    }

    /// Sends a commissioner keepalive and returns the border agent status.
    pub async fn keep_alive(&mut self) -> Result<ResultCode> {
        let session_id = self.session_id_required()?;
        let (message_id, token) = self.next_request_identity();
        let request = meshcop::keep_alive_request(message_id, token, session_id, true)?;
        let response = self
            .execute_meshcop(CommissionerOperation::KeepAlive, request)
            .await?;
        let state = meshcop::parse_state_response(&response, true)?.ok_or(Error::InvalidState(
            "keepalive response did not include state",
        ))?;
        let result = result_code_from_meshcop_state(state);
        self.queue_event(CommissionerEvent::KeepAliveResponse(result));
        if state == MeshcopState::Reject {
            self.state = CommissionerState::Connected;
            self.session_id = None;
        }
        Ok(result)
    }

    /// Resigns from the active commissioner role.
    pub async fn resign(&mut self) -> Result<()> {
        let session_id = self.session_id_required()?;
        let (message_id, token) = self.next_request_identity();
        let request = meshcop::keep_alive_request(message_id, token, session_id, false)?;
        let response = self
            .execute_meshcop(CommissionerOperation::KeepAlive, request)
            .await?;
        if meshcop::parse_state_response(&response, true)? == Some(MeshcopState::Pending) {
            return Err(Error::InvalidState("resign response is pending"));
        }
        self.disconnect();
        Ok(())
    }

    /// Requests a CCM commissioner token.
    pub async fn request_token(&mut self, _registrar: SocketAddr) -> Result<Vec<u8>> {
        Err(Error::Unsupported("CCM token request is deferred"))
    }

    /// Sets a CCM commissioner token.
    pub fn set_token(&mut self, _signed_token: &[u8]) -> Result<()> {
        Err(Error::Unsupported("CCM token support is deferred"))
    }

    /// Receives the next commissioner event.
    ///
    /// If a DTLS session is established, this also reads protected application
    /// data from the border agent and routes unsolicited MeshCoP notifications
    /// into the event queue.
    pub async fn next_event(&mut self) -> Result<Option<CommissionerEvent>> {
        if let Some(event) = self.try_recv_queued_event() {
            return Ok(Some(event));
        }
        if self.dtls_session.is_none() {
            return Err(Error::InvalidState("DTLS session is not established"));
        }

        loop {
            let response_wire = self.recv_application_data().await?;
            let message = meshcop::CoapMessage::decode(&response_wire)?;
            self.handle_incoming(None, &message).await?;
            if let Some(event) = self.try_recv_queued_event() {
                return Ok(Some(event));
            }
        }
    }

    /// Disconnects the local handle.
    pub fn disconnect(&mut self) {
        self.state = CommissionerState::Disabled;
        self.session_id = None;
        self.dtls_session = None;
        self.mesh_local_prefix = None;
        self.joiner_sessions.clear();
    }

    fn next_request_identity(&mut self) -> (u16, [u8; 2]) {
        self.next_message_id = self.next_message_id.wrapping_add(1);
        (self.next_message_id, self.next_message_id.to_be_bytes())
    }

    fn session_id_required(&self) -> Result<u16> {
        self.session_id
            .ok_or(Error::InvalidState("commissioner session is not active"))
    }

    fn ensure_can_petition(&self) -> Result<()> {
        match self.state {
            CommissionerState::Connected => Ok(()),
            CommissionerState::Disabled => Err(Error::InvalidState("commissioner is disconnected")),
            CommissionerState::Petitioning => {
                Err(Error::InvalidState("petition is already active"))
            }
            CommissionerState::Active => Err(Error::InvalidState("commissioner is already active")),
        }
    }

    fn try_recv_queued_event(&mut self) -> Option<CommissionerEvent> {
        self.events.pop_front()
    }

    fn queue_event(&mut self, event: CommissionerEvent) {
        self.events.push_back(event);
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Commissioner {
    /// Test support: connects a [`Commissioner`] to the deterministic
    /// scripted MeshCoP transport instead of a real DTLS session, so tests
    /// can drive the public API without a network. Unstable test scaffolding
    /// for this workspace's suites; not a supported public API.
    pub async fn connect_scripted(
        config: CommissionerConfig,
        border_agent: SocketAddr,
        scripted_transport: ScriptedMeshcopTransport,
        initial_events: impl IntoIterator<Item = CommissionerEvent>,
    ) -> Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let mut events = VecDeque::new();
        for event in initial_events {
            events.push_back(event);
        }
        Ok(Self {
            config,
            border_agent,
            socket,
            state: CommissionerState::Connected,
            session_id: None,
            dtls_session: None,
            scripted_transport: Some(scripted_transport),
            next_message_id: 0,
            events,
            mesh_local_prefix: None,
            joiner_handler: None,
            joiner_sessions: HashMap::new(),
        })
    }

    /// Test support: returns the scripted MeshCoP transport when this
    /// `Commissioner` was created with [`Commissioner::connect_scripted`], for
    /// inspecting observed requests and sent messages. Unstable test
    /// scaffolding for this workspace's suites; not a supported public API.
    pub fn scripted_transport(&self) -> Option<&ScriptedMeshcopTransport> {
        self.scripted_transport.as_ref()
    }

    /// Test support: overrides the cached mesh-local prefix used for
    /// ALOC/RLOC routing, bypassing the dataset fetch that would otherwise
    /// populate it. Unstable test scaffolding for this workspace's suites;
    /// not a supported public API.
    pub fn set_cached_mesh_local_prefix(&mut self, prefix: Option<[u8; 8]>) {
        self.mesh_local_prefix = prefix;
    }

    /// Test support: returns the currently cached mesh-local prefix. Unstable
    /// test scaffolding for this workspace's suites; not a supported public
    /// API.
    pub fn cached_mesh_local_prefix(&self) -> Option<[u8; 8]> {
        self.mesh_local_prefix
    }
}

/// Computes a Thread anycast locator address from a mesh-local prefix.
fn aloc_address(mesh_local_prefix: [u8; 8], aloc16: u16) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    octets[..8].copy_from_slice(&mesh_local_prefix);
    octets[8..14].copy_from_slice(&[0x00, 0x00, 0x00, 0xff, 0xfe, 0x00]);
    octets[14..].copy_from_slice(&aloc16.to_be_bytes());
    Ipv6Addr::from(octets)
}

/// Validates that every listed TLV is present in `dataset`.
fn require_dataset_tlvs(dataset: &crate::dataset::Dataset, required: &[(u8, &str)]) -> Result<()> {
    for (ty, name) in required {
        if dataset.raw(*ty).is_none() {
            return Err(Error::Dataset(format!("{name} TLV is mandatory")));
        }
    }
    Ok(())
}

/// Returns `dataset` without the protocol-managed commissioner TLVs.
fn strip_managed_commissioner_tlvs(dataset: &crate::dataset::Dataset) -> crate::dataset::Dataset {
    let mut out = dataset.clone();
    out.remove_all(meshcop::TLV_COMMISSIONER_SESSION_ID);
    out.remove_all(meshcop::TLV_BORDER_AGENT_LOCATOR);
    out
}

/// Treats an `Accept`/absent State TLV as success and a `Pending`/`Reject`
/// State TLV as an error.
fn check_state_response(response: &meshcop::CoapMessage, state_mandatory: bool) -> Result<()> {
    let state = meshcop::parse_state_response(response, state_mandatory)?;
    match state {
        None | Some(MeshcopState::Accept) => Ok(()),
        Some(MeshcopState::Pending) => Err(Error::InvalidState("MeshCoP response is pending")),
        Some(MeshcopState::Reject) => Err(Error::InvalidState("MeshCoP request was rejected")),
    }
}

/// Prints a non-secret protocol trace line when `MESH50_TRACE` is set.
fn commissioner_trace(args: core::fmt::Arguments<'_>) {
    const TRACE_ENV: &str = "MESH50_TRACE";

    if std::env::var_os(TRACE_ENV).is_some() {
        eprintln!("[meshcop] {args}");
    }
}

/// Timeout applied to each DTLS receive and to an overall MeshCoP response wait.
const MESHCOP_TIMEOUT: Duration = Duration::from_secs(5);
/// Absolute DTLS handshake budget.
///
/// This leaves five seconds for the petition response after a replacement
/// commissioner refreshes a session using the minimum 30-second keep-alive
/// interval.
const DTLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

fn result_code_from_meshcop_state(state: MeshcopState) -> ResultCode {
    match state {
        MeshcopState::Accept => ResultCode::Accept,
        MeshcopState::Pending => ResultCode::Pending,
        MeshcopState::Reject => ResultCode::Reject,
    }
}
