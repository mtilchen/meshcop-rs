//! Async commissioner client.
//!
//! [`Commissioner`] is a cheap, cloneable handle to a session run by a
//! background driver task ([`driver`]). The driver owns the DTLS session,
//! matches responses to requests, retransmits, sends keep-alives, handles
//! relayed joiners, and publishes events. The handle's operations are grouped
//! into sibling modules that each `impl Commissioner`: [`datasets`]
//! (operational and commissioner dataset get/set), [`commands`]
//! (announce/scan/PAN-ID and the managed-device commands), [`diagnostics`]
//! (network-diagnostic queries), [`relay`] (joiner relay payloads), and
//! [`requests`] (request submission and mesh-local routing). This module holds
//! the handle, the session lifecycle, and the small shared helpers.

use std::{
    net::{Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use tokio::sync::{broadcast, mpsc, oneshot, watch};

use crate::{
    Result,
    error::Error,
    meshcop::{self, MeshcopState},
};

#[cfg(any(test, feature = "test-support"))]
use super::harness::ScriptedMeshcopTransport;
use super::{
    config::{CommissionerConfig, MIN_KEEPALIVE_INTERVAL},
    events::Events,
    joiner::JoinerHandler,
    types::{CommissionerEvent, PetitionResponse, ResultCode, SessionStatus},
};

mod commands;
mod datasets;
mod diagnostics;
mod driver;
mod relay;
mod requests;

use driver::{Command, Driver, Link};

/// Handle to a commissioner session with a Thread border agent.
///
/// A background task, started by [`Commissioner::connect`] or
/// [`Commissioner::connect_only`], runs the session: it sends keep-alives,
/// matches responses to requests, retransmits lost messages, commissions
/// relayed joiners, and publishes [`CommissionerEvent`]s. Handles are cheap to
/// clone, and every clone drives the same session, so independent tasks can
/// issue requests concurrently. The task needs a Tokio runtime; any flavor,
/// including `LocalRuntime`, works.
///
/// The session ends when [`Commissioner::resign`] is called, when the session
/// is lost, or when every handle has been dropped. In the last case the task
/// resigns on a best-effort basis, but a runtime that is shutting down cancels
/// it first, so call [`Commissioner::resign`] before a program exits.
#[derive(Debug, Clone)]
pub struct Commissioner {
    commands: mpsc::UnboundedSender<Command>,
    status: watch::Receiver<SessionStatus>,
    shared: Arc<Shared>,
}

/// State shared between the handles and the driver task.
#[derive(Debug)]
struct Shared {
    config: CommissionerConfig,
    border_agent: SocketAddr,
    mesh_local_prefix: Mutex<Option<[u8; 8]>>,
    /// Never read; kept so new subscribers can be created from any handle
    /// without keeping the event channel open after the driver stops.
    event_template: broadcast::Receiver<CommissionerEvent>,
    #[cfg(any(test, feature = "test-support"))]
    scripted_transport: Option<ScriptedMeshcopTransport>,
}

impl Shared {
    fn mesh_local_prefix(&self) -> MutexGuard<'_, Option<[u8; 8]>> {
        self.mesh_local_prefix
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

impl Commissioner {
    /// Connects to a border agent and petitions to become the active
    /// commissioner.
    ///
    /// Returns the handle and the first event subscription. Connection and
    /// petition failures, including [`Error::PetitionRejected`], are returned
    /// here, and no session is left running.
    pub async fn connect(
        config: CommissionerConfig,
        border_agent: SocketAddr,
    ) -> Result<(Self, Events)> {
        let (commissioner, events) = Self::connect_only(config, border_agent).await?;
        commissioner.petition().await?;
        Ok((commissioner, events))
    }

    /// Opens the DTLS session with a border agent without petitioning.
    ///
    /// A connect-only session can read datasets, and can be upgraded later
    /// with [`Commissioner::petition`]. Operations that need an active
    /// commissioner, such as network diagnostics, return
    /// [`Error::InvalidState`] until a petition is accepted. Border agents close
    /// an unpetitioned session after a short lifetime (about 50 seconds has
    /// been observed); the session then reports [`SessionStatus::Idle`] and
    /// opens a new DTLS session when a request needs one.
    pub async fn connect_only(
        config: CommissionerConfig,
        border_agent: SocketAddr,
    ) -> Result<(Self, Events)> {
        config.validate()?;
        if config.enable_ccm {
            return Err(Error::Unsupported("CCM is reserved but deferred"));
        }
        let link = Link::connect(border_agent, &config.pskc).await?;
        Ok(Self::spawn(
            config,
            border_agent,
            link,
            Vec::new(),
            #[cfg(any(test, feature = "test-support"))]
            None,
        ))
    }

    fn spawn(
        config: CommissionerConfig,
        border_agent: SocketAddr,
        link: Link,
        initial_events: Vec<CommissionerEvent>,
        #[cfg(any(test, feature = "test-support"))] scripted_transport: Option<
            ScriptedMeshcopTransport,
        >,
    ) -> (Self, Events) {
        let (event_sender, event_template) = broadcast::channel(config.event_capacity);
        let events = Events::new(event_template.resubscribe());
        let (status_sender, status) = watch::channel(SessionStatus::Connected);
        let (commands, command_receiver) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            config,
            border_agent,
            mesh_local_prefix: Mutex::new(None),
            event_template,
            #[cfg(any(test, feature = "test-support"))]
            scripted_transport,
        });
        for event in initial_events {
            // A send fails only without subscribers, and `events` is one.
            let _ = event_sender.send(event);
        }
        let driver = Driver::new(
            link,
            Arc::clone(&shared),
            command_receiver,
            event_sender,
            status_sender,
        );
        tokio::spawn(driver.run());
        (
            Self {
                commands,
                status,
                shared,
            },
            events,
        )
    }

    /// Returns a new subscription to this session's events.
    ///
    /// It receives events published after this call.
    pub fn subscribe(&self) -> Events {
        Events::new(self.shared.event_template.resubscribe())
    }

    /// Returns where the session stands.
    pub fn status(&self) -> SessionStatus {
        self.status.borrow().clone()
    }

    /// Returns the active commissioner session ID, when the session is
    /// active.
    pub fn session_id(&self) -> Option<u16> {
        self.status.borrow().session_id()
    }

    /// Returns the configured border-agent address.
    pub fn border_agent(&self) -> SocketAddr {
        self.shared.border_agent
    }

    /// Returns the commissioner config.
    pub fn config(&self) -> &CommissionerConfig {
        &self.shared.config
    }

    /// Installs the handler that provides joiner PSKds and finalization
    /// decisions, enabling joiner commissioning sessions.
    ///
    /// Without a handler, relayed joiner traffic surfaces as raw
    /// [`CommissionerEvent::JoinerMessage`] events. The handler runs on the
    /// session's task, so it must not block: while it runs, no keep-alive or
    /// other exchange makes progress.
    pub fn set_joiner_handler(&self, handler: impl JoinerHandler + 'static) -> Result<()> {
        self.send_command(Command::SetJoinerHandler(Some(Box::new(handler))))
    }

    /// Removes the joiner handler and drops in-progress joiner sessions.
    pub fn clear_joiner_handler(&self) -> Result<()> {
        self.send_command(Command::SetJoinerHandler(None))
    }

    /// Petitions to become the active commissioner.
    ///
    /// With [`super::KeepAlive::Automatic`], keep-alives start once the
    /// petition is accepted.
    pub async fn petition(&self) -> Result<PetitionResponse> {
        self.call(|reply| Command::Petition { reply }).await?
    }

    /// Sends a commissioner keep-alive and returns the border agent status.
    ///
    /// Any answer other than Accept, or a failed exchange, ends the session.
    /// With [`super::KeepAlive::Automatic`] this is never required, but it may
    /// be called; the next automatic keep-alive is rescheduled from it.
    pub async fn keep_alive(&self) -> Result<ResultCode> {
        self.call(|reply| Command::KeepAlive { reply }).await?
    }

    /// Ends the session, resigning the commissioner role first if the
    /// petition was accepted.
    ///
    /// The session ends even if the border agent does not confirm the
    /// resignation; the error then reports that it was not confirmed.
    pub async fn resign(&self) -> Result<()> {
        self.call(|reply| Command::Resign { reply }).await?
    }

    /// Requests a CCM commissioner token.
    pub async fn request_token(&self, _registrar: SocketAddr) -> Result<Vec<u8>> {
        Err(Error::Unsupported("CCM token request is deferred"))
    }

    /// Sets a CCM commissioner token.
    pub fn set_token(&self, _signed_token: &[u8]) -> Result<()> {
        Err(Error::Unsupported("CCM token support is deferred"))
    }

    fn send_command(&self, command: Command) -> Result<()> {
        self.commands
            .send(command)
            .map_err(|_| Error::SessionClosed)
    }

    /// Sends a command carrying a reply channel and waits for the reply.
    async fn call<T>(&self, command: impl FnOnce(oneshot::Sender<T>) -> Command) -> Result<T> {
        let (reply, response) = oneshot::channel();
        self.send_command(command(reply))?;
        response.await.map_err(|_| Error::SessionClosed)
    }

    fn session_id_required(&self) -> Result<u16> {
        self.session_id()
            .ok_or(Error::InvalidState("commissioner session is not active"))
    }
}

#[cfg(any(test, feature = "test-support"))]
impl Commissioner {
    /// Test support: starts a session over the deterministic scripted MeshCoP
    /// transport instead of a real DTLS session, so tests can drive the public
    /// API without a network. `initial_events` are published before any
    /// scripted traffic. Unstable test scaffolding for this workspace's suites;
    /// not a supported public API.
    pub async fn connect_scripted(
        config: CommissionerConfig,
        border_agent: SocketAddr,
        scripted_transport: ScriptedMeshcopTransport,
        initial_events: impl IntoIterator<Item = CommissionerEvent>,
    ) -> Result<(Self, Events)> {
        config.validate()?;
        Ok(Self::spawn(
            config,
            border_agent,
            Link::Scripted {
                transport: scripted_transport.clone(),
                open: true,
            },
            initial_events.into_iter().collect(),
            Some(scripted_transport),
        ))
    }

    /// Test support: returns the scripted MeshCoP transport when this session
    /// was created with [`Commissioner::connect_scripted`], for inspecting
    /// observed requests and sent messages. Unstable test scaffolding for this
    /// workspace's suites; not a supported public API.
    pub fn scripted_transport(&self) -> Option<&ScriptedMeshcopTransport> {
        self.shared.scripted_transport.as_ref()
    }

    /// Test support: overrides the cached mesh-local prefix used for
    /// ALOC/RLOC routing, bypassing the dataset fetch that would otherwise
    /// populate it. Unstable test scaffolding for this workspace's suites;
    /// not a supported public API.
    pub fn set_cached_mesh_local_prefix(&self, prefix: Option<[u8; 8]>) {
        *self.shared.mesh_local_prefix() = prefix;
    }

    /// Test support: returns the currently cached mesh-local prefix. Unstable
    /// test scaffolding for this workspace's suites; not a supported public
    /// API.
    pub fn cached_mesh_local_prefix(&self) -> Option<[u8; 8]> {
        *self.shared.mesh_local_prefix()
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

/// Rejects CoAP client-error (4.xx) and server-error (5.xx) responses so a
/// peer's failure surfaces as an error instead of being decoded as an empty
/// payload. Any 2.xx success response passes through to the tolerant
/// per-operation decoders.
fn require_success_response(response: meshcop::CoapMessage) -> Result<meshcop::CoapMessage> {
    let class = response.code.0 >> 5;
    if class == 4 || class == 5 {
        commissioner_trace(format_args!(
            "MeshCoP exchange returned CoAP error code 0x{:02x}",
            response.code.0
        ));
        return Err(Error::InvalidState(
            "MeshCoP exchange returned a CoAP error response",
        ));
    }
    Ok(response)
}

/// Prints a non-secret protocol trace line when `MESHCOP_TRACE` is set.
fn commissioner_trace(args: core::fmt::Arguments<'_>) {
    const TRACE_ENV: &str = "MESHCOP_TRACE";

    if std::env::var_os(TRACE_ENV).is_some() {
        eprintln!("[meshcop] {args}");
    }
}

/// Absolute budget for one CoAP request/response exchange, including its
/// retransmissions.
const COAP_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(12);
/// Slack kept between one CoAP exchange and the end of the minimum keep-alive
/// interval when budgeting a handshake.
const SESSION_REPLACEMENT_MARGIN: Duration = Duration::from_secs(3);
/// Absolute DTLS handshake budget.
///
/// A handshake followed by a petition exchange must fit inside the minimum
/// keep-alive interval, so the handshake receives what that interval leaves
/// after one CoAP exchange and a margin.
const DTLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(
    MIN_KEEPALIVE_INTERVAL.as_secs()
        - COAP_EXCHANGE_TIMEOUT.as_secs()
        - SESSION_REPLACEMENT_MARGIN.as_secs(),
);

fn result_code_from_meshcop_state(state: MeshcopState) -> ResultCode {
    match state {
        MeshcopState::Accept => ResultCode::Accept,
        MeshcopState::Pending => ResultCode::Pending,
        MeshcopState::Reject => ResultCode::Reject,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_and_petition_fit_the_minimum_keepalive_interval() {
        assert!(
            DTLS_HANDSHAKE_TIMEOUT + COAP_EXCHANGE_TIMEOUT + SESSION_REPLACEMENT_MARGIN
                <= MIN_KEEPALIVE_INTERVAL
        );
    }
}
