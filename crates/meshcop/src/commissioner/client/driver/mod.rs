//! The session driver: the background task behind every
//! [`super::Commissioner`] handle.
//!
//! One task owns the connection to the border agent and runs a loop over
//! handle commands, received datagrams, and timers (retransmissions, exchange
//! deadlines, and keep-alives). [`exchange`] tracks outstanding requests,
//! [`incoming`] routes what arrives, [`relay`] drives joiner sessions, and
//! [`link`] is the DTLS session (or the scripted transport in tests).

use std::collections::HashMap;
use std::sync::Arc;

use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio::time::Instant;

use crate::{
    Result,
    error::Error,
    meshcop::{self, CoapMessage, CommissionerOperation, MeshcopState},
};

use super::super::config::KeepAlive;
use super::super::joiner::{JoinerHandler, JoinerSession};
use super::super::types::{
    CloseReason, CommissionerEvent, Destination, PetitionResponse, ResultCode, SessionStatus,
};
use super::{Shared, commissioner_trace, require_success_response, result_code_from_meshcop_state};

mod exchange;
mod incoming;
mod link;
mod relay;

pub(super) use exchange::Outbound;
use exchange::{Completion, Exchanges, is_transport_error};
pub(super) use link::Link;

/// A request from a handle to the driver.
pub(super) enum Command {
    Exchange {
        /// Identifies the request to [`Command::Withdraw`].
        id: u64,
        request: Outbound,
        reply: oneshot::Sender<Result<Option<CoapMessage>>>,
    },
    /// The caller of the identified request stopped waiting for it.
    Withdraw(u64),
    Petition {
        reply: oneshot::Sender<Result<PetitionResponse>>,
    },
    KeepAlive {
        reply: oneshot::Sender<Result<ResultCode>>,
    },
    Resign {
        reply: oneshot::Sender<Result<()>>,
    },
    SetJoinerHandler(Option<Box<dyn JoinerHandler>>),
}

/// What woke the driver loop.
enum Wake {
    Command(Option<Command>),
    Received(Result<Vec<u8>>),
    Timer,
}

pub(super) struct Driver {
    link: Link,
    shared: Arc<Shared>,
    commands: mpsc::UnboundedReceiver<Command>,
    events: broadcast::Sender<CommissionerEvent>,
    status: watch::Sender<SessionStatus>,
    next_message_id: u16,
    exchanges: Exchanges,
    keep_alive_at: Option<Instant>,
    joiner_handler: Option<Box<dyn JoinerHandler>>,
    joiner_sessions: HashMap<[u8; 8], JoinerSession>,
    /// Every handle has been dropped; the driver is resigning.
    handles_dropped: bool,
}

impl Driver {
    pub(super) fn new(
        link: Link,
        shared: Arc<Shared>,
        commands: mpsc::UnboundedReceiver<Command>,
        events: broadcast::Sender<CommissionerEvent>,
        status: watch::Sender<SessionStatus>,
    ) -> Self {
        Self {
            link,
            shared,
            commands,
            events,
            status,
            next_message_id: 0,
            exchanges: Exchanges::default(),
            keep_alive_at: None,
            joiner_handler: None,
            joiner_sessions: HashMap::new(),
            handles_dropped: false,
        }
    }

    /// Runs the session until it ends.
    pub(super) async fn run(mut self) {
        while !self.is_closed() {
            // Yield once the task's cooperative budget is spent, so a steady
            // stream of ready work cannot starve other tasks on the runtime.
            tokio::task::coop::consume_budget().await;
            let wake = self.next_wake().await;
            match wake {
                Wake::Command(Some(command)) => self.handle_command(command).await,
                Wake::Command(None) => self.handles_dropped().await,
                Wake::Received(Ok(plaintext)) => self.handle_datagram(&plaintext).await,
                Wake::Received(Err(err)) => self.receive_failed(err).await,
                Wake::Timer => self.run_timers().await,
            }
        }
    }

    /// Waits for the next thing to do. Due timers come first, so a deadline
    /// is enforced before a late response is read, and handle commands come
    /// last, so no volume of them can hold up keep-alives or responses.
    async fn next_wake(&mut self) -> Wake {
        let deadline = self.next_deadline();
        let accepting_commands = !self.handles_dropped;
        tokio::select! {
            biased;
            () = sleep_until(deadline) => Wake::Timer,
            received = self.link.recv() => Wake::Received(received),
            command = self.commands.recv(), if accepting_commands => Wake::Command(command),
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        [self.exchanges.next_deadline(), self.keep_alive_at]
            .into_iter()
            .flatten()
            .min()
    }

    fn is_closed(&self) -> bool {
        matches!(*self.status.borrow(), SessionStatus::Closed { .. })
    }

    fn session_id(&self) -> Option<u16> {
        self.status.borrow().session_id()
    }

    fn set_status(&self, status: SessionStatus) {
        commissioner_trace(format_args!("session status {status:?}"));
        self.status.send_replace(status);
    }

    /// Publishes an event to every subscriber. Having none is not an error.
    fn publish(&self, event: CommissionerEvent) {
        let _ = self.events.send(event);
    }

    async fn handle_command(&mut self, command: Command) {
        match command {
            Command::Exchange { id, request, reply } => {
                if self.exchanges.resigning() {
                    let _ = reply.send(Err(Error::InvalidState(RESIGNING)));
                    return;
                }
                if let Err(err) = self.ensure_open().await {
                    let _ = reply.send(Err(err));
                    return;
                }
                self.submit(request, Completion::Caller { id, reply }).await;
            }
            Command::Withdraw(id) => self.withdraw(id).await,
            Command::Petition { reply } => self.petition(reply).await,
            Command::KeepAlive { reply } => {
                let refusal = if self.session_id().is_none() {
                    Some("commissioner session is not active")
                } else if self.exchanges.resigning() {
                    Some(RESIGNING)
                } else if self.exchanges.keep_alive_outstanding() {
                    Some("a keep-alive is already outstanding")
                } else {
                    None
                };
                if let Some(refusal) = refusal {
                    let _ = reply.send(Err(Error::InvalidState(refusal)));
                    return;
                }
                self.send_keep_alive(Completion::KeepAlive(Some(reply)))
                    .await;
            }
            Command::Resign { reply } => {
                if self.exchanges.resigning() {
                    let _ = reply.send(Err(Error::InvalidState(RESIGNING)));
                    return;
                }
                self.resign(Some(reply)).await;
            }
            Command::SetJoinerHandler(handler) => {
                if handler.is_none() {
                    self.joiner_sessions.clear();
                }
                self.joiner_handler = handler;
            }
        }
    }

    /// Reopens a connect-only session that the border agent closed.
    async fn ensure_open(&mut self) -> Result<()> {
        if self.link.is_open() {
            return Ok(());
        }
        self.link.reopen().await?;
        self.set_status(SessionStatus::Connected);
        Ok(())
    }

    async fn petition(&mut self, reply: oneshot::Sender<Result<PetitionResponse>>) {
        let refusal = match *self.status.borrow() {
            SessionStatus::Connected | SessionStatus::Idle => None,
            SessionStatus::Petitioning => Some("petition is already active"),
            SessionStatus::Active { .. } => Some("commissioner is already active"),
            SessionStatus::Closed { .. } => Some("commissioner is disconnected"),
        };
        if let Some(refusal) = refusal {
            let _ = reply.send(Err(Error::InvalidState(refusal)));
            return;
        }
        if let Err(err) = self.ensure_open().await {
            let _ = reply.send(Err(err));
            return;
        }
        let (message_id, token) = (0, Vec::new());
        let request =
            match meshcop::petition_request(message_id, token, &self.shared.config.commissioner_id)
            {
                Ok(request) => request,
                Err(err) => {
                    let _ = reply.send(Err(err));
                    return;
                }
            };
        self.set_status(SessionStatus::Petitioning);
        self.start(
            control_request(request, CommissionerOperation::Petition),
            Completion::Petition(reply),
        )
        .await;
    }

    async fn send_keep_alive(&mut self, completion: Completion) {
        let Some(session_id) = self.session_id() else {
            return self
                .complete(
                    completion,
                    Err(Error::InvalidState("commissioner session is not active")),
                )
                .await;
        };
        self.keep_alive_at = None;
        match meshcop::keep_alive_request(0, Vec::new(), session_id, true) {
            Ok(request) => {
                self.start(
                    control_request(request, CommissionerOperation::KeepAlive),
                    completion,
                )
                .await;
            }
            Err(err) => self.complete(completion, Err(err)).await,
        }
    }

    /// Resigns an active session, or closes an unpetitioned one at once.
    async fn resign(&mut self, reply: Option<oneshot::Sender<Result<()>>>) {
        let Some(session_id) = self.session_id() else {
            self.end_session(CloseReason::Resigned).await;
            if let Some(reply) = reply {
                let _ = reply.send(Ok(()));
            }
            return;
        };
        self.keep_alive_at = None;
        match meshcop::keep_alive_request(0, Vec::new(), session_id, false) {
            Ok(request) => {
                self.start(
                    control_request(request, CommissionerOperation::KeepAlive),
                    Completion::Resign(reply),
                )
                .await;
            }
            Err(err) => self.complete(Completion::Resign(reply), Err(err)).await,
        }
    }

    async fn handles_dropped(&mut self) {
        self.handles_dropped = true;
        if self.exchanges.resigning() {
            return;
        }
        commissioner_trace(format_args!("every handle was dropped; resigning"));
        self.resign(None).await;
    }

    async fn handle_datagram(&mut self, plaintext: &[u8]) {
        let message = match CoapMessage::decode(plaintext) {
            Ok(message) => message,
            Err(err) => {
                commissioner_trace(format_args!("drop undecodable datagram: {err}"));
                return;
            }
        };
        commissioner_trace(format_args!(
            "recv mid={} type={:?} code=0x{:02x} token={}",
            message.message_id,
            message.ty,
            message.code.0,
            hex::encode(&message.token)
        ));
        if let Err(err) = self.route_incoming(message).await {
            if is_transport_error(&err) {
                self.transport_failed(err.to_string()).await;
            } else {
                commissioner_trace(format_args!("drop message that failed to route: {err}"));
            }
        }
    }

    async fn receive_failed(&mut self, err: Error) {
        let peer_closed = matches!(err, Error::Dtls(meshcop_dtls::Error::PeerClosed));
        if peer_closed && self.session_id().is_none() && !self.handles_dropped {
            // Border agents close unpetitioned sessions after a short lifetime.
            // A connect-only session reopens when a request needs it.
            commissioner_trace(format_args!("border agent closed the unpetitioned session"));
            self.link.close();
            self.fail_all(|| Error::SessionLost(CloseReason::PeerClosed))
                .await;
            self.set_status(SessionStatus::Idle);
            return;
        }
        if peer_closed {
            return self.end_session(CloseReason::PeerClosed).await;
        }
        self.transport_failed(err.to_string()).await;
    }

    async fn run_timers(&mut self) {
        self.run_exchange_timers().await;
        if self.is_closed() {
            return;
        }
        let keep_alive_due = self
            .keep_alive_at
            .is_some_and(|keep_alive_at| keep_alive_at <= Instant::now());
        // The timer is cleared while a keep-alive is outstanding, so a due
        // timer never duplicates one.
        if keep_alive_due {
            self.send_keep_alive(Completion::KeepAlive(None)).await;
        }
    }

    /// Delivers an exchange outcome to whoever is waiting for it, applying
    /// session-control outcomes to the session first.
    async fn complete(&mut self, completion: Completion, outcome: Result<Option<CoapMessage>>) {
        match completion {
            Completion::Caller { reply, .. } => {
                let _ = reply.send(outcome);
                self.send_queued().await;
            }
            Completion::Petition(reply) => {
                let result = self.petition_outcome(outcome);
                let _ = reply.send(result);
            }
            Completion::KeepAlive(reply) => self.keep_alive_outcome(outcome, reply).await,
            Completion::Resign(reply) => {
                let result = response_required(outcome).and_then(|response| {
                    match meshcop::parse_state_response(&response, true)? {
                        Some(MeshcopState::Pending) => {
                            Err(Error::InvalidState("resign response is pending"))
                        }
                        _ => Ok(()),
                    }
                });
                self.end_session(CloseReason::Resigned).await;
                if let Some(reply) = reply {
                    let _ = reply.send(result);
                }
            }
        }
    }

    fn petition_outcome(
        &mut self,
        outcome: Result<Option<CoapMessage>>,
    ) -> Result<PetitionResponse> {
        let result = response_required(outcome).and_then(|response| {
            let petition = meshcop::parse_petition_response(&response)?;
            match petition.state {
                MeshcopState::Accept => {
                    let session_id = petition.session_id.ok_or(Error::InvalidState(
                        "petition accepted without a session ID",
                    ))?;
                    Ok(PetitionResponse {
                        session_id,
                        existing_commissioner_id: petition.existing_commissioner_id,
                    })
                }
                MeshcopState::Pending => Err(Error::InvalidState("petition response is pending")),
                MeshcopState::Reject => Err(Error::PetitionRejected {
                    existing_commissioner_id: petition.existing_commissioner_id,
                }),
            }
        });
        if self.is_closed() {
            return result;
        }
        match &result {
            Ok(petition) => {
                self.set_status(SessionStatus::Active {
                    session_id: petition.session_id,
                });
                self.schedule_keep_alive();
            }
            Err(_) => self.set_status(SessionStatus::Connected),
        }
        result
    }

    async fn keep_alive_outcome(
        &mut self,
        outcome: Result<Option<CoapMessage>>,
        reply: Option<oneshot::Sender<Result<ResultCode>>>,
    ) {
        let result = response_required(outcome).and_then(|response| {
            meshcop::parse_state_response(&response, true)?
                .map(result_code_from_meshcop_state)
                .ok_or(Error::InvalidState(
                    "keepalive response did not include state",
                ))
        });
        let end = match &result {
            Ok(code) => {
                self.publish(CommissionerEvent::KeepAliveResponse(*code));
                match code {
                    ResultCode::Accept => None,
                    ResultCode::Reject => Some(CloseReason::KeepAliveRejected),
                    ResultCode::Pending => Some(CloseReason::KeepAlivePending),
                }
            }
            Err(err) => Some(CloseReason::KeepAliveFailed {
                error: err.to_string(),
            }),
        };
        if let Some(reply) = reply {
            let _ = reply.send(result);
        }
        match end {
            None => self.schedule_keep_alive(),
            Some(reason) => self.end_session(reason).await,
        }
    }

    fn schedule_keep_alive(&mut self) {
        if self.shared.config.keep_alive == KeepAlive::Automatic && self.session_id().is_some() {
            self.keep_alive_at = Some(Instant::now() + self.shared.config.keepalive_interval);
        }
    }

    async fn transport_failed(&mut self, error: String) {
        self.end_session(CloseReason::TransportFailed { error })
            .await;
    }

    /// Ends the session: fails every outstanding request, publishes the loss
    /// unless the application ended the session, and closes the link.
    async fn end_session(&mut self, reason: CloseReason) {
        if self.is_closed() {
            return;
        }
        commissioner_trace(format_args!("session ended: {reason}"));
        self.set_status(SessionStatus::Closed {
            reason: reason.clone(),
        });
        self.keep_alive_at = None;
        self.joiner_sessions.clear();
        self.link.close();
        let lost = reason != CloseReason::Resigned;
        self.fail_all(|| {
            if lost {
                Error::SessionLost(reason.clone())
            } else {
                Error::SessionClosed
            }
        })
        .await;
        if lost {
            self.publish(CommissionerEvent::SessionLost { reason });
        }
    }

    /// Fails every in-flight and queued exchange with `error()`.
    async fn fail_all(&mut self, error: impl Fn() -> Error) {
        for completion in self.exchanges.drain() {
            // Boxed: completing a session-control exchange can itself end the
            // session and fail exchanges.
            Box::pin(self.complete(completion, Err(error()))).await;
        }
    }
}

/// Why new work is refused once the session has started resigning.
const RESIGNING: &str = "commissioner is resigning";

/// Wraps a session-control request for the driver's own exchange.
fn control_request(message: CoapMessage, operation: CommissionerOperation) -> Outbound {
    Outbound {
        message,
        destination: Destination::BorderAgent,
        expect_response: true,
        label: operation.label(),
    }
}

/// Returns the successful response of a session-control exchange.
fn response_required(outcome: Result<Option<CoapMessage>>) -> Result<CoapMessage> {
    outcome?
        .ok_or(Error::InvalidState("MeshCoP exchange produced no response"))
        .and_then(require_success_response)
}

/// Sleeps until `deadline`, or forever without one.
async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => core::future::pending().await,
    }
}
