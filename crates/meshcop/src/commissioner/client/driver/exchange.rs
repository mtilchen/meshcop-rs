//! Outstanding CoAP exchanges: identity assignment, RFC 7252 retransmission,
//! the in-flight limit, and exchange deadlines.

use std::collections::VecDeque;
use std::time::Duration;

use rand_core::RngCore;
use tokio::sync::oneshot;
use tokio::time::Instant;

use crate::{
    Result,
    error::Error,
    meshcop::{self, CoapMessage},
};

use super::super::super::types::{Destination, PetitionResponse, ResultCode};
use super::super::{COAP_EXCHANGE_TIMEOUT, commissioner_trace};
use super::Driver;

const COAP_ACK_TIMEOUT: Duration = Duration::from_secs(2);
const COAP_ACK_RANDOM_WINDOW_MILLIS: u64 = 1_000;
// Two retries always fit the 12-second MeshCoP operation deadline with the
// RFC 7252 randomized 2-3 second initial timeout and its doubled successor.
const COAP_MAX_RETRANSMIT: u8 = 2;
/// Application exchanges outstanding with the border agent at once, following
/// the RFC 7252 §4.7 NSTART default. Session-control exchanges (petition,
/// keep-alive, resign) are not counted, so a slow request never delays a
/// keep-alive.
const MAX_APPLICATION_IN_FLIGHT: usize = 1;
/// Length of the random token that correlates a response with its request.
const TOKEN_LENGTH: usize = 4;

/// A Reset answering the outstanding request ends the exchange at once
/// instead of being retransmitted until the exchange deadline.
pub(super) const COAP_RESET_ERROR: &str = "CoAP request was reset by the peer";

#[derive(Debug, Clone, Copy)]
pub(super) struct CoapRetransmitSchedule {
    timeout: Duration,
    retransmissions: u8,
}

impl CoapRetransmitSchedule {
    fn randomized(rng: &mut impl RngCore) -> Self {
        let jitter = u64::from(rng.next_u32()) % (COAP_ACK_RANDOM_WINDOW_MILLIS + 1);
        Self::new(COAP_ACK_TIMEOUT + Duration::from_millis(jitter))
    }

    const fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            retransmissions: 0,
        }
    }

    const fn timeout(self) -> Option<Duration> {
        if self.retransmissions < COAP_MAX_RETRANSMIT {
            Some(self.timeout)
        } else {
            None
        }
    }

    fn record_retransmission(&mut self) {
        self.retransmissions = self.retransmissions.saturating_add(1);
        self.timeout = self.timeout.saturating_mul(2);
    }
}

/// A request waiting to be sent.
#[derive(Debug)]
pub(in super::super) struct Outbound {
    /// The request; its message ID and token are assigned when it is sent.
    pub(in super::super) message: CoapMessage,
    pub(in super::super) destination: Destination,
    /// Whether to wait for a response. Without one the exchange completes
    /// as soon as the request is sent.
    pub(in super::super) expect_response: bool,
    /// Operation name for traces.
    pub(in super::super) label: &'static str,
}

/// Who is waiting for an exchange, and what its outcome means.
#[derive(Debug)]
pub(super) enum Completion {
    /// A handle request, identified so its caller can withdraw it.
    Caller {
        id: u64,
        reply: oneshot::Sender<Result<Option<CoapMessage>>>,
    },
    /// A petition.
    Petition(oneshot::Sender<Result<PetitionResponse>>),
    /// A keep-alive; `None` when the driver scheduled it.
    KeepAlive(Option<oneshot::Sender<Result<ResultCode>>>),
    /// A resignation; `None` when every handle was dropped.
    Resign(Option<oneshot::Sender<Result<()>>>),
}

impl Completion {
    /// Whether this exchange counts against the application in-flight limit.
    const fn is_application(&self) -> bool {
        matches!(self, Self::Caller { .. })
    }

    /// Whether this is the handle request `id`.
    const fn is_caller(&self, id: u64) -> bool {
        matches!(self, Self::Caller { id: caller, .. } if *caller == id)
    }
}

/// A sent request waiting for its response.
#[derive(Debug)]
pub(super) struct Pending {
    /// The logical request with its assigned identity; for a proxied request,
    /// the encapsulated inner request.
    pub(super) request: CoapMessage,
    destination: Destination,
    label: &'static str,
    retransmit: Option<CoapRetransmitSchedule>,
    retry_at: Option<Instant>,
    deadline: Instant,
    pub(super) completion: Completion,
}

impl Pending {
    /// Whether answers to this exchange arrive through the UDP proxy rather
    /// than directly from the border agent.
    const fn is_proxied(&self) -> bool {
        matches!(self.destination, Destination::Mesh { .. })
    }
}

/// Exchanges in flight and application requests waiting for a slot.
#[derive(Debug, Default)]
pub(super) struct Exchanges {
    pub(super) in_flight: Vec<Pending>,
    queued: VecDeque<(Outbound, Completion)>,
}

impl Exchanges {
    fn application_in_flight(&self) -> usize {
        self.in_flight
            .iter()
            .filter(|pending| pending.completion.is_application())
            .count()
    }

    /// Whether a resignation is outstanding.
    pub(super) fn resigning(&self) -> bool {
        self.in_flight
            .iter()
            .any(|pending| matches!(pending.completion, Completion::Resign(_)))
    }

    /// Whether a keep-alive is outstanding.
    pub(super) fn keep_alive_outstanding(&self) -> bool {
        self.in_flight
            .iter()
            .any(|pending| matches!(pending.completion, Completion::KeepAlive(_)))
    }

    /// Removes the handle request `id`, queued or in flight, and reports
    /// whether it was found.
    fn withdraw(&mut self, id: u64) -> bool {
        if let Some(index) = self
            .queued
            .iter()
            .position(|(_, completion)| completion.is_caller(id))
        {
            self.queued.remove(index);
            return true;
        }
        if let Some(index) = self
            .in_flight
            .iter()
            .position(|pending| pending.completion.is_caller(id))
        {
            self.in_flight.remove(index);
            return true;
        }
        false
    }

    /// Returns the earliest retransmission or deadline among in-flight
    /// exchanges.
    pub(super) fn next_deadline(&self) -> Option<Instant> {
        self.in_flight
            .iter()
            .flat_map(|pending| [pending.retry_at, Some(pending.deadline)])
            .flatten()
            .min()
    }

    /// Removes every in-flight and queued exchange.
    pub(super) fn drain(&mut self) -> Vec<Completion> {
        let mut completions: Vec<Completion> = self
            .in_flight
            .drain(..)
            .map(|pending| pending.completion)
            .collect();
        completions.extend(self.queued.drain(..).map(|(_, completion)| completion));
        completions
    }
}

impl Driver {
    /// Queues an application request, sending it when a slot is free.
    pub(super) async fn submit(&mut self, request: Outbound, completion: Completion) {
        self.exchanges.queued.push_back((request, completion));
        self.send_queued().await;
    }

    /// Forgets the handle request `id`, whose caller stopped waiting: a queued
    /// request is never sent, and a sent one is no longer retransmitted and
    /// frees its slot. A late response to it is dropped as unmatched.
    pub(super) async fn withdraw(&mut self, id: u64) {
        if self.exchanges.withdraw(id) {
            commissioner_trace(format_args!("request {id} withdrawn by its caller"));
            self.send_queued().await;
        }
    }

    /// Sends queued application requests while the in-flight limit allows.
    pub(super) async fn send_queued(&mut self) {
        while self.exchanges.application_in_flight() < MAX_APPLICATION_IN_FLIGHT {
            let Some((request, completion)) = self.exchanges.queued.pop_front() else {
                return;
            };
            // Boxed: starting can complete an exchange, which sends queued
            // requests in turn.
            Box::pin(self.start(request, completion)).await;
            if self.is_closed() {
                return;
            }
        }
    }

    /// Assigns the request's identity, sends it, and tracks its response.
    pub(super) async fn start(&mut self, request: Outbound, completion: Completion) {
        let Outbound {
            mut message,
            destination,
            expect_response,
            label,
        } = request;
        self.assign_identity(&mut message);
        let wire_message = match self.wire_message(&message, destination) {
            Ok(wire_message) => wire_message,
            Err(err) => return self.complete(completion, Err(err)).await,
        };
        commissioner_trace(format_args!(
            "send {label} mid={} token={} destination={destination:?}",
            message.message_id,
            hex::encode(&message.token)
        ));
        if let Err(err) = self.link.send_request(&wire_message).await {
            return self.fail_send(completion, err).await;
        }
        if !expect_response {
            return self.complete(completion, Ok(None)).await;
        }
        let now = Instant::now();
        let retransmit = (message.ty == meshcop::CoapType::Confirmable)
            .then(|| CoapRetransmitSchedule::randomized(&mut rand_core::OsRng));
        let retry_at = retransmit
            .and_then(CoapRetransmitSchedule::timeout)
            .map(|timeout| now + timeout);
        self.exchanges.in_flight.push(Pending {
            request: message,
            destination,
            label,
            retransmit,
            retry_at,
            deadline: now + COAP_EXCHANGE_TIMEOUT,
            completion,
        });
    }

    /// Fails an exchange whose request could not be sent. A transport
    /// failure also ends the session, first, so queued requests fail with the
    /// session instead of being tried on the broken link.
    async fn fail_send(&mut self, completion: Completion, err: Error) {
        if is_transport_error(&err) {
            self.transport_failed(err.to_string()).await;
        }
        self.complete(completion, Err(err)).await;
    }

    /// Retransmits and expires in-flight exchanges whose timers are due.
    pub(super) async fn run_exchange_timers(&mut self) {
        let now = Instant::now();
        let mut index = 0;
        while index < self.exchanges.in_flight.len() {
            let pending = &self.exchanges.in_flight[index];
            if pending.deadline <= now {
                let pending = self.exchanges.in_flight.remove(index);
                commissioner_trace(format_args!(
                    "{} mid={} timed out",
                    pending.label, pending.request.message_id
                ));
                self.complete(
                    pending.completion,
                    Err(Error::Timeout("MeshCoP exchange timed out")),
                )
                .await;
                if self.is_closed() {
                    return;
                }
                continue;
            }
            if pending.retry_at.is_some_and(|retry_at| retry_at <= now) {
                let (request, destination) = (pending.request.clone(), pending.destination);
                let result = match self.wire_message(&request, destination) {
                    Ok(wire_message) => self.link.send(&wire_message).await,
                    Err(err) => Err(err),
                };
                if let Err(err) = result {
                    if is_transport_error(&err) {
                        return self.transport_failed(err.to_string()).await;
                    }
                }
                let pending = &mut self.exchanges.in_flight[index];
                if let Some(schedule) = pending.retransmit.as_mut() {
                    schedule.record_retransmission();
                    pending.retry_at = schedule.timeout().map(|timeout| now + timeout);
                    commissioner_trace(format_args!(
                        "retransmit {} mid={} attempt={}",
                        pending.label, pending.request.message_id, schedule.retransmissions
                    ));
                }
            }
            index += 1;
        }
        self.send_queued().await;
    }

    /// Stops retransmitting the exchange that `ack` acknowledges, if it is an
    /// empty ACK that arrived by the exchange's route (`proxied` or direct);
    /// the separate response is still awaited.
    pub(super) fn acknowledge(&mut self, ack: &CoapMessage, proxied: bool) -> bool {
        match self.exchanges.in_flight.iter_mut().find(|pending| {
            pending.is_proxied() == proxied && ack.is_empty_ack_for(pending.request.message_id)
        }) {
            Some(pending) => {
                pending.retry_at = None;
                true
            }
            None => false,
        }
    }

    /// Removes and returns the exchange answered by `response`: a Reset of
    /// its message ID, or a response carrying its token. Only exchanges on
    /// the route `response` arrived by (`proxied` or direct) can match, so a
    /// mesh device answering through the proxy cannot complete an exchange
    /// with the border agent itself.
    pub(super) fn take_answered(
        &mut self,
        response: &CoapMessage,
        proxied: bool,
    ) -> Option<Pending> {
        let index = self.exchanges.in_flight.iter().position(|pending| {
            pending.is_proxied() == proxied
                && (response.is_reset_for(pending.request.message_id)
                    || (is_response(response) && response.token == pending.request.token))
        })?;
        Some(self.exchanges.in_flight.remove(index))
    }

    pub(super) fn assign_identity(&mut self, message: &mut CoapMessage) {
        self.next_message_id = self.next_message_id.wrapping_add(1);
        message.message_id = self.next_message_id;
        message.token = self.unused_token();
    }

    /// Returns a random token that no in-flight exchange uses, so responses
    /// cannot be predicted from message IDs.
    fn unused_token(&self) -> Vec<u8> {
        loop {
            let mut token = vec![0; TOKEN_LENGTH];
            rand_core::OsRng.fill_bytes(&mut token);
            let in_use = self
                .exchanges
                .in_flight
                .iter()
                .any(|pending| pending.request.token == token);
            if !in_use {
                return token;
            }
        }
    }

    /// Returns the message to put on the wire for `request`: the request
    /// itself, or a UDP_TX encapsulation with a fresh outer identity.
    pub(super) fn wire_message(
        &mut self,
        request: &CoapMessage,
        destination: Destination,
    ) -> Result<CoapMessage> {
        match destination {
            Destination::BorderAgent => Ok(request.clone()),
            Destination::Mesh { address, port } => {
                let inner = request.encode()?;
                let mut outer = meshcop::udp_tx_request(0, Vec::new(), address, port, &inner)?;
                self.assign_identity(&mut outer);
                Ok(outer)
            }
        }
    }
}

/// Whether `message` is a response (2.xx, 4.xx, or 5.xx) rather than a
/// request, an empty message, or a reserved code class.
const fn is_response(message: &CoapMessage) -> bool {
    matches!(message.code.0 >> 5, 2 | 4 | 5)
}

/// Whether `err` means the DTLS session or socket is unusable.
pub(super) fn is_transport_error(err: &Error) -> bool {
    matches!(err, Error::Io(_) | Error::Dtls(_))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::Error as RandError;

    struct FixedRng(u32);

    impl RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            self.0
        }

        fn next_u64(&mut self) -> u64 {
            u64::from(self.0)
        }

        fn fill_bytes(&mut self, destination: &mut [u8]) {
            destination.fill(0);
        }

        fn try_fill_bytes(
            &mut self,
            destination: &mut [u8],
        ) -> core::result::Result<(), RandError> {
            destination.fill(0);
            Ok(())
        }
    }

    #[test]
    fn randomized_coap_timeout_spans_the_inclusive_two_to_three_second_window() {
        let minimum = CoapRetransmitSchedule::randomized(&mut FixedRng(0));
        let maximum = CoapRetransmitSchedule::randomized(&mut FixedRng(1_000));
        assert_eq!(minimum.timeout(), Some(Duration::from_secs(2)));
        assert_eq!(maximum.timeout(), Some(Duration::from_secs(3)));
    }

    #[test]
    fn coap_retransmit_schedule_doubles_and_stops_at_the_exchange_limit() {
        let mut schedule = CoapRetransmitSchedule::new(Duration::from_secs(2));
        schedule.record_retransmission();
        assert_eq!(schedule.timeout(), Some(Duration::from_secs(4)));
        schedule.record_retransmission();
        assert_eq!(schedule.timeout(), None);
    }

    #[test]
    fn only_non_empty_non_request_codes_are_responses() {
        let request = CoapMessage::post_request(
            meshcop::CoapType::Confirmable,
            1,
            vec![0, 1],
            meshcop::uri::KEEP_ALIVE,
            Vec::new(),
        )
        .unwrap();
        assert!(!is_response(&request));
        assert!(!is_response(&CoapMessage::empty_ack(1)));
        assert!(is_response(&CoapMessage::empty_changed_response(&request)));
    }
}
