//! Transport layer: DTLS session management, request/response routing, and
//! UDP_TX/UDP_RX proxy encapsulation with ALOC addressing.

use std::net::Ipv6Addr;
use std::time::Duration;

use crate::{
    Result,
    dataset::Dataset,
    error::Error,
    meshcop::{self, CommissionerOperation},
};
use meshcop_dtls::DtlsSession;
use rand_core::RngCore;

use super::super::types::{CommissionerEvent, CommissionerState, DatasetFlags};
use super::{
    COAP_EXCHANGE_TIMEOUT, Commissioner, DTLS_HANDSHAKE_TIMEOUT, MeshcopRoute, aloc_address,
    check_state_response, commissioner_trace,
};

const COAP_ACK_TIMEOUT: Duration = Duration::from_secs(2);
const COAP_ACK_RANDOM_WINDOW_MILLIS: u64 = 1_000;
// Two retries always fit the 12-second MeshCoP operation deadline with the
// RFC 7252 randomized 2-3 second initial timeout and its doubled successor.
const COAP_MAX_RETRANSMIT: u8 = 2;

#[derive(Debug, Clone, Copy)]
struct CoapRetransmitSchedule {
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

#[derive(Debug)]
enum IncomingOutcome {
    Response(meshcop::CoapMessage),
    Acknowledged,
    Continue,
}

impl Commissioner {
    /// Returns the cached mesh-local prefix, fetching it from the active
    /// dataset when needed.
    async fn require_mesh_local_prefix(&mut self) -> Result<[u8; 8]> {
        if let Some(prefix) = self.mesh_local_prefix {
            return Ok(prefix);
        }
        let raw = self
            .get_raw_active_dataset(DatasetFlags::MESH_LOCAL_PREFIX)
            .await?;
        let dataset = Dataset::from_bytes(&raw)?;
        let prefix = dataset.mesh_local_prefix()?.ok_or(Error::InvalidState(
            "active dataset does not include the mesh-local prefix",
        ))?;
        if prefix[0] != 0xfd {
            return Err(Error::Dataset(
                "mesh-local prefix must be within fd00::/8".to_string(),
            ));
        }
        self.mesh_local_prefix = Some(prefix);
        Ok(prefix)
    }

    /// Returns the anycast address of the Thread leader.
    pub(super) async fn leader_aloc(&mut self) -> Result<Ipv6Addr> {
        let prefix = self.require_mesh_local_prefix().await?;
        Ok(aloc_address(prefix, meshcop::LEADER_ALOC16))
    }

    /// Returns the anycast address of the Primary Backbone Router.
    pub(super) async fn primary_bbr_aloc(&mut self) -> Result<Ipv6Addr> {
        let prefix = self.require_mesh_local_prefix().await?;
        Ok(aloc_address(prefix, meshcop::PRIMARY_BBR_ALOC16))
    }

    pub(super) async fn execute_state_operation(
        &mut self,
        operation: CommissionerOperation,
        request: meshcop::CoapMessage,
        state_mandatory: bool,
    ) -> Result<()> {
        let response = self.execute_meshcop(operation, request).await?;
        check_state_response(&response, state_mandatory)
    }

    /// Executes a direct border-agent exchange and returns the response.
    pub(super) async fn execute_meshcop(
        &mut self,
        operation: CommissionerOperation,
        request: meshcop::CoapMessage,
    ) -> Result<meshcop::CoapMessage> {
        let response = self
            .execute(operation, request, MeshcopRoute::Direct, true)
            .await?;
        response
            .ok_or(Error::InvalidState("MeshCoP exchange produced no response"))
            .and_then(require_success_response)
    }

    /// Executes a UDP-proxied exchange and returns the inner response.
    pub(super) async fn execute_proxied(
        &mut self,
        operation: CommissionerOperation,
        request: meshcop::CoapMessage,
        destination: Ipv6Addr,
    ) -> Result<meshcop::CoapMessage> {
        let route = MeshcopRoute::Proxied {
            destination,
            destination_port: meshcop::DEFAULT_MM_PORT,
        };
        let response = self.execute(operation, request, route, true).await?;
        response
            .ok_or(Error::InvalidState("MeshCoP exchange produced no response"))
            .and_then(require_success_response)
    }

    /// Executes a proxied command, waiting for a response only when the inner
    /// request is confirmable.
    pub(super) async fn execute_proxied_command(
        &mut self,
        operation: CommissionerOperation,
        request: meshcop::CoapMessage,
        destination: Ipv6Addr,
    ) -> Result<()> {
        let wait_for_response = request.ty == meshcop::CoapType::Confirmable;
        let route = MeshcopRoute::Proxied {
            destination,
            destination_port: meshcop::DEFAULT_MM_PORT,
        };
        match self
            .execute(operation, request, route, wait_for_response)
            .await?
        {
            Some(response) => check_state_response(&response, false),
            None => Ok(()),
        }
    }

    /// Sends a request without waiting for any response.
    pub(super) async fn execute_no_response(
        &mut self,
        operation: CommissionerOperation,
        request: meshcop::CoapMessage,
    ) -> Result<()> {
        self.execute(operation, request, MeshcopRoute::Direct, false)
            .await
            .map(|_| ())
    }

    async fn execute(
        &mut self,
        operation: CommissionerOperation,
        request: meshcop::CoapMessage,
        route: MeshcopRoute,
        wait_for_response: bool,
    ) -> Result<Option<meshcop::CoapMessage>> {
        if self.state == CommissionerState::Disabled {
            return Err(Error::InvalidState("commissioner is disconnected"));
        }

        let wire_message = match route {
            MeshcopRoute::Direct => request.clone(),
            MeshcopRoute::Proxied {
                destination,
                destination_port,
            } => {
                let inner = request.encode()?;
                let (message_id, token) = self.next_request_identity();
                meshcop::udp_tx_request(message_id, token, destination, destination_port, &inner)?
            }
        };
        commissioner_trace(format_args!(
            "send {} mid={} token={} route={route:?}",
            operation.label(),
            request.message_id,
            hex::encode(&request.token)
        ));

        #[cfg(any(test, feature = "test-support"))]
        if let Some(scripted) = self.scripted_transport.as_mut() {
            let mut incoming = scripted.exchange(operation, wire_message)?;
            if !wait_for_response {
                return Ok(None);
            }
            loop {
                let Some(message) = incoming.pop_front() else {
                    return Err(Error::InvalidState(
                        "scripted MeshCoP exchange did not produce a response",
                    ));
                };
                if let IncomingOutcome::Response(response) =
                    self.route_incoming(Some(&request), &message).await?
                {
                    return Ok(Some(response));
                }
            }
        }

        Box::pin(self.execute_live(operation, request, wire_message, route, wait_for_response))
            .await
    }

    async fn execute_live(
        &mut self,
        operation: CommissionerOperation,
        request: meshcop::CoapMessage,
        wire_message: meshcop::CoapMessage,
        route: MeshcopRoute,
        wait_for_response: bool,
    ) -> Result<Option<meshcop::CoapMessage>> {
        self.ensure_dtls_session().await?;
        let wire = wire_message.encode()?;
        self.send_application_data(&wire).await?;
        if !wait_for_response {
            return Ok(None);
        }

        let retransmit = (request.ty == meshcop::CoapType::Confirmable).then(|| {
            let mut rng = rand_core::OsRng;
            CoapRetransmitSchedule::randomized(&mut rng)
        });
        with_meshcop_exchange_timeout(Box::pin(
            self.wait_for_response(operation, &request, &wire, route, retransmit),
        ))
        .await
    }

    async fn wait_for_response(
        &mut self,
        operation: CommissionerOperation,
        request: &meshcop::CoapMessage,
        wire: &[u8],
        route: MeshcopRoute,
        mut retransmit: Option<CoapRetransmitSchedule>,
    ) -> Result<Option<meshcop::CoapMessage>> {
        let mut retry_at = retransmit
            .and_then(CoapRetransmitSchedule::timeout)
            .map(|timeout| tokio::time::Instant::now() + timeout);
        loop {
            let response_wire = if let Some(deadline) = retry_at {
                tokio::select! {
                    response = self.recv_application_data() => response?,
                    () = tokio::time::sleep_until(deadline) => {
                        let retransmission = self.retransmission_wire(request, wire, route)?;
                        self.send_application_data(&retransmission).await?;
                        let schedule = retransmit
                            .as_mut()
                            .ok_or(Error::InvalidState("CoAP retransmission schedule is missing"))?;
                        schedule.record_retransmission();
                        retry_at = schedule
                            .timeout()
                            .map(|timeout| tokio::time::Instant::now() + timeout);
                        commissioner_trace(format_args!(
                            "retransmit {} mid={} attempt={}",
                            operation.label(),
                            request.message_id,
                            schedule.retransmissions
                        ));
                        continue;
                    }
                }
            } else {
                self.recv_application_data().await?
            };
            let message = meshcop::CoapMessage::decode(&response_wire)?;
            commissioner_trace(format_args!(
                "recv {} mid={} type={:?} code=0x{:02x} token={}",
                operation.label(),
                message.message_id,
                message.ty,
                message.code.0,
                hex::encode(&message.token)
            ));
            match self.route_incoming(Some(request), &message).await? {
                IncomingOutcome::Response(response) => return Ok(Some(response)),
                IncomingOutcome::Acknowledged => retry_at = None,
                IncomingOutcome::Continue => {}
            }
        }
    }

    fn retransmission_wire(
        &mut self,
        request: &meshcop::CoapMessage,
        initial_wire: &[u8],
        route: MeshcopRoute,
    ) -> Result<Vec<u8>> {
        match route {
            MeshcopRoute::Direct => Ok(initial_wire.to_vec()),
            MeshcopRoute::Proxied {
                destination,
                destination_port,
            } => {
                let inner = request.encode()?;
                let (message_id, token) = self.next_request_identity();
                meshcop::udp_tx_request(message_id, token, destination, destination_port, &inner)?
                    .encode()
            }
        }
    }

    /// Routes one incoming message.
    ///
    /// When `expected` is set and `incoming` answers that request (directly or
    /// through a UDP_RX encapsulation), the response is returned. Unsolicited
    /// notifications are converted to queued events. Unmatched direct and
    /// proxied messages are dropped so delayed duplicate responses cannot
    /// poison a later exchange.
    pub(super) async fn handle_incoming(
        &mut self,
        expected: Option<&meshcop::CoapMessage>,
        incoming: &meshcop::CoapMessage,
    ) -> Result<Option<meshcop::CoapMessage>> {
        match self.route_incoming(expected, incoming).await? {
            IncomingOutcome::Response(response) => Ok(Some(response)),
            IncomingOutcome::Acknowledged | IncomingOutcome::Continue => Ok(None),
        }
    }

    async fn route_incoming(
        &mut self,
        expected: Option<&meshcop::CoapMessage>,
        incoming: &meshcop::CoapMessage,
    ) -> Result<IncomingOutcome> {
        let udp_rx = match meshcop::parse_udp_rx(incoming) {
            Ok(udp_rx) => udp_rx,
            Err(err) => {
                // A peer on the mesh controls UDP_RX contents; drop malformed
                // encapsulations instead of failing the commissioner exchange.
                commissioner_trace(format_args!("drop malformed UDP_RX: {err}"));
                return Ok(IncomingOutcome::Continue);
            }
        };
        if let Some(udp_rx) = udp_rx {
            if udp_rx.destination_port != meshcop::DEFAULT_MM_PORT {
                commissioner_trace(format_args!(
                    "drop UDP_RX for unsupported port {}",
                    udp_rx.destination_port
                ));
                return Ok(IncomingOutcome::Continue);
            }
            let inner = match meshcop::CoapMessage::decode(&udp_rx.payload) {
                Ok(inner) => inner,
                Err(err) => {
                    commissioner_trace(format_args!("drop undecodable proxied datagram: {err}"));
                    return Ok(IncomingOutcome::Continue);
                }
            };
            if let Some(request) = expected {
                if inner.is_empty_ack_for(request.message_id) {
                    return Ok(IncomingOutcome::Acknowledged);
                }
                if inner.token == request.token {
                    if inner.ty == meshcop::CoapType::Confirmable {
                        self.send_proxied_ack(
                            meshcop::CoapMessage::empty_ack(inner.message_id),
                            &udp_rx,
                        )
                        .await?;
                    }
                    return Ok(IncomingOutcome::Response(inner));
                }
            }
            if self.route_unsolicited_proxied(&inner, &udp_rx).await? {
                return Ok(IncomingOutcome::Continue);
            }
            commissioner_trace(format_args!(
                "drop unmatched proxied message mid={} token={}",
                inner.message_id,
                hex::encode(&inner.token)
            ));
            return Ok(IncomingOutcome::Continue);
        }

        if let Some(request) = expected {
            if incoming.is_empty_ack_for(request.message_id) {
                return Ok(IncomingOutcome::Acknowledged);
            }
            if incoming.token == request.token {
                self.ack_if_confirmable(incoming).await?;
                return Ok(IncomingOutcome::Response(incoming.clone()));
            }
        }
        if self.route_unsolicited_message(incoming).await? {
            self.ack_if_confirmable(incoming).await?;
            return Ok(IncomingOutcome::Continue);
        }
        match expected {
            Some(_) => {
                commissioner_trace(format_args!(
                    "drop unmatched direct message mid={} token={}",
                    incoming.message_id,
                    hex::encode(&incoming.token)
                ));
                Ok(IncomingOutcome::Continue)
            }
            None => Ok(IncomingOutcome::Continue),
        }
    }

    async fn ensure_dtls_session(&mut self) -> Result<()> {
        if self.dtls_session.is_none() {
            let session = with_dtls_handshake_timeout(async {
                DtlsSession::connect(
                    &self.socket,
                    self.config.pskc.as_bytes(),
                    DTLS_HANDSHAKE_TIMEOUT,
                )
                .await
                .map_err(Error::from)
            })
            .await?;
            self.dtls_session = Some(session);
        }
        Ok(())
    }

    /// Sends an encoded CoAP message over the active transport.
    pub(super) async fn send_wire(&mut self, message: &meshcop::CoapMessage) -> Result<()> {
        #[cfg(any(test, feature = "test-support"))]
        if let Some(scripted) = &mut self.scripted_transport {
            scripted.record_sent(message.clone());
            return Ok(());
        }
        let wire = message.encode()?;
        self.send_application_data(&wire).await
    }

    async fn send_application_data(&mut self, data: &[u8]) -> Result<()> {
        let session = self
            .dtls_session
            .as_mut()
            .ok_or(Error::InvalidState("DTLS session is not established"))?;
        session
            .send_application_data(&self.socket, data)
            .await
            .map_err(Error::from)
    }

    pub(super) async fn recv_application_data(&mut self) -> Result<Vec<u8>> {
        let session = self
            .dtls_session
            .as_mut()
            .ok_or(Error::InvalidState("DTLS session is not established"))?;
        session
            .recv_application_data(&self.socket, COAP_EXCHANGE_TIMEOUT)
            .await
            .map_err(Error::from)
    }

    async fn ack_if_confirmable(&mut self, message: &meshcop::CoapMessage) -> Result<()> {
        if message.ty == meshcop::CoapType::Confirmable {
            let ack = meshcop::CoapMessage::empty_ack(message.message_id);
            self.send_wire(&ack).await?;
        }
        Ok(())
    }

    /// Sends `response` back through the UDP proxy to the UDP_RX source.
    async fn send_proxied_ack(
        &mut self,
        response: meshcop::CoapMessage,
        udp_rx: &meshcop::UdpRx,
    ) -> Result<()> {
        let inner = response.encode()?;
        let (message_id, token) = self.next_request_identity();
        let udp_tx = meshcop::udp_tx_request(
            message_id,
            token,
            udp_rx.source_address,
            udp_rx.source_port,
            &inner,
        )?;
        self.send_wire(&udp_tx).await
    }

    async fn route_unsolicited_message(&mut self, message: &meshcop::CoapMessage) -> Result<bool> {
        let Some(notification) = meshcop::parse_notification(message)? else {
            return Ok(false);
        };
        if let meshcop::MeshcopNotification::RelayRx {
            joiner_udp_port,
            joiner_router_locator,
            joiner_iid,
            payload,
        } = &notification
        {
            if self.joiner_handler.is_some() {
                self.handle_relay_rx(
                    *joiner_udp_port,
                    *joiner_router_locator,
                    *joiner_iid,
                    payload,
                )
                .await?;
                return Ok(true);
            }
        }
        if notification == meshcop::MeshcopNotification::DatasetChanged {
            // A dataset change may move the mesh-local prefix; drop the cache so
            // the next ALOC/RLOC route is recomputed. Mirrors the proxied path
            // in `route_unsolicited_proxied`.
            self.mesh_local_prefix = None;
        }
        let event = self.notification_to_event(notification, self.border_agent.ip().to_string());
        self.queue_event(event);
        Ok(true)
    }

    /// Routes a notification that arrived encapsulated in UDP_RX.
    async fn route_unsolicited_proxied(
        &mut self,
        inner: &meshcop::CoapMessage,
        udp_rx: &meshcop::UdpRx,
    ) -> Result<bool> {
        let Some(notification) = meshcop::parse_notification(inner)? else {
            return Ok(false);
        };
        if notification == meshcop::MeshcopNotification::DatasetChanged {
            // The dataset change may carry a new mesh-local prefix; refresh it
            // before the next proxied request.
            self.mesh_local_prefix = None;
        }
        let event = self.notification_to_event(notification, udp_rx.source_address.to_string());
        self.queue_event(event);
        if inner.ty == meshcop::CoapType::Confirmable {
            self.send_proxied_ack(meshcop::CoapMessage::empty_changed_response(inner), udp_rx)
                .await?;
        }
        Ok(true)
    }

    fn notification_to_event(
        &self,
        notification: meshcop::MeshcopNotification,
        peer_addr: String,
    ) -> CommissionerEvent {
        match notification {
            meshcop::MeshcopNotification::DatasetChanged => CommissionerEvent::DatasetChanged,
            meshcop::MeshcopNotification::DiagGetAnswer { data } => {
                CommissionerEvent::DiagnosticAnswer { peer_addr, data }
            }
            meshcop::MeshcopNotification::PanIdConflict {
                channel_mask,
                pan_id,
            } => CommissionerEvent::PanIdConflict {
                peer_addr,
                channel_mask,
                pan_id,
            },
            meshcop::MeshcopNotification::EnergyReport {
                channel_mask,
                energy_list,
            } => CommissionerEvent::EnergyReport {
                peer_addr,
                channel_mask,
                energy_list,
            },
            meshcop::MeshcopNotification::RelayRx {
                joiner_udp_port,
                joiner_iid,
                payload,
                ..
            } => CommissionerEvent::JoinerMessage {
                joiner_id: joiner_iid.to_vec(),
                port: joiner_udp_port,
                payload,
            },
        }
    }
}

async fn with_meshcop_exchange_timeout<T>(
    exchange: impl core::future::Future<Output = Result<T>>,
) -> Result<T> {
    tokio::time::timeout(COAP_EXCHANGE_TIMEOUT, exchange)
        .await
        .map_err(|_| Error::Timeout("MeshCoP exchange timed out"))?
}

async fn with_dtls_handshake_timeout<T>(
    handshake: impl core::future::Future<Output = Result<T>>,
) -> Result<T> {
    tokio::time::timeout(DTLS_HANDSHAKE_TIMEOUT, handshake)
        .await
        .map_err(|_| Error::Timeout("DTLS handshake timed out"))?
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commissioner::CommissionerConfig;
    use crate::meshcop::{CoapCode, CoapMessage, CoapType, TLV_UDP_ENCAPSULATION};
    use crate::tlv::TlvSet;
    use meshcop_dtls::DtlsServer;
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
            destination.fill(self.0 as u8);
        }

        fn try_fill_bytes(
            &mut self,
            destination: &mut [u8],
        ) -> core::result::Result<(), RandError> {
            self.fill_bytes(destination);
            Ok(())
        }
    }

    #[test]
    fn randomized_coap_timeout_spans_the_inclusive_two_to_three_second_window() {
        let lower = CoapRetransmitSchedule::randomized(&mut FixedRng(0));
        let upper = CoapRetransmitSchedule::randomized(&mut FixedRng(1_000));
        assert_eq!(lower.timeout(), Some(Duration::from_secs(2)));
        assert_eq!(upper.timeout(), Some(Duration::from_secs(3)));
    }

    #[test]
    fn coap_retransmit_schedule_doubles_and_stops_at_the_exchange_limit() {
        let mut schedule = CoapRetransmitSchedule::new(Duration::from_secs(2));
        for expected in [2, 4] {
            assert_eq!(schedule.timeout(), Some(Duration::from_secs(expected)));
            schedule.record_retransmission();
        }
        assert_eq!(schedule.timeout(), None);
        assert_eq!(schedule.retransmissions, COAP_MAX_RETRANSMIT);
    }

    #[tokio::test]
    async fn proxied_retry_preserves_inner_identity_and_refreshes_outer_identity() {
        let pskc = [0x42; 16];
        let server = DtlsServer::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr();
        let destination: Ipv6Addr = "fd00::1".parse().unwrap();
        let server_task = async move {
            let mut session = server.accept(&pskc, Duration::from_secs(10)).await.unwrap();
            let first_wire = session
                .recv_application_data(Duration::from_secs(10))
                .await
                .unwrap();
            let second_wire = session
                .recv_application_data(Duration::from_secs(5))
                .await
                .unwrap();
            let first = CoapMessage::decode(&first_wire).unwrap();
            let second = CoapMessage::decode(&second_wire).unwrap();
            assert_eq!(first.ty, CoapType::NonConfirmable);
            assert_eq!(second.ty, CoapType::NonConfirmable);
            assert_ne!(first.message_id, second.message_id);
            assert_ne!(first.token, second.token);

            let first_inner = proxied_inner_wire(&first);
            let second_inner = proxied_inner_wire(&second);
            assert_eq!(first_inner, second_inner);
            let request = CoapMessage::decode(&first_inner).unwrap();
            let response = CoapMessage {
                ty: CoapType::Acknowledgement,
                code: CoapCode::CHANGED,
                message_id: request.message_id,
                token: request.token,
                options: Vec::new(),
                payload: Vec::new(),
            };
            let outer = crate::commissioner::harness::udp_rx_message(
                destination,
                meshcop::DEFAULT_MM_PORT,
                meshcop::DEFAULT_MM_PORT,
                &response.encode().unwrap(),
            )
            .unwrap();
            session
                .send_application_data(&outer.encode().unwrap())
                .await
                .unwrap();
        };

        let mut commissioner =
            Commissioner::connect(CommissionerConfig::pskc("proxied-retry", pskc), server_addr)
                .await
                .unwrap();
        let request = CoapMessage::post_request(
            CoapType::Confirmable,
            0x1234,
            [0x12, 0x34],
            "/test",
            Vec::new(),
        )
        .unwrap();
        let route = MeshcopRoute::Proxied {
            destination,
            destination_port: meshcop::DEFAULT_MM_PORT,
        };
        let ((), response) = tokio::join!(
            server_task,
            commissioner.execute(CommissionerOperation::Petition, request, route, true)
        );
        assert!(response.unwrap().is_some());
    }

    fn proxied_inner_wire(message: &CoapMessage) -> Vec<u8> {
        let tlvs = TlvSet::parse(&message.payload).unwrap();
        tlvs.last_value(TLV_UDP_ENCAPSULATION).unwrap()[4..].to_vec()
    }

    #[tokio::test(start_paused = true)]
    async fn meshcop_exchange_timeout_is_absolute() {
        let started = tokio::time::Instant::now();
        let err = with_meshcop_exchange_timeout(core::future::pending::<Result<()>>())
            .await
            .unwrap_err();

        assert!(matches!(err, Error::Timeout("MeshCoP exchange timed out")));
        assert_eq!(started.elapsed(), COAP_EXCHANGE_TIMEOUT);
    }

    #[tokio::test(start_paused = true)]
    async fn dtls_handshake_timeout_is_absolute() {
        let started = tokio::time::Instant::now();
        let err = with_dtls_handshake_timeout(core::future::pending::<Result<()>>())
            .await
            .unwrap_err();

        assert!(matches!(err, Error::Timeout("DTLS handshake timed out")));
        assert_eq!(started.elapsed(), DTLS_HANDSHAKE_TIMEOUT);
    }
}
