//! Routing of messages received from the border agent: responses to
//! outstanding exchanges, UDP_RX decapsulation, and unsolicited
//! notifications.

use crate::{
    Result,
    error::Error,
    meshcop::{self, CoapMessage},
};

use super::super::super::types::{CommissionerEvent, Destination};
use super::super::commissioner_trace;
use super::Driver;
use super::exchange::COAP_RESET_ERROR;

impl Driver {
    /// Routes one received message.
    ///
    /// A response completes the exchange it answers, a Reset fails it, and an
    /// empty ACK stops its retransmission. Unsolicited notifications become
    /// events. A retransmitted confirmable message gets its first copy's
    /// reply again and nothing else. Malformed and unmatched messages are
    /// dropped so delayed duplicates and peer-controlled UDP_RX contents
    /// cannot disturb the session.
    pub(super) async fn route_incoming(&mut self, incoming: CoapMessage) -> Result<()> {
        let udp_rx = match meshcop::parse_udp_rx(&incoming) {
            Ok(udp_rx) => udp_rx,
            Err(err) => {
                // A peer on the mesh controls UDP_RX contents; drop malformed
                // encapsulations instead of failing the session.
                commissioner_trace(format_args!("drop malformed UDP_RX: {err}"));
                return Ok(());
            }
        };
        let Some(udp_rx) = udp_rx else {
            return self.route_direct(incoming).await;
        };
        if udp_rx.destination_port != meshcop::DEFAULT_MM_PORT {
            commissioner_trace(format_args!(
                "drop UDP_RX for unsupported port {}",
                udp_rx.destination_port
            ));
            return Ok(());
        }
        let inner = match CoapMessage::decode(&udp_rx.payload) {
            Ok(inner) => inner,
            Err(err) => {
                commissioner_trace(format_args!("drop undecodable proxied datagram: {err}"));
                return Ok(());
            }
        };
        let origin = Destination::Mesh {
            address: udp_rx.source_address,
            port: udp_rx.source_port,
        };
        if self.answer_retransmission(&inner, origin).await? {
            return Ok(());
        }
        if self.acknowledge(&inner, true) {
            return Ok(());
        }
        if let Some(pending) = self.take_answered(&inner, true) {
            if inner.ty == meshcop::CoapType::Reset {
                self.complete(
                    pending.completion,
                    Err(Error::InvalidState(COAP_RESET_ERROR)),
                )
                .await;
                return Ok(());
            }
            if inner.ty == meshcop::CoapType::Confirmable {
                let ack = CoapMessage::empty_ack(inner.message_id);
                self.reply(&inner, ack, origin).await?;
            }
            self.complete(pending.completion, Ok(Some(inner))).await;
            return Ok(());
        }
        if self
            .route_unsolicited_proxied(&inner, &udp_rx, origin)
            .await?
        {
            return Ok(());
        }
        commissioner_trace(format_args!(
            "drop unmatched proxied message mid={} token={}",
            inner.message_id,
            hex::encode(&inner.token)
        ));
        Ok(())
    }

    async fn route_direct(&mut self, incoming: CoapMessage) -> Result<()> {
        if self
            .answer_retransmission(&incoming, Destination::BorderAgent)
            .await?
        {
            return Ok(());
        }
        if self.acknowledge(&incoming, false) {
            return Ok(());
        }
        if let Some(pending) = self.take_answered(&incoming, false) {
            if incoming.ty == meshcop::CoapType::Reset {
                self.complete(
                    pending.completion,
                    Err(Error::InvalidState(COAP_RESET_ERROR)),
                )
                .await;
                return Ok(());
            }
            self.ack_if_confirmable(&incoming).await?;
            self.complete(pending.completion, Ok(Some(incoming))).await;
            return Ok(());
        }
        if self.route_unsolicited_message(&incoming).await? {
            self.ack_if_confirmable(&incoming).await?;
            return Ok(());
        }
        commissioner_trace(format_args!(
            "drop unmatched direct message mid={} token={}",
            incoming.message_id,
            hex::encode(&incoming.token)
        ));
        Ok(())
    }

    async fn ack_if_confirmable(&mut self, message: &CoapMessage) -> Result<()> {
        if message.ty == meshcop::CoapType::Confirmable {
            let ack = CoapMessage::empty_ack(message.message_id);
            self.reply(message, ack, Destination::BorderAgent).await?;
        }
        Ok(())
    }

    /// Sends the reply already given to a retransmitted confirmable message
    /// again, returning whether `message` was such a retransmission.
    async fn answer_retransmission(
        &mut self,
        message: &CoapMessage,
        origin: Destination,
    ) -> Result<bool> {
        if message.ty != meshcop::CoapType::Confirmable {
            return Ok(false);
        }
        let Some(reply) = self.answered.reply_to(origin, message.message_id) else {
            return Ok(false);
        };
        commissioner_trace(format_args!(
            "answer retransmitted mid={} again",
            message.message_id
        ));
        self.send_reply(&reply, origin).await?;
        Ok(true)
    }

    /// Sends `reply` to the confirmable `message` from `origin`, remembering
    /// it for the message's retransmissions.
    async fn reply(
        &mut self,
        message: &CoapMessage,
        reply: CoapMessage,
        origin: Destination,
    ) -> Result<()> {
        self.send_reply(&reply, origin).await?;
        self.answered.remember(origin, message.message_id, reply);
        Ok(())
    }

    /// Sends `reply` directly to the border agent, or through the UDP proxy
    /// to a device on the mesh.
    async fn send_reply(&mut self, reply: &CoapMessage, origin: Destination) -> Result<()> {
        let wire_message = self.wire_message(reply, origin)?;
        self.link.send(&wire_message).await
    }

    async fn route_unsolicited_message(&mut self, message: &CoapMessage) -> Result<bool> {
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
            self.shared.invalidate_mesh_local_prefix();
        }
        let peer_addr = self.shared.border_agent.ip().to_string();
        self.publish(notification_to_event(notification, peer_addr));
        Ok(true)
    }

    /// Routes a notification that arrived encapsulated in UDP_RX.
    async fn route_unsolicited_proxied(
        &mut self,
        inner: &CoapMessage,
        udp_rx: &meshcop::UdpRx,
        origin: Destination,
    ) -> Result<bool> {
        let Some(notification) = meshcop::parse_notification(inner)? else {
            return Ok(false);
        };
        if notification == meshcop::MeshcopNotification::DatasetChanged {
            // The dataset change may carry a new mesh-local prefix; refresh it
            // before the next proxied request.
            self.shared.invalidate_mesh_local_prefix();
        }
        self.publish(notification_to_event(
            notification,
            udp_rx.source_address.to_string(),
        ));
        if inner.ty == meshcop::CoapType::Confirmable {
            let changed = CoapMessage::empty_changed_response(inner);
            self.reply(inner, changed, origin).await?;
        }
        Ok(true)
    }
}

fn notification_to_event(
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
