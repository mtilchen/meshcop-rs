//! Routing of messages received from the border agent: responses to
//! outstanding exchanges, UDP_RX decapsulation, and unsolicited
//! notifications.

use crate::{
    Result,
    error::Error,
    meshcop::{self, CoapMessage},
};

use super::super::super::types::CommissionerEvent;
use super::super::commissioner_trace;
use super::Driver;
use super::exchange::COAP_RESET_ERROR;

impl Driver {
    /// Routes one received message.
    ///
    /// A response completes the exchange it answers, a Reset fails it, and an
    /// empty ACK stops its retransmission. Unsolicited notifications become
    /// events. Malformed and unmatched messages are dropped so delayed
    /// duplicates and peer-controlled UDP_RX contents cannot disturb the
    /// session.
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
                self.send_proxied(CoapMessage::empty_ack(inner.message_id), &udp_rx)
                    .await?;
            }
            self.complete(pending.completion, Ok(Some(inner))).await;
            return Ok(());
        }
        if self.route_unsolicited_proxied(&inner, &udp_rx).await? {
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
            self.link
                .send(&CoapMessage::empty_ack(message.message_id))
                .await?;
        }
        Ok(())
    }

    /// Sends `message` back through the UDP proxy to the UDP_RX source.
    async fn send_proxied(&mut self, message: CoapMessage, udp_rx: &meshcop::UdpRx) -> Result<()> {
        let wire_message = self.wire_message(
            &message,
            super::super::super::types::Destination::Mesh {
                address: udp_rx.source_address,
                port: udp_rx.source_port,
            },
        )?;
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
            self.send_proxied(CoapMessage::empty_changed_response(inner), udp_rx)
                .await?;
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
