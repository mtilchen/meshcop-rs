//! Joiner relay handling: forwarding payloads to joiners and driving the
//! server-side DTLS session for relayed joiner traffic.

use std::time::Instant;

use zeroize::Zeroizing;

use crate::{
    Result,
    meshcop::{self, CommissionerOperation},
};

use super::super::joiner::{JoinerSession, JoinerSessionEvent, joiner_id_from_iid};
use super::super::types::CommissionerEvent;
use super::{Commissioner, commissioner_trace};

impl Commissioner {
    /// Sends a UDP payload to a proxied joiner.
    pub async fn send_to_joiner(
        &mut self,
        joiner_id: &[u8],
        port: u16,
        payload: &[u8],
    ) -> Result<()> {
        let (message_id, token) = self.next_request_identity();
        let request = meshcop::relay_tx_request(message_id, token, joiner_id, port, 0, payload)?;
        self.execute_no_response(CommissionerOperation::SendToJoiner, request)
            .await
    }

    /// Drives the joiner session for one RLY_RX.ntf payload.
    ///
    /// Joiner-level failures tear down that joiner's session without failing
    /// the commissioner exchange that surfaced the relay message.
    pub(super) async fn handle_relay_rx(
        &mut self,
        joiner_udp_port: u16,
        joiner_router_locator: u16,
        joiner_iid: [u8; 8],
        payload: &[u8],
    ) -> Result<()> {
        let now = Instant::now();
        self.joiner_sessions.retain(|_, session| {
            let expired = session.expired(now);
            if expired {
                commissioner_trace(format_args!(
                    "joiner session {} expired",
                    hex::encode(session.joiner_id())
                ));
            }
            !expired
        });

        let joiner_id = joiner_id_from_iid(&joiner_iid);
        let Some(handler) = self.joiner_handler.as_mut() else {
            return Ok(());
        };
        if let std::collections::hash_map::Entry::Vacant(entry) =
            self.joiner_sessions.entry(joiner_id)
        {
            let Some(pskd) = handler.joiner_pskd(&joiner_id) else {
                commissioner_trace(format_args!(
                    "ignoring disabled joiner {}",
                    hex::encode(joiner_id)
                ));
                return Ok(());
            };
            let pskd = Zeroizing::new(pskd);
            let session = JoinerSession::new(
                joiner_iid,
                joiner_udp_port,
                joiner_router_locator,
                pskd.as_str(),
                now,
                &mut rand_core::OsRng,
            );
            entry.insert(session);
        }

        let mut transmissions: Vec<(Vec<u8>, Option<[u8; 16]>)> = Vec::new();
        let mut queued_events = Vec::new();
        // A joiner-level failure tears down only that joiner's session and is
        // never propagated out of the commissioner exchange that surfaced the
        // relay (see the method doc). `session_failed` defers the removal until
        // the `session`/`handler` borrows end.
        let mut session_failed = false;
        let relay_target;
        {
            // Both were established above; bail out joiner-locally rather than
            // panicking if that invariant is ever broken by a refactor.
            let (Some(handler), Some(session)) = (
                self.joiner_handler.as_mut(),
                self.joiner_sessions.get_mut(&joiner_id),
            ) else {
                return Ok(());
            };
            relay_target = (
                session.joiner_iid(),
                session.joiner_udp_port(),
                session.joiner_router_locator(),
            );
            match session.receive(payload, handler.as_mut(), &mut rand_core::OsRng) {
                Ok(events) => {
                    for event in events {
                        match event {
                            JoinerSessionEvent::Transmit {
                                datagram,
                                include_kek,
                            } => {
                                let kek = if include_kek {
                                    match session.joiner_router_kek() {
                                        Ok(kek) => Some(kek),
                                        Err(err) => {
                                            commissioner_trace(format_args!(
                                                "joiner {} KEK derivation failed: {err}",
                                                hex::encode(joiner_id)
                                            ));
                                            session_failed = true;
                                            break;
                                        }
                                    }
                                } else {
                                    None
                                };
                                transmissions.push((datagram, kek));
                            }
                            JoinerSessionEvent::Connected => {
                                handler.on_joiner_connected(&joiner_id);
                                queued_events
                                    .push(CommissionerEvent::JoinerConnected { joiner_id });
                            }
                            JoinerSessionEvent::Finalized { accepted, info } => {
                                queued_events.push(CommissionerEvent::JoinerFinalized {
                                    joiner_id,
                                    accepted,
                                    info,
                                });
                            }
                        }
                    }
                }
                Err(err) => {
                    commissioner_trace(format_args!(
                        "joiner {} session failed: {err}",
                        hex::encode(joiner_id)
                    ));
                    self.joiner_sessions.remove(&joiner_id);
                    return Ok(());
                }
            }
        }

        // Surface any events that genuinely occurred before a failure.
        for event in queued_events {
            self.queue_event(event);
        }
        if session_failed {
            self.joiner_sessions.remove(&joiner_id);
            return Ok(());
        }
        let (iid, udp_port, router_locator) = relay_target;
        for (datagram, kek) in transmissions {
            let (message_id, token) = self.next_request_identity();
            let relay = meshcop::relay_tx_request_with_kek(
                message_id,
                token,
                &iid,
                udp_port,
                router_locator,
                &datagram,
                kek.as_ref(),
            )?;
            self.send_wire(&relay).await?;
        }
        Ok(())
    }
}
