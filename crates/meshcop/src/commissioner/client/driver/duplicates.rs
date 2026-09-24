//! Confirmable messages the driver has already answered, so a retransmission
//! gets the same reply again instead of being handled twice (RFC 7252 §4.5).
//!
//! A sender retransmits a confirmable message until it sees an
//! acknowledgement. When the driver's acknowledgement is lost, the copy that
//! follows must be acknowledged again, but must not complete a second
//! exchange or publish a second event.

use std::collections::VecDeque;
use std::time::Duration;

use tokio::time::Instant;

use crate::meshcop::CoapMessage;

use super::super::super::types::Destination;

/// How long a sender may keep retransmitting a confirmable message:
/// RFC 7252's EXCHANGE_LIFETIME with the default transmission parameters.
const EXCHANGE_LIFETIME: Duration = Duration::from_secs(247);

/// The most answered messages remembered at once. Devices on the mesh choose
/// how many confirmable messages they send, so the record is bounded; the
/// oldest entry is forgotten first.
const MAX_REMEMBERED: usize = 64;

struct Answered {
    origin: Destination,
    message_id: u16,
    reply: CoapMessage,
    at: Instant,
}

/// Recently answered confirmable messages, oldest first.
#[derive(Default)]
pub(super) struct AnsweredMessages {
    entries: VecDeque<Answered>,
}

impl AnsweredMessages {
    /// Returns the reply already sent to the message `message_id` from
    /// `origin`, if it was answered within the exchange lifetime.
    pub(super) fn reply_to(&mut self, origin: Destination, message_id: u16) -> Option<CoapMessage> {
        self.forget_expired();
        self.entries
            .iter()
            .find(|entry| entry.origin == origin && entry.message_id == message_id)
            .map(|entry| entry.reply.clone())
    }

    /// Records that the message `message_id` from `origin` was answered with
    /// `reply`.
    pub(super) fn remember(&mut self, origin: Destination, message_id: u16, reply: CoapMessage) {
        self.forget_expired();
        if self.entries.len() == MAX_REMEMBERED {
            self.entries.pop_front();
        }
        self.entries.push_back(Answered {
            origin,
            message_id,
            reply,
            at: Instant::now(),
        });
    }

    /// Forgets the border agent's messages. A reopened DTLS session is a new
    /// association, in which the border agent may reuse the last one's
    /// message IDs.
    pub(super) fn forget_border_agent(&mut self) {
        self.entries
            .retain(|entry| entry.origin != Destination::BorderAgent);
    }

    fn forget_expired(&mut self) {
        while self
            .entries
            .front()
            .is_some_and(|entry| entry.at.elapsed() >= EXCHANGE_LIFETIME)
        {
            self.entries.pop_front();
        }
    }
}
