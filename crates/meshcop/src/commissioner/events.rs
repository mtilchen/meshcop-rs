//! Commissioner event subscription.

use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll, ready},
};

use futures_core::Stream;
use tokio::sync::broadcast::{self, error::RecvError};

use super::types::CommissionerEvent;

type Receiver = broadcast::Receiver<CommissionerEvent>;
type PendingReceive =
    Pin<Box<dyn Future<Output = (Result<CommissionerEvent, RecvError>, Receiver)> + Send>>;

/// A subscription to a commissioner session's events.
///
/// Returned by [`super::Commissioner::connect`] and
/// [`super::Commissioner::subscribe`]. Read it with [`Events::next`] or as a
/// [`Stream`]. The stream ends once the session has ended and every event sent
/// before that has been delivered.
///
/// A subscriber that falls more than
/// [`super::CommissionerConfig::event_capacity`] events behind receives
/// [`CommissionerEvent::Lagged`] and then continues with the oldest event still
/// buffered. The session never waits for a slow subscriber.
pub struct Events {
    receiver: Option<Receiver>,
    pending: Option<PendingReceive>,
}

impl Events {
    pub(crate) fn new(receiver: Receiver) -> Self {
        Self {
            receiver: Some(receiver),
            pending: None,
        }
    }

    /// Waits for the next event, returning `None` once the session has ended
    /// and every earlier event has been delivered.
    pub async fn next(&mut self) -> Option<CommissionerEvent> {
        core::future::poll_fn(|cx| Pin::new(&mut *self).poll_next(cx)).await
    }
}

impl Stream for Events {
    type Item = CommissionerEvent;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.pending.is_none() {
            let Some(mut receiver) = this.receiver.take() else {
                return Poll::Ready(None);
            };
            this.pending = Some(Box::pin(async move {
                let result = receiver.recv().await;
                (result, receiver)
            }));
        }
        let Some(pending) = this.pending.as_mut() else {
            return Poll::Ready(None);
        };
        let (result, receiver) = ready!(pending.as_mut().poll(cx));
        this.pending = None;
        match result {
            Ok(event) => {
                this.receiver = Some(receiver);
                Poll::Ready(Some(event))
            }
            Err(RecvError::Lagged(missed)) => {
                this.receiver = Some(receiver);
                Poll::Ready(Some(CommissionerEvent::Lagged { missed }))
            }
            Err(RecvError::Closed) => Poll::Ready(None),
        }
    }
}

impl core::fmt::Debug for Events {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Events")
            .field(
                "ended",
                &(self.receiver.is_none() && self.pending.is_none()),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn delivers_events_in_order_then_ends_when_the_sender_is_gone() {
        let (sender, receiver) = broadcast::channel(4);
        let mut events = Events::new(receiver);
        sender.send(CommissionerEvent::DatasetChanged).unwrap();
        sender
            .send(CommissionerEvent::Lagged { missed: 7 })
            .unwrap();
        drop(sender);

        assert_eq!(events.next().await, Some(CommissionerEvent::DatasetChanged));
        assert_eq!(
            events.next().await,
            Some(CommissionerEvent::Lagged { missed: 7 })
        );
        assert_eq!(events.next().await, None);
        assert_eq!(events.next().await, None);
    }

    #[tokio::test]
    async fn debug_output_reports_whether_the_stream_has_ended() {
        let (sender, receiver) = broadcast::channel(1);
        let mut events = Events::new(receiver);
        assert_eq!(format!("{events:?}"), "Events { ended: false }");

        sender.send(CommissionerEvent::DatasetChanged).unwrap();
        events.next().await;
        assert_eq!(format!("{events:?}"), "Events { ended: false }");

        drop(sender);
        assert_eq!(events.next().await, None);
        assert_eq!(format!("{events:?}"), "Events { ended: true }");
    }

    #[tokio::test]
    async fn reports_missed_events_when_a_subscriber_falls_behind() {
        let (sender, receiver) = broadcast::channel(2);
        let mut events = Events::new(receiver);
        for _ in 0..3 {
            sender.send(CommissionerEvent::DatasetChanged).unwrap();
        }

        assert_eq!(
            events.next().await,
            Some(CommissionerEvent::Lagged { missed: 1 })
        );
        assert_eq!(events.next().await, Some(CommissionerEvent::DatasetChanged));
        assert_eq!(events.next().await, Some(CommissionerEvent::DatasetChanged));
    }
}
