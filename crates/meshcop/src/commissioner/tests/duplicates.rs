//! Retransmitted confirmable messages: each copy is acknowledged, but only
//! the first is handled.

use super::harness::{ObservedRequest, udp_rx_message};
use super::*;
use crate::meshcop::DEFAULT_MM_PORT;

/// RFC 7252's EXCHANGE_LIFETIME: how long a sender may retransmit.
const EXCHANGE_LIFETIME: Duration = Duration::from_secs(247);
/// How many answered messages the driver remembers.
const MAX_REMEMBERED: u16 = 64;

fn other_device() -> Ipv6Addr {
    "fd00:db8::beef".parse().unwrap()
}

/// `message` wrapped in UDP_RX, as sent by the Thread device `source`.
fn from_device(source: Ipv6Addr, message: &CoapMessage) -> CoapMessage {
    udp_rx_message(
        source,
        DEFAULT_MM_PORT,
        DEFAULT_MM_PORT,
        &message.encode().unwrap(),
    )
    .unwrap()
}

/// The replies proxied back to devices, unwrapped from UDP_TX, with the
/// device each went to.
fn proxied_replies(transport: &ScriptedMeshcopTransport) -> Vec<(Option<Ipv6Addr>, CoapMessage)> {
    transport
        .sent_messages()
        .into_iter()
        .map(|message| ObservedRequest {
            operation: CommissionerOperation::GetActiveDataset,
            message,
        })
        .filter_map(|sent| Some((sent.proxy_destination(), sent.inner_message()?)))
        .collect()
}

async fn connected() -> (Commissioner, Events, ScriptedMeshcopTransport) {
    let script = ScriptedMeshcopTransport::new([]);
    let transport = script.clone();
    let (commissioner, events) = scripted_commissioner(script, []).await;
    (commissioner, events, transport)
}

#[tokio::test]
async fn a_retransmitted_response_is_acknowledged_again() {
    with_test_deadline(async {
        const RESPONSE_ID: u16 = 0x5001;
        let script =
            ScriptedMeshcopTransport::new([exchange(CommissionerOperation::GetActiveDataset, [])]);
        let transport = script.clone();
        let (commissioner, _events) = scripted_commissioner(script, []).await;
        let read = {
            let commissioner = commissioner.clone();
            tokio::spawn(async move {
                commissioner
                    .get_active_dataset(DatasetFlags::NETWORK_NAME)
                    .await
            })
        };
        wait_until(|| transport.observed_requests().len() == 1).await;
        let request = sent_request(&transport, 0);
        let separate_response = CoapMessage {
            ty: CoapType::Confirmable,
            code: CoapCode::CONTENT,
            message_id: RESPONSE_ID,
            token: request.token.clone(),
            options: Vec::new(),
            payload: dataset_with_name("separate").to_bytes().unwrap(),
        };

        transport.deliver(separate_response.clone());
        let dataset = read.await.unwrap().unwrap();
        assert_eq!(dataset.network_name().unwrap(), Some("separate"));
        // The first ACK was lost, so the border agent sends the response again.
        transport.deliver(separate_response);
        wait_until(|| transport.acked_confirmable_responses().len() == 2).await;
        assert_eq!(
            transport.acked_confirmable_responses(),
            [RESPONSE_ID, RESPONSE_ID]
        );
    })
    .await
}

#[tokio::test]
async fn a_retransmitted_notification_is_acknowledged_again_but_published_once() {
    with_test_deadline(async {
        let (_commissioner, mut events, transport) = connected().await;
        let notification = dataset_changed_notification(0x6001, true);

        transport.deliver(notification.clone());
        transport.deliver(notification);
        assert_eq!(
            next_event(&mut events).await,
            Some(CommissionerEvent::DatasetChanged)
        );
        wait_until(|| transport.acked_confirmable_responses().len() == 2).await;
        assert_no_event(&mut events).await;
    })
    .await
}

#[tokio::test]
async fn a_retransmitted_device_report_is_answered_again_but_published_once() {
    with_test_deadline(async {
        let (_commissioner, mut events, transport) = connected().await;
        let report = dataset_changed_notification(0x6002, true);

        transport.deliver(from_device(unicast_destination(), &report));
        transport.deliver(from_device(unicast_destination(), &report));
        assert_eq!(
            next_event(&mut events).await,
            Some(CommissionerEvent::DatasetChanged)
        );
        wait_until(|| proxied_replies(&transport).len() == 2).await;
        let changed = CoapMessage::empty_changed_response(&report);
        assert_eq!(
            proxied_replies(&transport),
            [
                (Some(unicast_destination()), changed.clone()),
                (Some(unicast_destination()), changed),
            ]
        );
        assert_no_event(&mut events).await;

        // Another device's message is a different message, whatever its ID.
        transport.deliver(from_device(other_device(), &report));
        assert_eq!(
            next_event(&mut events).await,
            Some(CommissionerEvent::DatasetChanged)
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_message_id_is_new_again_after_the_exchange_lifetime() {
    with_paused_test_deadline(async {
        const JUST_BEFORE: Duration = Duration::from_secs(1);
        let (_commissioner, mut events, transport) = connected().await;
        let notification = dataset_changed_notification(0x6003, true);
        transport.deliver(notification.clone());
        assert_eq!(
            next_event(&mut events).await,
            Some(CommissionerEvent::DatasetChanged)
        );

        tokio::time::sleep(EXCHANGE_LIFETIME - JUST_BEFORE).await;
        transport.deliver(notification.clone());
        wait_until(|| transport.acked_confirmable_responses().len() == 2).await;
        // Waiting for no event moves the paused clock on by its window.
        let started = tokio::time::Instant::now();
        assert_no_event(&mut events).await;
        tokio::time::sleep(JUST_BEFORE - started.elapsed()).await;

        transport.deliver(notification);
        assert_eq!(
            next_event(&mut events).await,
            Some(CommissionerEvent::DatasetChanged)
        );
    })
    .await
}

#[tokio::test]
async fn only_the_most_recent_messages_are_remembered() {
    with_test_deadline(async {
        let (_commissioner, mut events, transport) = connected().await;
        for message_id in 1..=MAX_REMEMBERED + 1 {
            transport.deliver(dataset_changed_notification(message_id, true));
            assert_eq!(
                next_event(&mut events).await,
                Some(CommissionerEvent::DatasetChanged)
            );
        }

        // The second message is still remembered; the first was forgotten.
        transport.deliver(dataset_changed_notification(2, true));
        transport.deliver(dataset_changed_notification(1, true));
        assert_eq!(
            next_event(&mut events).await,
            Some(CommissionerEvent::DatasetChanged)
        );
        wait_until(|| {
            transport.acked_confirmable_responses().len() == usize::from(MAX_REMEMBERED) + 3
        })
        .await;
        assert_no_event(&mut events).await;
    })
    .await
}

#[tokio::test]
async fn a_reopened_session_forgets_the_border_agents_message_ids() {
    with_test_deadline(async {
        let notification = dataset_changed_notification(0x6004, true);
        let script = ScriptedMeshcopTransport::new([
            exchange(
                CommissionerOperation::GetActiveDataset,
                [
                    ScriptedResponse::content(dataset_with_name("before").to_bytes().unwrap()),
                    ScriptedResponse::Raw(notification.clone()),
                    ScriptedResponse::PeerClosed,
                ],
            ),
            active_get("after"),
        ]);
        let transport = script.clone();
        let (commissioner, mut events) = scripted_commissioner(script, []).await;
        commissioner
            .get_active_dataset(DatasetFlags::NETWORK_NAME)
            .await
            .unwrap();
        assert_eq!(
            next_event(&mut events).await,
            Some(CommissionerEvent::DatasetChanged)
        );
        wait_until(|| commissioner.status() == SessionStatus::Idle).await;

        commissioner
            .get_active_dataset(DatasetFlags::NETWORK_NAME)
            .await
            .unwrap();
        transport.deliver(notification);
        assert_eq!(
            next_event(&mut events).await,
            Some(CommissionerEvent::DatasetChanged)
        );
    })
    .await
}
