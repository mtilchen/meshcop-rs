//! Response matching: which received messages may answer, acknowledge, or
//! reset an outstanding exchange.

use super::harness::udp_rx_message;
use super::*;
use crate::meshcop::DEFAULT_MM_PORT;

/// State TLV payload accepting a keep-alive.
const ACCEPT_STATE: [u8; 3] = [TLV_STATE, 1, 1];

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

#[tokio::test(start_paused = true)]
async fn a_proxied_answer_cannot_complete_an_exchange_with_the_border_agent() {
    with_paused_test_deadline(async {
        // A mesh device echoes the keep-alive's token and message ID in a
        // rejection, which arrives through the proxy before the border agent's
        // own answer.
        let script = ScriptedMeshcopTransport::new([
            petition_exchange(),
            exchange(
                CommissionerOperation::KeepAlive,
                [
                    ScriptedResponse::proxied(unicast_destination(), ScriptedResponse::reject()),
                    ScriptedResponse::accept(),
                ],
            ),
        ]);
        let (commissioner, _events) = scripted_commissioner(script, []).await;
        commissioner.petition().await.unwrap();

        assert_eq!(commissioner.keep_alive().await.unwrap(), ResultCode::Accept);
        assert!(commissioner.status().is_active());
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_direct_answer_cannot_complete_a_proxied_exchange() {
    with_paused_test_deadline(async {
        let script = ScriptedMeshcopTransport::new([
            petition_exchange(),
            exchange(CommissionerOperation::DiagnosticGetUnicast, []),
        ]);
        let transport = script.clone();
        let (commissioner, _events) = scripted_commissioner(script, []).await;
        commissioner.petition().await.unwrap();
        let diagnostics = {
            let commissioner = commissioner.clone();
            tokio::spawn(async move {
                commissioner
                    .get_diagnostics(unicast_destination(), 0b1)
                    .await
            })
        };
        wait_until(|| transport.observed_requests().len() == 2).await;
        let request = sent_request(&transport, 1);

        // MAC Address TLVs: the direct copy must be ignored.
        transport.deliver(answer(&request, CoapCode::CONTENT, vec![1, 2, 0xde, 0xad]));
        transport.deliver(from_device(
            unicast_destination(),
            &answer(&request, CoapCode::CONTENT, vec![1, 2, 0x80, 0x00]),
        ));
        let data = diagnostics.await.unwrap().unwrap();
        assert_eq!(data.mac_addr, Some(0x8000));
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn only_an_empty_ack_stops_retransmission() {
    with_paused_test_deadline(async {
        let script = ScriptedMeshcopTransport::new([
            petition_exchange(),
            exchange(CommissionerOperation::GetActiveDataset, []),
        ]);
        let transport = script.clone();
        let (commissioner, _events) = scripted_commissioner(script, []).await;
        commissioner.petition().await.unwrap();
        let read = {
            let commissioner = commissioner.clone();
            tokio::spawn(async move {
                commissioner
                    .get_active_dataset(DatasetFlags::NETWORK_NAME)
                    .await
            })
        };
        wait_until(|| transport.observed_requests().len() == 2).await;
        let request = sent_request(&transport, 1);
        let retransmissions = || {
            transport
                .sent_messages()
                .iter()
                .filter(|message| message.message_id == request.message_id)
                .count()
        };

        // An ACK that carries a token is not an empty ACK: the request is
        // still retransmitted after its 2–3 second timeout.
        let mut tokened_ack = CoapMessage::empty_ack(request.message_id);
        tokened_ack.token = request.token.clone();
        transport.deliver(tokened_ack);
        tokio::time::sleep(Duration::from_secs(4)).await;
        assert_eq!(retransmissions(), 1);

        // A real empty ACK stops the retransmission due by 9 seconds.
        transport.deliver(CoapMessage::empty_ack(request.message_id));
        tokio::time::sleep(Duration::from_secs(7)).await;
        assert_eq!(retransmissions(), 1);

        transport.deliver(answer(
            &request,
            CoapCode::CONTENT,
            dataset_with_name("separate").to_bytes().unwrap(),
        ));
        let dataset = read.await.unwrap().unwrap();
        assert_eq!(dataset.network_name().unwrap(), Some("separate"));
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_reserved_code_class_does_not_answer_a_request() {
    with_paused_test_deadline(async {
        const RESERVED_CLASS_3: CoapCode = CoapCode(3 << 5);
        let script = ScriptedMeshcopTransport::new([
            petition_exchange(),
            exchange(CommissionerOperation::GetActiveDataset, []),
        ]);
        let transport = script.clone();
        let (commissioner, _events) = scripted_commissioner(script, []).await;
        commissioner.petition().await.unwrap();
        let read = {
            let commissioner = commissioner.clone();
            tokio::spawn(async move {
                commissioner
                    .get_active_dataset(DatasetFlags::NETWORK_NAME)
                    .await
            })
        };
        wait_until(|| transport.observed_requests().len() == 2).await;
        let request = sent_request(&transport, 1);

        transport.deliver(answer(
            &request,
            RESERVED_CLASS_3,
            dataset_with_name("reserved").to_bytes().unwrap(),
        ));
        transport.deliver(answer(
            &request,
            CoapCode::CONTENT,
            dataset_with_name("content").to_bytes().unwrap(),
        ));
        let dataset = read.await.unwrap().unwrap();
        assert_eq!(dataset.network_name().unwrap(), Some("content"));
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn concurrent_exchanges_are_matched_by_unpredictable_tokens() {
    with_paused_test_deadline(async {
        let script = ScriptedMeshcopTransport::new([
            petition_exchange(),
            exchange(CommissionerOperation::KeepAlive, []),
            exchange(CommissionerOperation::GetActiveDataset, []),
        ]);
        let transport = script.clone();
        let (commissioner, _events) = scripted_commissioner(script, []).await;
        commissioner.petition().await.unwrap();
        let keep_alive = {
            let commissioner = commissioner.clone();
            tokio::spawn(async move { commissioner.keep_alive().await })
        };
        wait_until(|| transport.observed_requests().len() == 2).await;
        let read = {
            let commissioner = commissioner.clone();
            tokio::spawn(async move {
                commissioner
                    .get_active_dataset(DatasetFlags::NETWORK_NAME)
                    .await
            })
        };
        wait_until(|| transport.observed_requests().len() == 3).await;
        let keep_alive_request = sent_request(&transport, 1);
        let read_request = sent_request(&transport, 2);
        for request in [&keep_alive_request, &read_request] {
            assert_eq!(request.token.len(), 4);
            assert_ne!(request.token, request.message_id.to_be_bytes());
        }
        assert_ne!(keep_alive_request.token, read_request.token);

        // Answered in the opposite order to the requests.
        transport.deliver(answer(
            &read_request,
            CoapCode::CONTENT,
            dataset_with_name("read").to_bytes().unwrap(),
        ));
        transport.deliver(answer(
            &keep_alive_request,
            CoapCode::CHANGED,
            ACCEPT_STATE.to_vec(),
        ));
        let dataset = read.await.unwrap().unwrap();
        assert_eq!(dataset.network_name().unwrap(), Some("read"));
        assert_eq!(keep_alive.await.unwrap().unwrap(), ResultCode::Accept);
    })
    .await
}
