use super::*;

#[tokio::test]
async fn steering_helpers_update_the_commissioner_dataset() {
    let joiner_id = [0x1au8, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81];
    let mut expected_steering = vec![0u8; 16];
    crate::crypto::add_joiner_to_steering_data(&mut expected_steering, &joiner_id);

    let existing = {
        let mut dataset = Dataset::default();
        dataset.set_raw(TLV_STEERING_DATA, vec![0x00]);
        dataset.to_bytes().unwrap()
    };
    let script = ScriptedMeshcopTransport::new([
        exchange(
            CommissionerOperation::Petition,
            [ScriptedResponse::petition_accept(0xcafe)],
        ),
        exchange(
            CommissionerOperation::GetCommissionerDataset,
            [ScriptedResponse::content(existing)],
        ),
        exchange(
            CommissionerOperation::SetCommissionerDataset,
            [ScriptedResponse::accept()],
        ),
        exchange(
            CommissionerOperation::SetCommissionerDataset,
            [ScriptedResponse::accept()],
        ),
        exchange(
            CommissionerOperation::SetCommissionerDataset,
            [ScriptedResponse::accept()],
        ),
    ]);
    let mut commissioner = scripted_commissioner(script, []).await;
    commissioner.petition().await.unwrap();

    commissioner.enable_joiner(&joiner_id).await.unwrap();
    commissioner.enable_all_joiners(true).await.unwrap();
    commissioner.enable_all_joiners(false).await.unwrap();

    let harness = commissioner.scripted_transport().unwrap();
    let requests = harness.observed_requests();
    let steering =
        |idx: usize| tlv_value(&requests[idx].inner_message().unwrap(), TLV_STEERING_DATA).unwrap();
    // enable_joiner: the 1-byte closed filter is replaced by a fresh 16-byte
    // Bloom filter containing the joiner.
    assert_eq!(steering(2), expected_steering);
    // enable_all_joiners: wildcard open, then closed.
    assert_eq!(steering(3), vec![0xff]);
    assert_eq!(steering(4), vec![0x00]);
}

#[test]
fn joiner_id_round_trips_the_universal_local_bit() {
    use crate::commissioner::joiner_id_from_iid;

    // IID with the bit clear: the joiner ID sets it.
    assert_eq!(
        joiner_id_from_iid(&[0x11, 0, 0, 0, 0, 0, 0, 0]),
        [0x13, 0, 0, 0, 0, 0, 0, 0]
    );
    // IID with the bit set: the joiner ID clears it (XOR, not OR).
    assert_eq!(
        joiner_id_from_iid(&[0x13, 0, 0, 0, 0, 0, 0, 0]),
        [0x11, 0, 0, 0, 0, 0, 0, 0]
    );
}

#[test]
fn static_joiner_handler_reenable_replaces_the_pskd() {
    let mut handler = StaticJoinerHandler::new();
    let first = [1u8; 8];
    let second = [2u8; 8];
    handler.enable_joiner_id(first, "AAAAAA");
    handler.enable_joiner_id(second, "BBBBBB");
    handler.enable_joiner_id(first, "CCCCCC");
    assert_eq!(handler.joiner_pskd(&first).as_deref(), Some("CCCCCC"));
    assert_eq!(handler.joiner_pskd(&second).as_deref(), Some("BBBBBB"));
}

#[test]
fn static_joiner_handler_debug_redacts_every_pskd() {
    let joiner_id = [0x42; 8];
    let mut handler = StaticJoinerHandler::new();
    handler.enable_all("wildcard-secret");
    handler.enable_joiner_id(joiner_id, "joiner-secret");

    let debug = format!("{handler:?}");
    assert!(debug.contains("<redacted>"));
    assert!(debug.contains("enabled_joiner_count: 1"));
    assert!(!debug.contains("wildcard-secret"));
    assert!(!debug.contains("joiner-secret"));
    assert!(!debug.contains(&hex::encode(joiner_id)));
}

#[test]
fn joiner_handler_default_callbacks_accept_and_ignore() {
    #[derive(Debug)]
    struct DefaultsOnly;
    impl JoinerHandler for DefaultsOnly {
        fn joiner_pskd(&mut self, _joiner_id: &[u8; 8]) -> Option<String> {
            None
        }
    }

    let mut handler = DefaultsOnly;
    // The default connected callback is a no-op and the default finalize
    // decision accepts the joiner.
    handler.on_joiner_connected(&[0u8; 8]);
    let info = JoinerFinalizeInfo {
        vendor_name: "n".into(),
        vendor_model: "m".into(),
        vendor_sw_version: "v".into(),
        vendor_stack_version: vec![1],
        provisioning_url: None,
        vendor_data: None,
    };
    assert!(handler.on_joiner_finalize(&[0u8; 8], &info));
}

#[tokio::test]
async fn dataset_set_operations_validate_mandatory_tlvs() {
    let script = ScriptedMeshcopTransport::new([exchange(
        CommissionerOperation::Petition,
        [ScriptedResponse::petition_accept(0xcafe)],
    )]);
    let mut commissioner = scripted_commissioner(script, []).await;
    commissioner.petition().await.unwrap();

    // Active set without an Active Timestamp.
    assert!(matches!(
        commissioner
            .set_active_dataset(&dataset_with_name("incomplete"))
            .await
            .unwrap_err(),
        Error::Dataset(message) if message.contains("Active Timestamp")
    ));
    // Pending set missing the Delay Timer.
    let mut no_delay = active_dataset_with_name("incomplete");
    no_delay.set_raw(DATASET_TLV_PENDING_TIMESTAMP, 1u64.to_be_bytes());
    assert!(matches!(
        commissioner.set_pending_dataset(&no_delay).await.unwrap_err(),
        Error::Dataset(message) if message.contains("Delay Timer")
    ));
    // Secure pending set missing the Pending Timestamp.
    let mut no_pending = active_dataset_with_name("incomplete");
    no_pending.set_raw(crate::dataset::TLV_DELAY_TIMER, 30_000u32.to_be_bytes());
    assert!(matches!(
        commissioner
            .set_secure_pending_dataset(120, &no_pending)
            .await
            .unwrap_err(),
        Error::Dataset(message) if message.contains("Pending Timestamp")
    ));
    // Nothing was sent for any of the rejected datasets.
    assert_eq!(
        commissioner
            .scripted_transport()
            .unwrap()
            .observed_requests()
            .len(),
        1
    );
}

#[tokio::test]
async fn commissioner_runs_petition_over_a_real_dtls_session() {
    use meshcop_dtls::{ContentType, DtlsRecord, test_support};

    let pskc = [0x42u8; 16];
    let border = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let border_addr = border.local_addr().unwrap();

    // Border-agent side: complete the DTLS handshake, then answer the
    // petition request with an accepting COMM_PET.rsp over the session.
    let agent = tokio::spawn(async move {
        // Learn the commissioner's ephemeral address, then connect so the
        // loopback server can use send()/recv() like the dtls tests.
        let mut peek = [0u8; 1];
        let (_, peer) = border.peek_from(&mut peek).await.unwrap();
        border.connect(peer).await.unwrap();
        let keys =
            test_support::loopback_dtls_server(&border, &pskc, test_support::LoopbackEnd::Complete)
                .await
                .unwrap()
                .unwrap();
        let mut buf = [0u8; 4096];
        loop {
            let len =
                tokio::time::timeout(std::time::Duration::from_secs(2), border.recv(&mut buf))
                    .await
                    .unwrap()
                    .unwrap();
            for record in DtlsRecord::parse_datagram(&buf[..len]).unwrap() {
                if record.header.epoch != 1
                    || record.header.content_type != ContentType::ApplicationData
                {
                    continue;
                }
                let plaintext = meshcop_dtls::open_aes_128_ccm_8_record(
                    &record,
                    meshcop_dtls::RecordProtectionKey::new(keys.key_block.client_write_key),
                    &keys.key_block.client_write_iv,
                )
                .unwrap();
                let request = CoapMessage::decode(&plaintext).unwrap();
                let mut payload = vec![TLV_STATE, 1, 0x01];
                payload.extend_from_slice(&[TLV_COMMISSIONER_SESSION_ID, 2, 0x12, 0x34]);
                let response = CoapMessage {
                    ty: CoapType::Acknowledgement,
                    code: CoapCode::CHANGED,
                    message_id: request.message_id,
                    token: request.token.clone(),
                    options: Vec::new(),
                    payload,
                };
                let protected = meshcop_dtls::protect_aes_128_ccm_8_record(
                    ContentType::ApplicationData,
                    1,
                    1,
                    meshcop_dtls::RecordProtectionKey::new(keys.key_block.server_write_key),
                    &keys.key_block.server_write_iv,
                    &response.encode().unwrap(),
                )
                .unwrap();
                border.send(&protected.encode().unwrap()).await.unwrap();
                return;
            }
        }
    });

    let mut commissioner =
        Commissioner::connect(CommissionerConfig::pskc("meshcop", pskc), border_addr)
            .await
            .unwrap();
    let petition = commissioner.petition().await.unwrap();
    assert_eq!(petition.session_id, 0x1234);
    assert_eq!(commissioner.state(), CommissionerState::Active);
    agent.await.expect("agent task panicked");
}

#[tokio::test]
async fn confirmable_request_is_retransmitted_without_changing_its_coap_identity() {
    use meshcop_dtls::DtlsServer;

    let pskc = [0x42u8; 16];
    let server = DtlsServer::bind("127.0.0.1:0").await.unwrap();
    let border_addr = server.local_addr();
    let server_task = async move {
        let mut session = server.accept(&pskc, Duration::from_secs(10)).await.unwrap();
        let first = session
            .recv_application_data(Duration::from_secs(10))
            .await
            .unwrap();
        let repeated = session
            .recv_application_data(Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(repeated, first);

        let request = CoapMessage::decode(&repeated).unwrap();
        let response =
            petition_accept_response(CoapType::Acknowledgement, request.message_id, request.token);
        session
            .send_application_data(&response.encode().unwrap())
            .await
            .unwrap();
    };

    let mut commissioner =
        Commissioner::connect(CommissionerConfig::pskc("meshcop", pskc), border_addr)
            .await
            .unwrap();
    let ((), petition) = tokio::join!(server_task, commissioner.petition());
    assert_eq!(petition.unwrap().session_id, 0x1234);
}

#[tokio::test]
async fn empty_ack_stops_retransmission_while_a_separate_response_is_pending() {
    use meshcop_dtls::{DtlsServer, driver::DriverError};

    let pskc = [0x42u8; 16];
    let server = DtlsServer::bind("127.0.0.1:0").await.unwrap();
    let border_addr = server.local_addr();
    let server_task = async move {
        let mut session = server.accept(&pskc, Duration::from_secs(10)).await.unwrap();
        let request_wire = session
            .recv_application_data(Duration::from_secs(10))
            .await
            .unwrap();
        let request = CoapMessage::decode(&request_wire).unwrap();
        let ack = CoapMessage::empty_ack(request.message_id);
        session
            .send_application_data(&ack.encode().unwrap())
            .await
            .unwrap();

        let unexpected = session.recv_application_data(Duration::from_secs(4)).await;
        assert!(
            matches!(unexpected, Err(DriverError::Timeout)),
            "an acknowledged CoAP request must not be retransmitted: {unexpected:?}"
        );

        let response = petition_accept_response(
            CoapType::NonConfirmable,
            request.message_id.wrapping_add(1),
            request.token,
        );
        session
            .send_application_data(&response.encode().unwrap())
            .await
            .unwrap();
    };

    let mut commissioner =
        Commissioner::connect(CommissionerConfig::pskc("meshcop", pskc), border_addr)
            .await
            .unwrap();
    let ((), petition) = tokio::join!(server_task, commissioner.petition());
    assert_eq!(petition.unwrap().session_id, 0x1234);
}

fn petition_accept_response(ty: CoapType, message_id: u16, token: Vec<u8>) -> CoapMessage {
    let mut payload = vec![TLV_STATE, 1, 0x01];
    payload.extend_from_slice(&[TLV_COMMISSIONER_SESSION_ID, 2, 0x12, 0x34]);
    CoapMessage {
        ty,
        code: CoapCode::CHANGED,
        message_id,
        token,
        options: Vec::new(),
        payload,
    }
}

#[tokio::test]
async fn multicast_commands_skip_the_response_wait() {
    // A multicast announce-begin is non-confirmable: the client must not wait
    // for a response, so a script with no response still succeeds.
    let script = ScriptedMeshcopTransport::new([
        exchange(
            CommissionerOperation::Petition,
            [ScriptedResponse::petition_accept(0xcafe)],
        ),
        exchange(CommissionerOperation::AnnounceBegin, []),
    ]);
    let mut commissioner = scripted_commissioner(script, []).await;
    commissioner.petition().await.unwrap();
    commissioner
        .announce_begin(0x07fff800, 1, 100, multicast_destination())
        .await
        .unwrap();

    let request = &commissioner
        .scripted_transport()
        .unwrap()
        .observed_requests()[1];
    assert_eq!(request.message.ty, CoapType::NonConfirmable);
    assert_eq!(logical_message(request).ty, CoapType::NonConfirmable);
}

#[tokio::test]
async fn clear_joiner_handler_drops_sessions_and_restores_raw_events() {
    let mut rng = rand_core::OsRng;
    let joiner = meshcop_dtls::ThreadDtlsHandshake::new(b"J01NME", &mut rng);
    let client_hello = joiner
        .client_hello_state()
        .unwrap()
        .next_client_hello_record()
        .unwrap()
        .encode()
        .unwrap();
    let joiner_iid = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

    let script = ScriptedMeshcopTransport::new([
        exchange(
            CommissionerOperation::Petition,
            [ScriptedResponse::petition_accept(0x1234)],
        ),
        exchange(
            CommissionerOperation::GetActiveDataset,
            [
                ScriptedResponse::Raw(joiner_sessions::relay_rx_message(
                    &joiner_iid,
                    &client_hello,
                )),
                ScriptedResponse::content(dataset_with_name("after").to_bytes().unwrap()),
            ],
        ),
    ]);
    let mut commissioner = scripted_commissioner(script, []).await;
    let mut handler = StaticJoinerHandler::new();
    handler.enable_all("J01NME");
    commissioner.set_joiner_handler(handler);
    // Clearing the handler before the relay arrives means the raw payload is
    // surfaced as a JoinerMessage event instead of being consumed.
    commissioner.clear_joiner_handler();
    commissioner.petition().await.unwrap();
    commissioner
        .get_active_dataset(DatasetFlags::NETWORK_NAME)
        .await
        .unwrap();
    assert_eq!(
        commissioner.next_event().await.unwrap(),
        Some(CommissionerEvent::JoinerMessage {
            joiner_id: joiner_iid.to_vec(),
            port: 1000,
            payload: client_hello,
        })
    );
    assert!(
        commissioner
            .scripted_transport()
            .unwrap()
            .sent_messages()
            .is_empty()
    );
}

#[tokio::test]
async fn proxied_commands_pick_confirmability_from_the_destination() {
    // Unicast destinations are confirmable (the client waits for a response);
    // multicast destinations are non-confirmable (fire-and-forget).
    let script = ScriptedMeshcopTransport::new([
        exchange(
            CommissionerOperation::Petition,
            [ScriptedResponse::petition_accept(0xcafe)],
        ),
        exchange(
            CommissionerOperation::Reenroll,
            [ScriptedResponse::accept()],
        ),
        exchange(CommissionerOperation::Reenroll, []),
        exchange(
            CommissionerOperation::DomainReset,
            [ScriptedResponse::accept()],
        ),
        exchange(CommissionerOperation::DomainReset, []),
        exchange(CommissionerOperation::Migrate, [ScriptedResponse::accept()]),
        exchange(CommissionerOperation::Migrate, []),
    ]);
    let mut commissioner = scripted_commissioner(script, []).await;
    commissioner.petition().await.unwrap();

    commissioner
        .command_reenroll(unicast_destination())
        .await
        .unwrap();
    commissioner
        .command_reenroll(multicast_destination())
        .await
        .unwrap();
    commissioner
        .command_domain_reset(unicast_destination())
        .await
        .unwrap();
    commissioner
        .command_domain_reset(multicast_destination())
        .await
        .unwrap();
    commissioner
        .command_migrate(unicast_destination(), "net")
        .await
        .unwrap();
    commissioner
        .command_migrate(multicast_destination(), "net")
        .await
        .unwrap();

    let requests = commissioner
        .scripted_transport()
        .unwrap()
        .observed_requests();
    // Requests 1..7 alternate unicast (confirmable) / multicast (non-confirmable).
    for (idx, expected) in [
        CoapType::Confirmable,
        CoapType::NonConfirmable,
        CoapType::Confirmable,
        CoapType::NonConfirmable,
        CoapType::Confirmable,
        CoapType::NonConfirmable,
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(
            logical_message(&requests[idx + 1]).ty,
            expected,
            "request {idx}"
        );
    }
}

#[tokio::test]
async fn non_confirmable_proxied_responses_are_not_acknowledged() {
    let leader: Ipv6Addr = "fd00:db8::ff:fe00:fc00".parse().unwrap();
    let script = ScriptedMeshcopTransport::new([
        exchange(
            CommissionerOperation::Petition,
            [ScriptedResponse::petition_accept(0x1234)],
        ),
        // A confirmable matched proxied response must be acknowledged through
        // the proxy; a non-confirmable one must not.
        exchange(
            CommissionerOperation::GetCommissionerDataset,
            [ScriptedResponse::proxied(
                leader,
                ScriptedResponse::Content {
                    payload: dataset_with_name("confirmable").to_bytes().unwrap(),
                    confirmable: true,
                },
            )],
        ),
        exchange(
            CommissionerOperation::GetCommissionerDataset,
            [ScriptedResponse::proxied(
                leader,
                ScriptedResponse::content(dataset_with_name("plain").to_bytes().unwrap()),
            )],
        ),
    ]);
    let mut commissioner = scripted_commissioner(script, []).await;
    commissioner.petition().await.unwrap();

    commissioner
        .get_commissioner_dataset(CommissionerDatasetFlags::STEERING_DATA)
        .await
        .unwrap();
    let acks_after_confirmable = commissioner
        .scripted_transport()
        .unwrap()
        .sent_messages()
        .len();
    assert_eq!(acks_after_confirmable, 1, "confirmable response is acked");

    commissioner
        .get_commissioner_dataset(CommissionerDatasetFlags::STEERING_DATA)
        .await
        .unwrap();
    let acks_after_plain = commissioner
        .scripted_transport()
        .unwrap()
        .sent_messages()
        .len();
    assert_eq!(
        acks_after_plain, acks_after_confirmable,
        "non-confirmable response must not be acked"
    );
}
