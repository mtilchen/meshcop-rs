use super::*;

#[tokio::test]
async fn proxied_operations_wrap_requests_in_udp_tx_to_the_leader_aloc() {
    let leader_aloc: Ipv6Addr = "fd00:db8::ff:fe00:fc00".parse().unwrap();
    let script = ScriptedMeshcopTransport::new([
        exchange(
            CommissionerOperation::Petition,
            [ScriptedResponse::petition_accept(0x1234)],
        ),
        exchange(
            CommissionerOperation::GetActiveDataset,
            [ScriptedResponse::content(
                prefixed_dataset().to_bytes().unwrap(),
            )],
        ),
        exchange(
            CommissionerOperation::GetCommissionerDataset,
            [ScriptedResponse::proxied(
                leader_aloc,
                ScriptedResponse::content(dataset_with_name("one").to_bytes().unwrap()),
            )],
        ),
        exchange(
            CommissionerOperation::GetCommissionerDataset,
            [ScriptedResponse::proxied(
                leader_aloc,
                ScriptedResponse::content(dataset_with_name("two").to_bytes().unwrap()),
            )],
        ),
    ]);
    let mut commissioner = scripted_commissioner(script, []).await;
    // Exercise the real mesh-local prefix fetch instead of the seeded cache.
    commissioner.set_cached_mesh_local_prefix(None);

    commissioner.petition().await.unwrap();
    let first = commissioner
        .get_commissioner_dataset(CommissionerDatasetFlags::STEERING_DATA)
        .await
        .unwrap();
    assert_eq!(first.network_name().unwrap(), Some("one"));
    assert_eq!(
        commissioner.cached_mesh_local_prefix(),
        Some(TEST_MESH_LOCAL_PREFIX)
    );
    // The cached prefix must satisfy the second call without a new fetch.
    let second = commissioner
        .get_commissioner_dataset(CommissionerDatasetFlags::STEERING_DATA)
        .await
        .unwrap();
    assert_eq!(second.network_name().unwrap(), Some("two"));

    let harness = commissioner.scripted_transport().unwrap();
    assert_eq!(harness.remaining_exchange_count(), 0);
    let requests = harness.observed_requests();
    assert_eq!(requests.len(), 4);
    assert_eq!(
        requests[1].operation,
        CommissionerOperation::GetActiveDataset
    );
    assert_eq!(
        tlv_value(&requests[1].message, TLV_GET),
        Some(vec![crate::dataset::TLV_MESH_LOCAL_PREFIX])
    );
    for request in &requests[2..] {
        assert_eq!(request.message.ty, CoapType::NonConfirmable);
        assert_eq!(
            request.message.uri_path().unwrap().as_deref(),
            Some(crate::meshcop::uri::UDP_TX)
        );
        assert_eq!(request.proxy_destination(), Some(leader_aloc));
        let inner = request.inner_message().unwrap();
        assert_eq!(
            inner.uri_path().unwrap().as_deref(),
            Some(crate::meshcop::uri::MGMT_COMMISSIONER_GET)
        );
    }
}

#[tokio::test]
async fn mesh_local_prefix_fetch_rejects_missing_or_invalid_prefixes() {
    let script = ScriptedMeshcopTransport::new([
        exchange(
            CommissionerOperation::Petition,
            [ScriptedResponse::petition_accept(0x1234)],
        ),
        exchange(
            CommissionerOperation::GetActiveDataset,
            [ScriptedResponse::content(
                dataset_with_name("no-prefix").to_bytes().unwrap(),
            )],
        ),
        exchange(
            CommissionerOperation::GetActiveDataset,
            [ScriptedResponse::content({
                let mut dataset = Dataset::default();
                dataset.set_raw(
                    crate::dataset::TLV_MESH_LOCAL_PREFIX,
                    [0x20u8, 0x01, 0x0d, 0xb8, 0, 0, 0, 0],
                );
                dataset.to_bytes().unwrap()
            })],
        ),
    ]);
    let mut commissioner = scripted_commissioner(script, []).await;
    commissioner.set_cached_mesh_local_prefix(None);
    commissioner.petition().await.unwrap();

    assert!(matches!(
        commissioner
            .get_commissioner_dataset(CommissionerDatasetFlags::STEERING_DATA)
            .await
            .unwrap_err(),
        Error::InvalidState("active dataset does not include the mesh-local prefix")
    ));
    assert!(matches!(
        commissioner
            .get_commissioner_dataset(CommissionerDatasetFlags::STEERING_DATA)
            .await
            .unwrap_err(),
        Error::Dataset(message) if message.contains("fd00::/8")
    ));
    assert_eq!(commissioner.cached_mesh_local_prefix(), None);
}

#[tokio::test]
async fn multicast_listener_and_secure_pending_route_to_the_primary_bbr() {
    let pbbr_aloc: Ipv6Addr = "fd00:db8::ff:fe00:fc38".parse().unwrap();
    let script = ScriptedMeshcopTransport::new([
        exchange(
            CommissionerOperation::Petition,
            [ScriptedResponse::petition_accept(0x1234)],
        ),
        exchange(
            CommissionerOperation::RegisterMulticastListener,
            [ScriptedResponse::proxied(
                pbbr_aloc,
                ScriptedResponse::content(vec![THREAD_TLV_STATUS, 1, 2]),
            )],
        ),
        exchange(
            CommissionerOperation::SetSecurePendingDataset,
            [ScriptedResponse::proxied(
                pbbr_aloc,
                ScriptedResponse::accept(),
            )],
        ),
    ]);
    let mut commissioner = scripted_commissioner(script, []).await;
    commissioner.petition().await.unwrap();

    assert_eq!(
        commissioner
            .register_multicast_listener(&["ff05::abcd".to_string()], 300)
            .await
            .unwrap(),
        2
    );
    commissioner
        .set_secure_pending_dataset(120, &pending_dataset_with_name("secure"))
        .await
        .unwrap();

    let harness = commissioner.scripted_transport().unwrap();
    let requests = harness.observed_requests();
    for request in &requests[1..] {
        assert_eq!(request.proxy_destination(), Some(pbbr_aloc), "{request:?}");
    }
    let secure_pending = requests[2].inner_message().unwrap();
    let dissemination = tlv_value(&secure_pending, TLV_SECURE_DISSEMINATION).unwrap();
    let uri = String::from_utf8_lossy(&dissemination[12..]);
    assert_eq!(uri, "coaps://[fd00:db8::ff:fe00:fc38]/c/pg");
}

#[tokio::test]
async fn udp_rx_notifications_queue_events_and_send_proxied_acks() {
    let reporter: Ipv6Addr = "fd00:db8::aa".parse().unwrap();
    let mut diag_answer = CoapMessage {
        ty: CoapType::Confirmable,
        code: CoapCode::POST,
        message_id: 0x4242,
        token: vec![0x42],
        options: Vec::new(),
        // Leader Data TLV (6): partition 1, weighting 64, versions 10/9, router 5.
        payload: vec![6, 8, 0, 0, 0, 1, 64, 10, 9, 5],
    };
    diag_answer
        .set_uri_path(crate::meshcop::uri::DIAG_GET_ANSWER)
        .unwrap();

    let script = ScriptedMeshcopTransport::new([
        exchange(
            CommissionerOperation::Petition,
            [ScriptedResponse::petition_accept(0x1234)],
        ),
        exchange(
            CommissionerOperation::GetActiveDataset,
            [
                ScriptedResponse::UdpRx {
                    source_address: reporter,
                    source_port: crate::meshcop::DEFAULT_MM_PORT,
                    destination_port: crate::meshcop::DEFAULT_MM_PORT,
                    inner: Box::new(ScriptedResponse::Raw(diag_answer.clone())),
                },
                ScriptedResponse::content(dataset_with_name("after").to_bytes().unwrap()),
            ],
        ),
    ]);
    let mut commissioner = scripted_commissioner(script, []).await;
    commissioner.petition().await.unwrap();
    commissioner
        .get_active_dataset(DatasetFlags::NETWORK_NAME)
        .await
        .unwrap();

    let event = commissioner.next_event().await.unwrap().unwrap();
    let CommissionerEvent::DiagnosticAnswer { peer_addr, data } = event else {
        panic!("expected a diagnostic answer event, got {event:?}");
    };
    assert_eq!(peer_addr, reporter.to_string());
    let leader_data = data.leader_data.unwrap();
    assert_eq!(leader_data.partition_id, 1);
    assert_eq!(leader_data.weighting, 64);
    assert_eq!(leader_data.router_id, 5);

    // The confirmable DIAG_GET.ans must be answered with an empty 2.04
    // Changed acknowledgement, proxied back to the reporter through UDP_TX.
    let harness = commissioner.scripted_transport().unwrap();
    let proxied_ack = harness
        .sent_messages()
        .iter()
        .find(|message| message.uri_path().unwrap().as_deref() == Some(crate::meshcop::uri::UDP_TX))
        .expect("proxied acknowledgement was not sent");
    let observed = super::harness::ObservedRequest {
        operation: CommissionerOperation::GetActiveDataset,
        message: proxied_ack.clone(),
    };
    assert_eq!(observed.proxy_destination(), Some(reporter));
    let inner_ack = observed.inner_message().unwrap();
    assert_eq!(inner_ack.ty, CoapType::Acknowledgement);
    assert_eq!(inner_ack.code, CoapCode::CHANGED);
    assert_eq!(inner_ack.message_id, diag_answer.message_id);
    assert_eq!(inner_ack.token, diag_answer.token);
}

#[tokio::test]
async fn get_diagnostics_returns_unicast_answer_over_dg() {
    // The DIAG_GET.req (`/d/dg`) response carries the requested TLVs piggybacked
    // with the request token: MAC Address (1) = 0x8000 and Leader Data (6) =
    // partition 1, weighting 64, versions 10/9, Leader Router ID 5.
    let diag_payload = vec![1, 2, 0x80, 0x00, 6, 8, 0, 0, 0, 1, 64, 10, 9, 5];
    let script = ScriptedMeshcopTransport::new([
        exchange(
            CommissionerOperation::Petition,
            [ScriptedResponse::petition_accept(0x1234)],
        ),
        exchange(
            CommissionerOperation::DiagnosticGetUnicast,
            [ScriptedResponse::content(diag_payload)],
        ),
    ]);
    let mut commissioner = scripted_commissioner(script, []).await;
    commissioner.petition().await.unwrap();

    let data = commissioner
        .get_diagnostics(unicast_destination(), 0b101)
        .await
        .unwrap();
    assert_eq!(data.mac_addr, Some(0x8000));
    let leader = data.leader_data.expect("leader data TLV decoded");
    assert_eq!(leader.partition_id, 1);
    assert_eq!(leader.router_id, 5);

    // The request must target the unicast DIAG_GET.req resource and be proxied
    // to the destination through UDP_TX.
    let requests = commissioner
        .scripted_transport()
        .unwrap()
        .observed_requests();
    let request = observed(requests, CommissionerOperation::DiagnosticGetUnicast);
    assert_eq!(request.proxy_destination(), Some(unicast_destination()));
    assert_eq!(
        logical_message(request).uri_path().unwrap().as_deref(),
        Some(crate::meshcop::uri::DIAG_GET_REQUEST)
    );
}

#[tokio::test]
async fn get_diagnostics_rejects_error_coded_response() {
    // A 4.04-coded response must surface an error rather than being decoded as
    // an empty (all-`None`) diagnostic answer.
    let script = ScriptedMeshcopTransport::new([
        exchange(
            CommissionerOperation::Petition,
            [ScriptedResponse::petition_accept(0x1234)],
        ),
        exchange(
            CommissionerOperation::DiagnosticGetUnicast,
            [ScriptedResponse::Coded {
                code: CoapCode(0x84),
                payload: Vec::new(),
            }],
        ),
    ]);
    let mut commissioner = scripted_commissioner(script, []).await;
    commissioner.petition().await.unwrap();
    let result = commissioner
        .get_diagnostics(unicast_destination(), 0b101)
        .await;
    assert!(
        matches!(result, Err(Error::InvalidState(_))),
        "expected InvalidState, got {result:?}"
    );
}

#[tokio::test]
async fn get_diagnostics_rejects_multicast_destination() {
    let script = ScriptedMeshcopTransport::new([exchange(
        CommissionerOperation::Petition,
        [ScriptedResponse::petition_accept(0x1234)],
    )]);
    let mut commissioner = scripted_commissioner(script, []).await;
    commissioner.petition().await.unwrap();
    let result = commissioner
        .get_diagnostics(multicast_destination(), 0b101)
        .await;
    assert!(
        matches!(result, Err(Error::InvalidState(_))),
        "expected InvalidState for multicast, got {result:?}"
    );
    // The guard must reject before any MeshCoP request is sent.
    assert!(
        commissioner
            .scripted_transport()
            .unwrap()
            .observed_requests()
            .iter()
            .all(|request| request.operation != CommissionerOperation::DiagnosticGetUnicast)
    );
}

#[tokio::test]
async fn proxied_dataset_changed_clears_the_mesh_local_prefix_cache() {
    let mut notification = dataset_changed_notification(0x7001, true);
    notification.token = vec![0x77];
    let script = ScriptedMeshcopTransport::new([
        exchange(
            CommissionerOperation::Petition,
            [ScriptedResponse::petition_accept(0x1234)],
        ),
        exchange(
            CommissionerOperation::GetActiveDataset,
            [
                ScriptedResponse::proxied(
                    "fd00:db8::1".parse().unwrap(),
                    ScriptedResponse::Raw(notification),
                ),
                ScriptedResponse::content(dataset_with_name("after").to_bytes().unwrap()),
            ],
        ),
    ]);
    let mut commissioner = scripted_commissioner(script, []).await;
    commissioner.petition().await.unwrap();
    assert!(commissioner.cached_mesh_local_prefix().is_some());

    commissioner
        .get_active_dataset(DatasetFlags::NETWORK_NAME)
        .await
        .unwrap();
    assert_eq!(
        commissioner.next_event().await.unwrap(),
        Some(CommissionerEvent::DatasetChanged)
    );
    assert_eq!(commissioner.cached_mesh_local_prefix(), None);
}

#[tokio::test]
async fn unproxied_dataset_changed_clears_the_mesh_local_prefix_cache() {
    // Same contract as the proxied case above, but for MGMT_DATASET_CHANGED
    // arriving directly on the commissioner session rather than inside UDP_RX.
    let script = ScriptedMeshcopTransport::new([
        exchange(
            CommissionerOperation::Petition,
            [ScriptedResponse::petition_accept(0x1234)],
        ),
        exchange(
            CommissionerOperation::GetActiveDataset,
            [
                ScriptedResponse::Raw(dataset_changed_notification(0x7003, false)),
                ScriptedResponse::content(dataset_with_name("after").to_bytes().unwrap()),
            ],
        ),
    ]);
    let mut commissioner = scripted_commissioner(script, []).await;
    commissioner.petition().await.unwrap();
    assert!(commissioner.cached_mesh_local_prefix().is_some());

    commissioner
        .get_active_dataset(DatasetFlags::NETWORK_NAME)
        .await
        .unwrap();
    assert_eq!(
        commissioner.next_event().await.unwrap(),
        Some(CommissionerEvent::DatasetChanged)
    );
    assert_eq!(commissioner.cached_mesh_local_prefix(), None);
}

#[tokio::test]
async fn udp_rx_messages_for_other_ports_are_dropped() {
    let script = ScriptedMeshcopTransport::new([
        exchange(
            CommissionerOperation::Petition,
            [ScriptedResponse::petition_accept(0x1234)],
        ),
        exchange(
            CommissionerOperation::GetActiveDataset,
            [
                ScriptedResponse::UdpRx {
                    source_address: "fd00:db8::2".parse().unwrap(),
                    source_port: crate::meshcop::DEFAULT_MM_PORT,
                    destination_port: 5683,
                    inner: Box::new(ScriptedResponse::Raw(dataset_changed_notification(
                        0x7002, true,
                    ))),
                },
                ScriptedResponse::content(dataset_with_name("after").to_bytes().unwrap()),
            ],
        ),
    ]);
    let mut commissioner = scripted_commissioner(script, []).await;
    commissioner.petition().await.unwrap();
    commissioner
        .get_active_dataset(DatasetFlags::NETWORK_NAME)
        .await
        .unwrap();

    // The mis-addressed encapsulation must not become an event or an ack.
    assert!(matches!(
        commissioner.next_event().await.unwrap_err(),
        Error::InvalidState("DTLS session is not established")
    ));
    assert!(
        commissioner
            .scripted_transport()
            .unwrap()
            .sent_messages()
            .is_empty()
    );
}

#[tokio::test]
async fn set_commissioner_dataset_strips_managed_tlvs_and_rejects_empty_sets() {
    let mut dataset = Dataset::default();
    dataset.set_raw(TLV_COMMISSIONER_SESSION_ID, 0xaaaau16.to_be_bytes());
    dataset.set_raw(TLV_BORDER_AGENT_LOCATOR, 0xbbbbu16.to_be_bytes());
    dataset.set_raw(TLV_STEERING_DATA, [0xff]);

    let script = ScriptedMeshcopTransport::new([
        exchange(
            CommissionerOperation::Petition,
            [ScriptedResponse::petition_accept(0xcafe)],
        ),
        exchange(
            CommissionerOperation::SetCommissionerDataset,
            [ScriptedResponse::accept()],
        ),
    ]);
    let mut commissioner = scripted_commissioner(script, []).await;
    commissioner.petition().await.unwrap();
    commissioner
        .set_commissioner_dataset(&dataset)
        .await
        .unwrap();

    let harness = commissioner.scripted_transport().unwrap();
    let inner = harness.observed_requests()[1].inner_message().unwrap();
    let tlvs = TlvSet::parse(&inner.payload).unwrap();
    let session_ids: Vec<_> = tlvs
        .entries()
        .iter()
        .filter(|entry| entry.ty == TLV_COMMISSIONER_SESSION_ID)
        .collect();
    assert_eq!(session_ids.len(), 1);
    assert_eq!(session_ids[0].value, 0xcafeu16.to_be_bytes());
    assert!(tlvs.last_value(TLV_BORDER_AGENT_LOCATOR).is_none());
    assert_eq!(
        tlvs.last_value(TLV_STEERING_DATA),
        Some([0xffu8].as_slice())
    );

    let mut managed_only = Dataset::default();
    managed_only.set_raw(TLV_COMMISSIONER_SESSION_ID, 0xaaaau16.to_be_bytes());
    assert!(matches!(
        commissioner
            .set_commissioner_dataset(&managed_only)
            .await
            .unwrap_err(),
        Error::Dataset(message) if message.contains("no settable TLVs")
    ));
}
