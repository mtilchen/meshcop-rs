use super::*;

#[tokio::test]
async fn connect_binds_udp_socket_and_exposes_state() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = server.local_addr().unwrap();
    let mut commissioner =
        Commissioner::connect(CommissionerConfig::pskc("test", [0x11; 16]), addr)
            .await
            .unwrap();

    assert_eq!(commissioner.state(), CommissionerState::Connected);
    assert_eq!(commissioner.border_agent(), addr);
    commissioner.disconnect();
    assert_eq!(commissioner.state(), CommissionerState::Disabled);
}

#[tokio::test]
async fn connect_rejects_invalid_keepalive_intervals_before_network_use() {
    for interval in [Duration::from_secs(29), Duration::from_secs(46)] {
        let mut config = CommissionerConfig::pskc("test", [0x11; 16]);
        config.keepalive_interval = interval;
        assert!(matches!(
            Commissioner::connect(config, border_agent())
                .await
                .unwrap_err(),
            Error::Configuration("keepalive interval must be between 30 and 45 seconds")
        ));
    }
}

#[tokio::test]
async fn scripted_harness_drives_petition_dataset_reads_events_and_resign() {
    let active_dataset = dataset_with_name("active-net");
    let pending_dataset = pending_dataset_with_name("pending-net");
    let commissioner_dataset = dataset_with_name("commissioner");
    let bbr_dataset = dataset_with_name("bbr");
    let active_payload = active_dataset.to_bytes().unwrap();

    let script = ScriptedMeshcopTransport::new([
        exchange(
            CommissionerOperation::Petition,
            [
                ScriptedResponse::empty_ack(),
                ScriptedResponse::petition_accept(0x1234),
            ],
        ),
        exchange(
            CommissionerOperation::GetActiveDataset,
            [ScriptedResponse::Content {
                payload: active_payload.clone(),
                confirmable: true,
            }],
        ),
        exchange(
            CommissionerOperation::GetActiveDataset,
            [ScriptedResponse::content(active_payload.clone())],
        ),
        exchange(
            CommissionerOperation::GetPendingDataset,
            [ScriptedResponse::content(
                pending_dataset.to_bytes().unwrap(),
            )],
        ),
        exchange(
            CommissionerOperation::GetCommissionerDataset,
            [ScriptedResponse::content(
                commissioner_dataset.to_bytes().unwrap(),
            )],
        ),
        exchange(
            CommissionerOperation::GetBbrDataset,
            [ScriptedResponse::content(bbr_dataset.to_bytes().unwrap())],
        ),
        exchange(
            CommissionerOperation::KeepAlive,
            [ScriptedResponse::accept()],
        ),
        exchange(
            CommissionerOperation::KeepAlive,
            [ScriptedResponse::reject()],
        ),
    ]);
    let mut commissioner = scripted_commissioner(script, [CommissionerEvent::DatasetChanged]).await;

    assert_eq!(
        commissioner.next_event().await.unwrap(),
        Some(CommissionerEvent::DatasetChanged)
    );

    let petition = commissioner.petition().await.unwrap();
    assert_eq!(petition.session_id, 0x1234);
    assert_eq!(commissioner.session_id(), Some(0x1234));
    assert_eq!(commissioner.state(), CommissionerState::Active);

    let active = commissioner
        .get_active_dataset(DatasetFlags::ACTIVE_TIMESTAMP | DatasetFlags::NETWORK_NAME)
        .await
        .unwrap();
    assert_eq!(active.network_name().unwrap(), Some("active-net"));
    assert_eq!(
        commissioner
            .get_raw_active_dataset(DatasetFlags::NETWORK_NAME)
            .await
            .unwrap(),
        active_payload
    );
    let pending = commissioner
        .get_pending_dataset(DatasetFlags::PENDING_TIMESTAMP | DatasetFlags::NETWORK_NAME)
        .await
        .unwrap();
    assert_eq!(pending.network_name().unwrap(), Some("pending-net"));
    let commissioner_data = commissioner
        .get_commissioner_dataset(CommissionerDatasetFlags::STEERING_DATA)
        .await
        .unwrap();
    assert_eq!(
        commissioner_data.network_name().unwrap(),
        Some("commissioner")
    );
    let bbr = commissioner
        .get_bbr_dataset(CommissionerDatasetFlags::BORDER_AGENT_LOCATOR)
        .await
        .unwrap();
    assert_eq!(bbr.network_name().unwrap(), Some("bbr"));
    assert_eq!(commissioner.keep_alive().await.unwrap(), ResultCode::Accept);
    assert_eq!(
        commissioner.next_event().await.unwrap(),
        Some(CommissionerEvent::KeepAliveResponse(ResultCode::Accept))
    );
    commissioner.resign().await.unwrap();
    assert_eq!(commissioner.state(), CommissionerState::Disabled);
    assert_eq!(commissioner.session_id(), None);

    let harness = commissioner.scripted_transport().unwrap();
    assert_eq!(harness.remaining_exchange_count(), 0);
    assert_eq!(harness.acked_confirmable_responses(), &[2]);
    let requests = harness.observed_requests();
    assert_eq!(
        requests
            .iter()
            .map(|request| request.operation)
            .collect::<Vec<_>>(),
        [
            CommissionerOperation::Petition,
            CommissionerOperation::GetActiveDataset,
            CommissionerOperation::GetActiveDataset,
            CommissionerOperation::GetPendingDataset,
            CommissionerOperation::GetCommissionerDataset,
            CommissionerOperation::GetBbrDataset,
            CommissionerOperation::KeepAlive,
            CommissionerOperation::KeepAlive,
        ]
    );
    assert_eq!(
        tlv_value(&requests[0].message, TLV_COMMISSIONER_ID),
        Some(b"meshcop".to_vec())
    );
    assert_eq!(
        tlv_value(&requests[1].message, TLV_GET),
        Some(vec![
            crate::dataset::TLV_ACTIVE_TIMESTAMP,
            DATASET_TLV_NETWORK_NAME
        ])
    );
    assert_eq!(
        tlv_value(&requests[2].message, TLV_GET),
        Some(vec![DATASET_TLV_NETWORK_NAME])
    );
    assert_eq!(
        tlv_value(&requests[3].message, TLV_GET),
        Some(vec![
            DATASET_TLV_NETWORK_NAME,
            DATASET_TLV_PENDING_TIMESTAMP
        ])
    );
    assert_eq!(tlv_value(&requests[6].message, TLV_STATE), Some(vec![0x01]));
    assert_eq!(tlv_value(&requests[7].message, TLV_STATE), Some(vec![0xff]));
}

#[tokio::test]
async fn public_mutating_operations_include_session_tlvs_and_handle_success() {
    let active_dataset = active_dataset_with_name("active-set");
    let pending_dataset = pending_dataset_with_name("pending-set");
    let commissioner_dataset = dataset_with_name("commissioner-set");
    let bbr_dataset = dataset_with_name("bbr-set");

    let script = ScriptedMeshcopTransport::new([
        exchange(
            CommissionerOperation::Petition,
            [ScriptedResponse::petition_accept(0xbeef)],
        ),
        exchange(
            CommissionerOperation::SetActiveDataset,
            [ScriptedResponse::accept()],
        ),
        exchange(
            CommissionerOperation::SetPendingDataset,
            [ScriptedResponse::accept()],
        ),
        exchange(
            CommissionerOperation::SetSecurePendingDataset,
            [ScriptedResponse::accept()],
        ),
        exchange(
            CommissionerOperation::SetCommissionerDataset,
            [ScriptedResponse::accept()],
        ),
        exchange(
            CommissionerOperation::SetBbrDataset,
            [ScriptedResponse::accept()],
        ),
        exchange(
            CommissionerOperation::AnnounceBegin,
            [ScriptedResponse::changed_without_state()],
        ),
        exchange(
            CommissionerOperation::PanIdQuery,
            [ScriptedResponse::changed_without_state()],
        ),
        exchange(
            CommissionerOperation::EnergyScan,
            [ScriptedResponse::changed_without_state()],
        ),
        exchange(
            CommissionerOperation::RegisterMulticastListener,
            [ScriptedResponse::content(vec![THREAD_TLV_STATUS, 1, 0])],
        ),
        exchange(
            CommissionerOperation::Reenroll,
            [ScriptedResponse::changed_without_state()],
        ),
        exchange(
            CommissionerOperation::DomainReset,
            [ScriptedResponse::changed_without_state()],
        ),
        exchange(
            CommissionerOperation::Migrate,
            [ScriptedResponse::changed_without_state()],
        ),
        exchange(
            CommissionerOperation::DiagnosticGet,
            [ScriptedResponse::changed_without_state()],
        ),
        exchange(
            CommissionerOperation::DiagnosticReset,
            [ScriptedResponse::changed_without_state()],
        ),
        exchange(
            CommissionerOperation::SendToJoiner,
            [ScriptedResponse::changed_without_state()],
        ),
    ]);
    let mut commissioner = scripted_commissioner(script, []).await;

    commissioner.petition().await.unwrap();
    commissioner
        .set_active_dataset(&active_dataset)
        .await
        .unwrap();
    commissioner
        .set_pending_dataset(&pending_dataset)
        .await
        .unwrap();
    commissioner
        .set_secure_pending_dataset(120, &pending_dataset)
        .await
        .unwrap();
    commissioner
        .set_commissioner_dataset(&commissioner_dataset)
        .await
        .unwrap();
    commissioner.set_bbr_dataset(&bbr_dataset).await.unwrap();
    commissioner
        .announce_begin(0x07fff800, 2, 100, multicast_destination())
        .await
        .unwrap();
    commissioner
        .pan_id_query(0x07fff800, 0xface, unicast_destination())
        .await
        .unwrap();
    commissioner
        .energy_scan(0x07fff800, 2, 100, 50, multicast_destination())
        .await
        .unwrap();
    assert_eq!(
        commissioner
            .register_multicast_listener(&["ff05::1".to_string()], 300)
            .await
            .unwrap(),
        0
    );
    commissioner
        .command_reenroll(unicast_destination())
        .await
        .unwrap();
    commissioner
        .command_domain_reset(unicast_destination())
        .await
        .unwrap();
    commissioner
        .command_migrate(unicast_destination(), "designated-net")
        .await
        .unwrap();
    commissioner
        .diagnostic_get(Some(unicast_destination()), 0b101)
        .await
        .unwrap();
    commissioner
        .diagnostic_reset(Some(unicast_destination()), 0b101)
        .await
        .unwrap();
    commissioner
        .send_to_joiner(&[1, 2, 3, 4, 5, 6, 7, 8], 1000, b"dtls")
        .await
        .unwrap();

    let requests = commissioner
        .scripted_transport()
        .unwrap()
        .observed_requests();
    assert_eq!(requests.len(), 16);
    for operation in [
        CommissionerOperation::SetActiveDataset,
        CommissionerOperation::SetPendingDataset,
        CommissionerOperation::SetSecurePendingDataset,
        CommissionerOperation::SetCommissionerDataset,
        CommissionerOperation::SetBbrDataset,
        CommissionerOperation::AnnounceBegin,
        CommissionerOperation::PanIdQuery,
        CommissionerOperation::EnergyScan,
        CommissionerOperation::Reenroll,
        CommissionerOperation::DomainReset,
        CommissionerOperation::Migrate,
    ] {
        let request = observed(requests, operation);
        assert_eq!(
            tlv_value(&logical_message(request), TLV_COMMISSIONER_SESSION_ID),
            Some(0xbeefu16.to_be_bytes().to_vec()),
            "{operation:?}"
        );
    }

    assert_eq!(
        logical_message(observed(requests, CommissionerOperation::AnnounceBegin)).ty,
        CoapType::NonConfirmable
    );
    assert_eq!(
        logical_message(observed(requests, CommissionerOperation::PanIdQuery)).ty,
        CoapType::Confirmable
    );
    assert_eq!(
        logical_message(observed(requests, CommissionerOperation::EnergyScan)).ty,
        CoapType::NonConfirmable
    );
    assert_eq!(
        tlv_value(
            &logical_message(observed(requests, CommissionerOperation::Migrate)),
            TLV_NETWORK_NAME
        ),
        Some(b"designated-net".to_vec())
    );
    let relay = &observed(requests, CommissionerOperation::SendToJoiner).message;
    assert_eq!(relay.ty, CoapType::NonConfirmable);
    assert_eq!(
        tlv_value(relay, TLV_JOINER_UDP_PORT),
        Some(vec![0x03, 0xe8])
    );
    assert_eq!(
        tlv_value(relay, TLV_JOINER_IID),
        Some(vec![1, 2, 3, 4, 5, 6, 7, 8])
    );
    assert_eq!(
        tlv_value(relay, TLV_JOINER_DTLS_ENCAPSULATION),
        Some(b"dtls".to_vec())
    );
}

#[tokio::test]
async fn public_api_maps_protocol_errors_without_touching_live_network() {
    let mut pending_petition = scripted_commissioner(
        ScriptedMeshcopTransport::new([exchange(
            CommissionerOperation::Petition,
            [ScriptedResponse::pending()],
        )]),
        [],
    )
    .await;
    assert!(matches!(
        pending_petition.petition().await.unwrap_err(),
        Error::InvalidState("petition response is pending")
    ));
    assert_eq!(pending_petition.state(), CommissionerState::Connected);

    let mut rejected_petition = scripted_commissioner(
        ScriptedMeshcopTransport::new([exchange(
            CommissionerOperation::Petition,
            [ScriptedResponse::petition_reject("existing-commissioner")],
        )]),
        [],
    )
    .await;
    assert!(matches!(
        rejected_petition.petition().await.unwrap_err(),
        Error::PetitionRejected {
            existing_commissioner_id: Some(id),
        } if id == "existing-commissioner"
    ));
    assert_eq!(rejected_petition.state(), CommissionerState::Connected);

    // Real border agents echo the petitioner's Commissioner ID in an accepted
    // petition response; that echoed ID must not be mistaken for a conflict.
    let mut accepted_with_echo = scripted_commissioner(
        ScriptedMeshcopTransport::new([exchange(
            CommissionerOperation::Petition,
            [ScriptedResponse::petition_accept_with_id(
                0x4242,
                "OT-commissioner",
            )],
        )]),
        [],
    )
    .await;
    let accepted = accepted_with_echo.petition().await.unwrap();
    assert_eq!(accepted.session_id, 0x4242);
    assert_eq!(
        accepted.existing_commissioner_id.as_deref(),
        Some("OT-commissioner")
    );
    assert_eq!(accepted_with_echo.state(), CommissionerState::Active);

    let mut rejected_set = scripted_commissioner(
        ScriptedMeshcopTransport::new([
            exchange(
                CommissionerOperation::Petition,
                [ScriptedResponse::petition_accept(0x1111)],
            ),
            exchange(
                CommissionerOperation::SetActiveDataset,
                [ScriptedResponse::reject()],
            ),
        ]),
        [],
    )
    .await;
    rejected_set.petition().await.unwrap();
    assert!(matches!(
        rejected_set
            .set_active_dataset(&active_dataset_with_name("reject"))
            .await
            .unwrap_err(),
        Error::InvalidState("MeshCoP request was rejected")
    ));

    let mut delayed_duplicate = scripted_commissioner(
        ScriptedMeshcopTransport::new([exchange(
            CommissionerOperation::Petition,
            [
                ScriptedResponse::Raw(CoapMessage {
                    ty: CoapType::Acknowledgement,
                    code: CoapCode::CHANGED,
                    message_id: 1,
                    token: vec![0xaa, 0xbb],
                    options: Vec::new(),
                    payload: vec![TLV_STATE, 1, 1],
                }),
                ScriptedResponse::petition_accept(0x1234),
            ],
        )]),
        [],
    )
    .await;
    assert_eq!(
        delayed_duplicate.petition().await.unwrap().session_id,
        0x1234
    );

    let mut responses = (0..40)
        .map(|idx| ScriptedResponse::Raw(dataset_changed_notification(0x8000 + idx, true)))
        .collect::<Vec<_>>();
    responses.push(ScriptedResponse::content(
        dataset_with_name("after-events").to_bytes().unwrap(),
    ));
    let mut unsolicited_events = scripted_commissioner(
        ScriptedMeshcopTransport::new([
            exchange(
                CommissionerOperation::Petition,
                [ScriptedResponse::petition_accept(0x1111)],
            ),
            exchange(CommissionerOperation::GetActiveDataset, responses),
        ]),
        [],
    )
    .await;
    unsolicited_events.petition().await.unwrap();
    let active = unsolicited_events
        .get_active_dataset(DatasetFlags::NETWORK_NAME)
        .await
        .unwrap();
    assert_eq!(active.network_name().unwrap(), Some("after-events"));
    for _ in 0..40 {
        assert_eq!(
            unsolicited_events.next_event().await.unwrap(),
            Some(CommissionerEvent::DatasetChanged)
        );
    }
    assert_eq!(
        unsolicited_events
            .scripted_transport()
            .unwrap()
            .acked_confirmable_responses()
            .len(),
        40
    );
}

#[tokio::test]
async fn petition_requires_connected_inactive_commissioner_state() {
    let mut disconnected = scripted_commissioner(ScriptedMeshcopTransport::new([]), []).await;
    disconnected.disconnect();
    assert!(matches!(
        disconnected.petition().await.unwrap_err(),
        Error::InvalidState("commissioner is disconnected")
    ));
    assert_eq!(disconnected.state(), CommissionerState::Disabled);
    assert_eq!(disconnected.session_id(), None);
    assert_eq!(
        disconnected
            .scripted_transport()
            .unwrap()
            .observed_requests()
            .len(),
        0
    );

    let mut active = scripted_commissioner(
        ScriptedMeshcopTransport::new([exchange(
            CommissionerOperation::Petition,
            [ScriptedResponse::petition_accept(0x2222)],
        )]),
        [],
    )
    .await;
    active.petition().await.unwrap();
    assert!(matches!(
        active.petition().await.unwrap_err(),
        Error::InvalidState("commissioner is already active")
    ));
    assert_eq!(active.state(), CommissionerState::Active);
    assert_eq!(active.session_id(), Some(0x2222));
    assert_eq!(
        active
            .scripted_transport()
            .unwrap()
            .observed_requests()
            .len(),
        1
    );
}

#[tokio::test]
async fn inactive_session_and_deferred_ccm_paths_are_reported() {
    let mut commissioner = scripted_commissioner(ScriptedMeshcopTransport::new([]), []).await;

    assert!(matches!(
        commissioner
            .set_active_dataset(&active_dataset_with_name("inactive"))
            .await
            .unwrap_err(),
        Error::InvalidState("commissioner session is not active")
    ));
    assert!(matches!(
        commissioner
            .register_multicast_listener(&["ff05::1".to_string()], 300)
            .await
            .unwrap_err(),
        Error::InvalidState("commissioner session is not active")
    ));
    assert!(matches!(
        commissioner
            .request_token("127.0.0.1:49156".parse().unwrap())
            .await
            .unwrap_err(),
        Error::Unsupported("CCM token request is deferred")
    ));
    assert!(matches!(
        commissioner.set_token(b"token").unwrap_err(),
        Error::Unsupported("CCM token support is deferred")
    ));

    let mut ccm_config = CommissionerConfig::pskc("test", [0x11; 16]);
    ccm_config.enable_ccm = true;
    assert!(matches!(
        Commissioner::connect(ccm_config, "127.0.0.1:49156".parse().unwrap())
            .await
            .unwrap_err(),
        Error::Unsupported("CCM is reserved but deferred")
    ));
}

#[tokio::test]
async fn public_commissioner_methods_are_table_driven() {
    let cases = [
        PublicCommissionerMethod::Connect,
        PublicCommissionerMethod::State,
        PublicCommissionerMethod::SessionId,
        PublicCommissionerMethod::BorderAgent,
        PublicCommissionerMethod::Config,
        PublicCommissionerMethod::Socket,
        PublicCommissionerMethod::Petition,
        PublicCommissionerMethod::KeepAlive,
        PublicCommissionerMethod::Resign,
        PublicCommissionerMethod::GetActiveDataset,
        PublicCommissionerMethod::GetRawActiveDataset,
        PublicCommissionerMethod::GetPendingDataset,
        PublicCommissionerMethod::SetActiveDataset,
        PublicCommissionerMethod::SetPendingDataset,
        PublicCommissionerMethod::SetSecurePendingDataset,
        PublicCommissionerMethod::GetCommissionerDataset,
        PublicCommissionerMethod::SetCommissionerDataset,
        PublicCommissionerMethod::GetBbrDataset,
        PublicCommissionerMethod::SetBbrDataset,
        PublicCommissionerMethod::AnnounceBegin,
        PublicCommissionerMethod::PanIdQuery,
        PublicCommissionerMethod::EnergyScan,
        PublicCommissionerMethod::RegisterMulticastListener,
        PublicCommissionerMethod::CommandReenroll,
        PublicCommissionerMethod::CommandDomainReset,
        PublicCommissionerMethod::CommandMigrate,
        PublicCommissionerMethod::DiagnosticGet,
        PublicCommissionerMethod::DiagnosticReset,
        PublicCommissionerMethod::SendToJoiner,
        PublicCommissionerMethod::RequestToken,
        PublicCommissionerMethod::SetToken,
        PublicCommissionerMethod::NextEvent,
        PublicCommissionerMethod::Disconnect,
    ];

    for case in cases {
        case.assert_covered().await;
    }
}
