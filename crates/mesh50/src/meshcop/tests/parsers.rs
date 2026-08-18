use super::*;

#[test]
fn parses_state_and_petition_responses() {
    let response = CoapMessage {
        ty: CoapType::Acknowledgement,
        code: CoapCode::CHANGED,
        message_id: 1,
        token: Vec::new(),
        options: Vec::new(),
        payload: vec![TLV_STATE, 1, 1, TLV_COMMISSIONER_SESSION_ID, 2, 0x12, 0x34],
    };

    assert_eq!(
        parse_state_response(&response, true).unwrap(),
        Some(MeshcopState::Accept)
    );
    let petition = parse_petition_response(&response).unwrap();
    assert_eq!(petition.state, MeshcopState::Accept);
    assert_eq!(petition.session_id, Some(0x1234));
}

#[test]
fn state_and_petition_parsers_reject_malformed_responses() {
    let cases = [
        (
            "wrong CoAP code",
            CoapMessage {
                ty: CoapType::Acknowledgement,
                code: CoapCode::CONTENT,
                message_id: 1,
                token: Vec::new(),
                options: Vec::new(),
                payload: vec![TLV_STATE, 1, 1],
            },
        ),
        (
            "missing mandatory state",
            CoapMessage {
                ty: CoapType::Acknowledgement,
                code: CoapCode::CHANGED,
                message_id: 1,
                token: Vec::new(),
                options: Vec::new(),
                payload: Vec::new(),
            },
        ),
        (
            "invalid state length",
            CoapMessage {
                ty: CoapType::Acknowledgement,
                code: CoapCode::CHANGED,
                message_id: 1,
                token: Vec::new(),
                options: Vec::new(),
                payload: vec![TLV_STATE, 2, 0, 1],
            },
        ),
        (
            "invalid state value",
            CoapMessage {
                ty: CoapType::Acknowledgement,
                code: CoapCode::CHANGED,
                message_id: 1,
                token: Vec::new(),
                options: Vec::new(),
                payload: vec![TLV_STATE, 1, 2],
            },
        ),
    ];

    for (name, response) in cases {
        assert!(parse_state_response(&response, true).is_err(), "{name}");
    }

    let invalid_id = CoapMessage {
        ty: CoapType::Acknowledgement,
        code: CoapCode::CHANGED,
        message_id: 1,
        token: Vec::new(),
        options: Vec::new(),
        payload: vec![TLV_STATE, 1, 0xff, TLV_COMMISSIONER_ID, 1, 0xff],
    };
    assert!(parse_petition_response(&invalid_id).is_err());
}

#[test]
fn diagnostic_and_mlr_requests_use_thread_scoped_tlvs() {
    let diag = diagnostic_request(
        CommissionerOperation::DiagnosticGet,
        1,
        [],
        (1 << 0) | (1 << 11),
        true,
    )
    .unwrap();
    assert_eq!(diag.uri_path().unwrap(), Some("/d/dq".to_string()));
    let diag_tlvs = TlvSet::parse(&diag.payload).unwrap();
    assert_eq!(
        diag_tlvs.last_value(NETWORK_DIAG_TLV_TYPE_LIST),
        Some(&[0, 3][..])
    );

    let mlr =
        multicast_listener_request(2, [], 0x3456, &["ff05::1".parse().unwrap()], 300).unwrap();
    assert_eq!(mlr.uri_path().unwrap(), Some("/n/mr".to_string()));
    let mlr_tlvs = TlvSet::parse(&mlr.payload).unwrap();
    assert_eq!(
        mlr_tlvs.last_value(THREAD_TLV_COMMISSIONER_SESSION_ID),
        Some(&[0x34, 0x56][..])
    );
    assert_eq!(
        mlr_tlvs.last_value(THREAD_TLV_TIMEOUT),
        Some(&300u32.to_be_bytes()[..])
    );
    assert_eq!(
        mlr_tlvs
            .last_value(THREAD_TLV_IPV6_ADDRESSES)
            .unwrap()
            .len(),
        16
    );
}

#[test]
fn relay_tx_request_encodes_joiner_fields() {
    let relay = relay_tx_request(1, [], &[1, 2, 3, 4, 5, 6, 7, 8], 1000, 0x6800, b"dtls").unwrap();
    assert_eq!(relay.ty, CoapType::NonConfirmable);
    assert_eq!(relay.uri_path().unwrap(), Some("/c/tx".to_string()));
    let tlvs = TlvSet::parse(&relay.payload).unwrap();
    assert_eq!(
        tlvs.last_value(TLV_JOINER_UDP_PORT),
        Some(&[0x03, 0xe8][..])
    );
    assert_eq!(
        tlvs.last_value(TLV_JOINER_ROUTER_LOCATOR),
        Some(&[0x68, 0x00][..])
    );
    assert_eq!(
        tlvs.last_value(TLV_JOINER_IID),
        Some(&[1, 2, 3, 4, 5, 6, 7, 8][..])
    );
    assert_eq!(
        tlvs.last_value(TLV_JOINER_DTLS_ENCAPSULATION),
        Some(&b"dtls"[..])
    );
}

#[test]
fn parses_unsolicited_notifications() {
    let dataset_changed = CoapMessage::post_request(
        CoapType::Confirmable,
        1,
        [],
        uri::MGMT_DATASET_CHANGED,
        Vec::new(),
    )
    .unwrap();
    assert_eq!(
        parse_notification(&dataset_changed).unwrap(),
        Some(MeshcopNotification::DatasetChanged)
    );

    let pan_id_conflict = CoapMessage::post_request(
        CoapType::Confirmable,
        2,
        [],
        uri::MGMT_PANID_CONFLICT,
        vec![
            TLV_CHANNEL_MASK,
            6,
            0,
            4,
            0x07,
            0xff,
            0xf8,
            0x00,
            TLV_PAN_ID,
            2,
            0xfa,
            0xce,
        ],
    )
    .unwrap();
    assert_eq!(
        parse_notification(&pan_id_conflict).unwrap(),
        Some(MeshcopNotification::PanIdConflict {
            channel_mask: 0x07fff800,
            pan_id: 0xface,
        })
    );

    let energy_report = CoapMessage::post_request(
        CoapType::Confirmable,
        3,
        [],
        uri::MGMT_ED_REPORT,
        vec![
            TLV_CHANNEL_MASK,
            6,
            0,
            4,
            0x07,
            0xff,
            0xf8,
            0x00,
            TLV_ENERGY_LIST,
            3,
            1,
            2,
            3,
        ],
    )
    .unwrap();
    assert_eq!(
        parse_notification(&energy_report).unwrap(),
        Some(MeshcopNotification::EnergyReport {
            channel_mask: 0x07fff800,
            energy_list: vec![1, 2, 3],
        })
    );
}

#[test]
fn notification_parser_rejects_malformed_payloads() {
    let cases = [
        (
            "pan-id conflict missing channel mask",
            CoapMessage::post_request(
                CoapType::Confirmable,
                1,
                [],
                uri::MGMT_PANID_CONFLICT,
                vec![TLV_PAN_ID, 2, 0xfa, 0xce],
            )
            .unwrap(),
        ),
        (
            "pan-id conflict without page-zero mask",
            CoapMessage::post_request(
                CoapType::Confirmable,
                2,
                [],
                uri::MGMT_PANID_CONFLICT,
                vec![TLV_CHANNEL_MASK, 3, 1, 1, 0xaa, TLV_PAN_ID, 2, 0xfa, 0xce],
            )
            .unwrap(),
        ),
        (
            "pan-id conflict with short page-zero mask",
            CoapMessage::post_request(
                CoapType::Confirmable,
                3,
                [],
                uri::MGMT_PANID_CONFLICT,
                vec![
                    TLV_CHANNEL_MASK,
                    5,
                    0,
                    3,
                    1,
                    2,
                    3,
                    TLV_PAN_ID,
                    2,
                    0xfa,
                    0xce,
                ],
            )
            .unwrap(),
        ),
        (
            "energy report with truncated channel mask",
            CoapMessage::post_request(
                CoapType::Confirmable,
                4,
                [],
                uri::MGMT_ED_REPORT,
                vec![TLV_CHANNEL_MASK, 1, 0],
            )
            .unwrap(),
        ),
        (
            "relay rx missing encapsulated payload",
            CoapMessage::post_request(
                CoapType::NonConfirmable,
                5,
                [],
                uri::RELAY_RX,
                vec![
                    TLV_JOINER_UDP_PORT,
                    2,
                    0x03,
                    0xe8,
                    TLV_JOINER_ROUTER_LOCATOR,
                    2,
                    0x68,
                    0x00,
                    TLV_JOINER_IID,
                    8,
                    1,
                    2,
                    3,
                    4,
                    5,
                    6,
                    7,
                    8,
                ],
            )
            .unwrap(),
        ),
        (
            "relay rx with short joiner iid",
            CoapMessage::post_request(
                CoapType::NonConfirmable,
                6,
                [],
                uri::RELAY_RX,
                vec![
                    TLV_JOINER_UDP_PORT,
                    2,
                    0x03,
                    0xe8,
                    TLV_JOINER_ROUTER_LOCATOR,
                    2,
                    0x68,
                    0x00,
                    TLV_JOINER_IID,
                    7,
                    1,
                    2,
                    3,
                    4,
                    5,
                    6,
                    7,
                    TLV_JOINER_DTLS_ENCAPSULATION,
                    1,
                    0xaa,
                ],
            )
            .unwrap(),
        ),
    ];

    for (name, message) in cases {
        assert!(parse_notification(&message).is_err(), "{name}");
    }
}

#[test]
fn parses_relay_rx_notification() {
    let relay = CoapMessage::post_request(
        CoapType::NonConfirmable,
        1,
        [],
        uri::RELAY_RX,
        vec![
            TLV_JOINER_UDP_PORT,
            2,
            0x03,
            0xe8,
            TLV_JOINER_ROUTER_LOCATOR,
            2,
            0x68,
            0x00,
            TLV_JOINER_IID,
            8,
            1,
            2,
            3,
            4,
            5,
            6,
            7,
            8,
            TLV_JOINER_DTLS_ENCAPSULATION,
            4,
            b'd',
            b't',
            b'l',
            b's',
        ],
    )
    .unwrap();

    assert_eq!(
        parse_notification(&relay).unwrap(),
        Some(MeshcopNotification::RelayRx {
            joiner_udp_port: 1000,
            joiner_router_locator: 0x6800,
            joiner_iid: [1, 2, 3, 4, 5, 6, 7, 8],
            payload: b"dtls".to_vec(),
        })
    );
}
