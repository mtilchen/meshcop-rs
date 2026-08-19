use super::*;

#[test]
fn coap_round_trip_with_options_and_payload() {
    let msg = CoapMessage {
        ty: CoapType::Confirmable,
        code: CoapCode::POST,
        message_id: 0x1234,
        token: vec![1, 2, 3, 4],
        options: vec![
            CoapOption {
                number: 11,
                value: b"c".to_vec(),
            },
            CoapOption {
                number: 15,
                value: b"meshcop".to_vec(),
            },
        ],
        payload: vec![0xde, 0xad, 0xbe, 0xef],
    };

    let encoded = msg.encode().unwrap();
    assert_eq!(CoapMessage::decode(&encoded).unwrap(), msg);
}

#[test]
fn coap_round_trip_with_extended_option_nibbles() {
    // Option deltas and value lengths covering the direct (0..=12),
    // one-byte-extended (13..=268), and two-byte-extended (269..) nibble
    // forms, including both boundaries of the one-byte form.
    let msg = CoapMessage {
        ty: CoapType::Confirmable,
        code: CoapCode::POST,
        message_id: 0x4242,
        token: vec![0xaa],
        options: vec![
            CoapOption {
                number: 11,
                value: vec![0x01],
            },
            CoapOption {
                number: 24, // delta 13: one-byte extension lower bound
                value: vec![0x22; 13],
            },
            CoapOption {
                number: 292, // delta 268: one-byte extension upper bound
                value: vec![0x33; 268],
            },
            CoapOption {
                number: 561, // delta 269: two-byte extension lower bound
                value: vec![0x44; 300],
            },
        ],
        payload: vec![0xff, 0x00],
    };

    let encoded = msg.encode().unwrap();
    assert_eq!(CoapMessage::decode(&encoded).unwrap(), msg);
}

#[test]
fn coap_token_length_boundaries_are_enforced() {
    let mut msg = CoapMessage {
        ty: CoapType::Confirmable,
        code: CoapCode::POST,
        message_id: 7,
        token: vec![0xab; 8],
        options: Vec::new(),
        payload: Vec::new(),
    };
    let encoded = msg.encode().unwrap();
    assert_eq!(CoapMessage::decode(&encoded).unwrap(), msg);

    msg.token = vec![0xab; 9];
    assert!(msg.encode().is_err(), "9-byte token must not encode");

    let mut tkl_nine = vec![0x49, 0x02, 0x00, 0x07];
    tkl_nine.extend_from_slice(&[0xab; 9]);
    assert!(
        CoapMessage::decode(&tkl_nine).is_err(),
        "TKL 9 must not decode"
    );

    let truncated_token = [0x42, 0x02, 0x00, 0x07, 0xab];
    assert!(
        CoapMessage::decode(&truncated_token).is_err(),
        "token shorter than TKL must not decode"
    );
}

#[test]
fn coap_decodes_reset_type_and_rejects_truncated_two_byte_extension() {
    let reset = CoapMessage::decode(&[0x70, 0x00, 0x12, 0x34]).unwrap();
    assert_eq!(reset.ty, CoapType::Reset);
    assert_eq!(reset.code, CoapCode::EMPTY);
    assert_eq!(reset.message_id, 0x1234);

    // A 14 (two-byte) extension nibble followed by only one trailing byte.
    assert!(CoapMessage::decode(&[0x40, 0x02, 0x00, 0x01, 0xe0, 0x01]).is_err());

    // A message that ends exactly at a complete two-byte extension is valid:
    // the truncation check must not reject a remainder of exactly two bytes.
    let exact = CoapMessage::decode(&[0x40, 0x02, 0x00, 0x01, 0xe0, 0x00, 0x00]).unwrap();
    assert_eq!(
        exact.options,
        vec![CoapOption {
            number: 269,
            value: Vec::new(),
        }]
    );
}

#[test]
fn coap_empty_ack_predicate_requires_every_field() {
    let ack = CoapMessage::empty_ack(0x0102);
    assert!(ack.is_empty_ack_for(0x0102));

    let mut wrong_type = ack.clone();
    wrong_type.ty = CoapType::Confirmable;
    let mut wrong_code = ack.clone();
    wrong_code.code = CoapCode::CHANGED;
    let mut wrong_id = ack.clone();
    wrong_id.message_id = 0x0103;
    let mut with_token = ack.clone();
    with_token.token = vec![0xab];
    let mut with_option = ack.clone();
    with_option.options.push(CoapOption {
        number: 11,
        value: Vec::new(),
    });
    let mut with_payload = ack.clone();
    with_payload.payload = vec![0x00];

    for (name, message) in [
        ("type", wrong_type),
        ("code", wrong_code),
        ("message id", wrong_id),
        ("token", with_token),
        ("options", with_option),
        ("payload", with_payload),
    ] {
        assert!(!message.is_empty_ack_for(0x0102), "{name}");
    }
}

#[test]
fn set_uri_path_replaces_path_options_and_keeps_others() {
    let mut msg = CoapMessage::post_request(
        CoapType::Confirmable,
        1,
        [0xaa],
        uri::MGMT_ACTIVE_GET,
        Vec::new(),
    )
    .unwrap();
    msg.options.push(CoapOption {
        number: 15,
        value: b"keep".to_vec(),
    });

    msg.set_uri_path("/c/as").unwrap();
    assert_eq!(msg.uri_path().unwrap(), Some("/c/as".to_string()));
    assert!(msg.options.iter().any(|option| option.number == 15));

    msg.set_uri_path("/").unwrap();
    assert_eq!(msg.uri_path().unwrap(), None);
    assert!(msg.options.iter().any(|option| option.number == 15));
}

#[test]
fn coap_decoder_rejects_malformed_inputs() {
    let cases = [
        ("truncated header", vec![0x40, 0x02, 0x00]),
        ("unsupported version", vec![0x00, 0x02, 0x00, 0x01]),
        ("invalid token length", vec![0x49, 0x02, 0x00, 0x01]),
        (
            "truncated option extension",
            vec![0x40, 0x02, 0x00, 0x01, 0xd0],
        ),
        ("reserved option nibble", vec![0x40, 0x02, 0x00, 0x01, 0xf0]),
        (
            "truncated option value",
            vec![0x40, 0x02, 0x00, 0x01, 0x02, 0xaa],
        ),
        (
            "overflowing option extension",
            vec![0x40, 0x02, 0x00, 0x01, 0xe0, 0xff, 0xff],
        ),
    ];

    for (name, bytes) in cases {
        assert!(CoapMessage::decode(&bytes).is_err(), "{name}");
    }
}

#[test]
fn uri_path_options_round_trip_in_segment_order() {
    let msg = CoapMessage::post_request(
        CoapType::Confirmable,
        1,
        [0xaa],
        uri::MGMT_ACTIVE_GET,
        Vec::new(),
    )
    .unwrap();

    let decoded = CoapMessage::decode(&msg.encode().unwrap()).unwrap();
    assert_eq!(decoded.uri_path().unwrap(), Some("/c/ag".to_string()));
}

#[test]
fn uri_path_rejects_empty_segments_and_non_utf8_options() {
    assert!(CoapMessage::post_request(CoapType::Confirmable, 1, [], "/c//ag", Vec::new()).is_err());

    let msg = CoapMessage {
        ty: CoapType::Confirmable,
        code: CoapCode::POST,
        message_id: 1,
        token: Vec::new(),
        options: vec![CoapOption {
            number: COAP_OPTION_URI_PATH,
            value: vec![0xff],
        }],
        payload: Vec::new(),
    };

    assert!(msg.uri_path().is_err());
}

#[test]
fn commissioner_operation_uris_match_openthread() {
    let cases = [
        (CommissionerOperation::Petition, "/c/cp"),
        (CommissionerOperation::KeepAlive, "/c/ca"),
        (CommissionerOperation::GetCommissionerDataset, "/c/cg"),
        (CommissionerOperation::SetCommissionerDataset, "/c/cs"),
        (CommissionerOperation::GetActiveDataset, "/c/ag"),
        (CommissionerOperation::SetActiveDataset, "/c/as"),
        (CommissionerOperation::GetPendingDataset, "/c/pg"),
        (CommissionerOperation::SetPendingDataset, "/c/ps"),
        (CommissionerOperation::SetSecurePendingDataset, "/c/sp"),
        (CommissionerOperation::GetBbrDataset, "/c/bg"),
        (CommissionerOperation::SetBbrDataset, "/c/bs"),
        (CommissionerOperation::AnnounceBegin, "/c/ab"),
        (CommissionerOperation::PanIdQuery, "/c/pq"),
        (CommissionerOperation::EnergyScan, "/c/es"),
        (CommissionerOperation::RegisterMulticastListener, "/n/mr"),
        (CommissionerOperation::Reenroll, "/c/re"),
        (CommissionerOperation::DomainReset, "/c/rt"),
        (CommissionerOperation::Migrate, "/c/nm"),
        (CommissionerOperation::DiagnosticGet, "/d/dq"),
        (CommissionerOperation::DiagnosticReset, "/d/dr"),
        (CommissionerOperation::SendToJoiner, "/c/tx"),
    ];

    for (operation, expected) in cases {
        assert_eq!(operation.uri_path(), expected);
    }
}

#[test]
fn petition_request_carries_commissioner_id() {
    let msg = petition_request(0x1111, [1, 2], "meshcop").unwrap();
    assert_eq!(msg.uri_path().unwrap(), Some("/c/cp".to_string()));

    let tlvs = TlvSet::parse(&msg.payload).unwrap();
    assert_eq!(tlvs.last_value(TLV_COMMISSIONER_ID), Some(&b"meshcop"[..]));
}

#[test]
fn keep_alive_and_resign_state_values_are_encoded() {
    let keep_alive = keep_alive_request(1, [], 0xabcd, true).unwrap();
    let resign = keep_alive_request(2, [], 0xabcd, false).unwrap();
    let keep_alive_tlvs = TlvSet::parse(&keep_alive.payload).unwrap();
    let resign_tlvs = TlvSet::parse(&resign.payload).unwrap();

    assert_eq!(keep_alive_tlvs.last_value(TLV_STATE), Some(&[1][..]));
    assert_eq!(resign_tlvs.last_value(TLV_STATE), Some(&[0xff][..]));
    assert_eq!(
        keep_alive_tlvs.last_value(TLV_COMMISSIONER_SESSION_ID),
        Some(&[0xab, 0xcd][..])
    );
}

#[test]
fn dataset_get_and_set_requests_use_get_and_session_tlvs() {
    let get = dataset_get_request(
        CommissionerOperation::GetActiveDataset,
        1,
        [],
        &[TLV_ACTIVE_TIMESTAMP, DATASET_TLV_NETWORK_NAME],
    )
    .unwrap();
    let get_tlvs = TlvSet::parse(&get.payload).unwrap();
    assert_eq!(
        get_tlvs.last_value(TLV_GET),
        Some(&[TLV_ACTIVE_TIMESTAMP, DATASET_TLV_NETWORK_NAME][..])
    );

    let dataset =
        Dataset::from_bytes(&[DATASET_TLV_NETWORK_NAME, 4, b't', b'e', b's', b't']).unwrap();
    let set = dataset_set_request(
        CommissionerOperation::SetCommissionerDataset,
        2,
        [],
        0x1234,
        &dataset,
    )
    .unwrap();
    let set_tlvs = TlvSet::parse(&set.payload).unwrap();
    assert_eq!(
        set_tlvs.last_value(TLV_COMMISSIONER_SESSION_ID),
        Some(&[0x12, 0x34][..])
    );
    assert_eq!(
        set_tlvs.last_value(DATASET_TLV_NETWORK_NAME),
        Some(&b"test"[..])
    );
}

#[test]
fn dataset_flag_mapping_uses_openthread_present_flag_bits() {
    assert_eq!(
        active_dataset_tlv_types((1 << 15) | (1 << 9)),
        vec![TLV_ACTIVE_TIMESTAMP, DATASET_TLV_NETWORK_NAME]
    );
    assert_eq!(
        pending_dataset_tlv_types((1 << 5) | (1 << 4)),
        vec![
            crate::dataset::TLV_DELAY_TIMER,
            crate::dataset::TLV_PENDING_TIMESTAMP
        ]
    );
    assert_eq!(
        commissioner_dataset_tlv_types((1 << 13) | (1 << 10)),
        vec![TLV_STEERING_DATA, TLV_JOINER_UDP_PORT]
    );
}

#[test]
fn query_builders_encode_channel_mask_and_command_fields() {
    let announce = announce_begin_request(1, [], 0x1111, 0x07fff800, 3, 200, false).unwrap();
    assert_eq!(announce.ty, CoapType::NonConfirmable);
    assert_eq!(announce.uri_path().unwrap(), Some("/c/ab".to_string()));
    let announce_tlvs = TlvSet::parse(&announce.payload).unwrap();
    assert_eq!(announce_tlvs.last_value(TLV_COUNT), Some(&[3][..]));
    assert_eq!(announce_tlvs.last_value(TLV_PERIOD), Some(&[0, 200][..]));
    assert_eq!(
        announce_tlvs.last_value(TLV_CHANNEL_MASK),
        Some(&[0, 4, 0x07, 0xff, 0xf8, 0x00][..])
    );

    let pan_id = pan_id_query_request(2, [], 0x1111, 0x07fff800, 0xface, true).unwrap();
    let pan_id_tlvs = TlvSet::parse(&pan_id.payload).unwrap();
    assert_eq!(pan_id_tlvs.last_value(TLV_PAN_ID), Some(&[0xfa, 0xce][..]));

    let energy = energy_scan_request(
        3,
        [],
        0x1111,
        EnergyScanRequest {
            channel_mask: 0x07fff800,
            count: 2,
            period_ms: 100,
            scan_duration_ms: 50,
            confirmable: true,
        },
    )
    .unwrap();
    let energy_tlvs = TlvSet::parse(&energy.payload).unwrap();
    assert_eq!(
        energy_tlvs.last_value(TLV_SCAN_DURATION),
        Some(&[0, 50][..])
    );
}
