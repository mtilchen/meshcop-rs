use super::*;

#[test]
fn content_type_try_from_covers_all_arms() {
    assert_eq!(
        ContentType::try_from(20).unwrap(),
        ContentType::ChangeCipherSpec
    );
    assert_eq!(ContentType::try_from(21).unwrap(), ContentType::Alert);
    assert_eq!(ContentType::try_from(22).unwrap(), ContentType::Handshake);
    assert_eq!(
        ContentType::try_from(23).unwrap(),
        ContentType::ApplicationData
    );
    assert!(ContentType::try_from(0).is_err());
    assert!(ContentType::try_from(24).is_err());
}

#[test]
fn open_aes_128_ccm_8_handles_empty_plaintext_and_rejects_short_records() {
    let key = RecordProtectionKey::new([0x44; 16]);
    let fixed_iv = [0x55; 4];

    // Empty plaintext yields the minimum payload (explicit nonce + tag) and round-trips.
    let record = protect_aes_128_ccm_8_record(
        ContentType::ApplicationData,
        1,
        2,
        key.clone(),
        &fixed_iv,
        b"",
    )
    .unwrap();
    assert_eq!(
        record.payload.len(),
        TLS_CCM_EXPLICIT_NONCE_LEN + TLS_CCM_8_TAG_LEN
    );
    assert_eq!(
        open_aes_128_ccm_8_record(&record, key.clone(), &fixed_iv).unwrap(),
        b""
    );

    // A payload shorter than nonce + tag is rejected without panicking.
    let short = DtlsRecord::new(ContentType::ApplicationData, 1, 2, vec![0u8; 4]).unwrap();
    assert!(open_aes_128_ccm_8_record(&short, key, &fixed_iv).is_err());
}

#[test]
fn key_material_debug_redacts_secrets() {
    let key_block = Tls12Aes128Ccm8KeyBlock {
        client_write_key: [0xab; 16],
        server_write_key: [0xcd; 16],
        client_write_iv: [0xef; 4],
        server_write_iv: [0x12; 4],
    };
    let block_debug = format!("{key_block:?}");
    assert!(block_debug.contains("Tls12Aes128Ccm8KeyBlock"));
    assert!(block_debug.contains("<redacted>"));

    let material = ThreadDtlsKeyMaterial {
        master_secret: [0x99; 48],
        key_block,
    };
    let material_debug = format!("{material:?}");
    assert!(material_debug.contains("ThreadDtlsKeyMaterial"));
    assert!(material_debug.contains("<redacted>"));
}

#[test]
fn handshake_type_try_from_round_trips_known_values() {
    for (value, variant) in [
        (0u8, HandshakeType::HelloRequest),
        (1, HandshakeType::ClientHello),
        (2, HandshakeType::ServerHello),
        (3, HandshakeType::HelloVerifyRequest),
        (11, HandshakeType::Certificate),
        (12, HandshakeType::ServerKeyExchange),
        (13, HandshakeType::CertificateRequest),
        (14, HandshakeType::ServerHelloDone),
        (15, HandshakeType::CertificateVerify),
        (16, HandshakeType::ClientKeyExchange),
        (20, HandshakeType::Finished),
    ] {
        assert_eq!(HandshakeType::try_from(value).unwrap(), variant);
        assert_eq!(variant as u8, value);
    }
    assert!(HandshakeType::try_from(4).is_err());
    assert!(HandshakeType::try_from(255).is_err());
}

#[test]
fn handshake_header_parse_requires_minimum_length() {
    let header = HandshakeHeader {
        message_type: HandshakeType::ServerHelloDone,
        length: 0,
        message_seq: 7,
        fragment_offset: 0,
        fragment_length: 0,
    };
    let encoded = header.encode().unwrap();
    assert_eq!(encoded.len(), HandshakeHeader::LEN);
    assert_eq!(HandshakeHeader::parse(&encoded).unwrap(), header);
    assert!(HandshakeHeader::parse(&encoded[..HandshakeHeader::LEN - 1]).is_err());
}

#[test]
fn handshake_header_validate_enforces_field_bounds() {
    let base = HandshakeHeader {
        message_type: HandshakeType::ClientHello,
        length: 4,
        message_seq: 0,
        fragment_offset: 0,
        fragment_length: 4,
    };
    assert!(base.validate().is_ok());

    // A fragment extent past the message length is rejected.
    assert!(
        HandshakeHeader {
            fragment_offset: 2,
            fragment_length: 4,
            ..base
        }
        .validate()
        .is_err()
    );

    // length must fit in 24 bits; the maximum value is still accepted.
    assert!(
        HandshakeHeader {
            length: MAX_U24 + 1,
            fragment_offset: 0,
            fragment_length: 0,
            ..base
        }
        .validate()
        .is_err()
    );
    assert!(
        HandshakeHeader {
            length: MAX_U24,
            fragment_offset: 0,
            fragment_length: MAX_U24,
            ..base
        }
        .validate()
        .is_ok()
    );
    // fragment_offset must fit in 24 bits; the maximum value is still accepted.
    assert!(
        HandshakeHeader {
            length: MAX_U24,
            fragment_offset: MAX_U24,
            fragment_length: 0,
            ..base
        }
        .validate()
        .is_ok()
    );
}

#[test]
fn handshake_fragment_parse_consumes_only_declared_bytes() {
    let fragment = HandshakeFragment {
        header: HandshakeHeader {
            message_type: HandshakeType::ClientHello,
            length: 4,
            message_seq: 1,
            fragment_offset: 0,
            fragment_length: 4,
        },
        fragment: b"abcd".to_vec(),
    };
    let mut encoded = fragment.encode().unwrap();
    encoded.push(0xff); // trailing byte beyond the declared fragment
    assert_eq!(HandshakeFragment::parse(&encoded).unwrap(), fragment);
}

#[test]
fn handshake_message_fragment_enforces_24_bit_payload_bound() {
    // A payload of exactly MAX_U24 bytes is the largest the 24-bit length field
    // can describe, so it must still fragment cleanly. One byte more is rejected.
    let at_limit = HandshakeMessage {
        message_type: HandshakeType::ClientHello,
        message_seq: 0,
        payload: vec![0u8; MAX_U24 as usize],
    };
    let fragments = at_limit.fragment(MAX_U24 as usize).unwrap();
    assert_eq!(fragments.len(), 1);
    assert_eq!(fragments[0].header.length, MAX_U24);

    let over_limit = HandshakeMessage {
        message_type: HandshakeType::ClientHello,
        message_seq: 0,
        payload: vec![0u8; MAX_U24 as usize + 1],
    };
    assert!(over_limit.fragment(MAX_U24 as usize).is_err());
}

#[test]
fn parse_unfragmented_handshake_messages_reads_packed_messages() {
    let first = HandshakeMessage {
        message_type: HandshakeType::ClientKeyExchange,
        message_seq: 4,
        payload: b"hello".to_vec(),
    };
    let second = HandshakeMessage {
        message_type: HandshakeType::Finished,
        message_seq: 5,
        payload: b"world!!".to_vec(),
    };
    let mut payload = first.encode().unwrap();
    payload.extend_from_slice(&second.encode().unwrap());
    let record = DtlsRecord::new(ContentType::Handshake, 1, 0, payload).unwrap();
    assert_eq!(
        parse_unfragmented_handshake_messages(&record).unwrap(),
        vec![first, second]
    );

    // Non-handshake records are rejected.
    let app = DtlsRecord::new(ContentType::ApplicationData, 1, 0, vec![0u8; 16]).unwrap();
    assert!(parse_unfragmented_handshake_messages(&app).is_err());

    // A partial (fragmented) message is rejected.
    let partial = HandshakeFragment {
        header: HandshakeHeader {
            message_type: HandshakeType::ClientHello,
            length: 4,
            message_seq: 0,
            fragment_offset: 0,
            fragment_length: 2,
        },
        fragment: b"ab".to_vec(),
    };
    let fragmented =
        DtlsRecord::new(ContentType::Handshake, 1, 0, partial.encode().unwrap()).unwrap();
    assert!(parse_unfragmented_handshake_messages(&fragmented).is_err());
}

#[test]
fn parse_unfragmented_handshake_record_rejects_fragmented_message() {
    let partial = HandshakeFragment {
        header: HandshakeHeader {
            message_type: HandshakeType::ServerHello,
            length: 4,
            message_seq: 0,
            fragment_offset: 0,
            fragment_length: 2,
        },
        fragment: b"ab".to_vec(),
    };
    let record = DtlsRecord::new(ContentType::Handshake, 0, 0, partial.encode().unwrap()).unwrap();
    assert!(parse_unfragmented_handshake_record(&record, HandshakeType::ServerHello).is_err());
}

#[test]
fn handshake_reassembler_rejects_metadata_mismatch() {
    let first = HandshakeFragment {
        header: HandshakeHeader {
            message_type: HandshakeType::ClientHello,
            length: 4,
            message_seq: 0,
            fragment_offset: 0,
            fragment_length: 2,
        },
        fragment: b"ab".to_vec(),
    };
    let follow_up = |header: HandshakeHeader| HandshakeFragment {
        header,
        fragment: b"cd".to_vec(),
    };

    // A follow-up fragment with a different declared length is rejected.
    let mut reassembler = HandshakeReassembler::default();
    assert!(reassembler.push(first.clone()).unwrap().is_none());
    assert!(
        reassembler
            .push(follow_up(HandshakeHeader {
                length: 6,
                fragment_offset: 2,
                fragment_length: 2,
                ..first.header
            }))
            .is_err()
    );

    // A follow-up fragment with a different message_seq is rejected.
    let mut reassembler = HandshakeReassembler::default();
    assert!(reassembler.push(first.clone()).unwrap().is_none());
    assert!(
        reassembler
            .push(follow_up(HandshakeHeader {
                message_seq: 9,
                fragment_offset: 2,
                fragment_length: 2,
                ..first.header
            }))
            .is_err()
    );

    // A follow-up fragment with a different message_type is rejected.
    let mut reassembler = HandshakeReassembler::default();
    assert!(reassembler.push(first.clone()).unwrap().is_none());
    assert!(
        reassembler
            .push(follow_up(HandshakeHeader {
                message_type: HandshakeType::ServerHello,
                fragment_offset: 2,
                fragment_length: 2,
                ..first.header
            }))
            .is_err()
    );
}

#[test]
fn client_hello_state_accessors_track_sequences_and_kkpp() {
    let mut state = DtlsClientHelloState::new([0u8; 32]);
    assert_eq!(state.ecjpake_kkpp(), None);
    assert_eq!(state.next_record_sequence(), 0);
    assert_eq!(state.next_message_sequence(), 0);

    state.set_ecjpake_kkpp(vec![0x41, 0x04, 0xbb]);
    assert_eq!(state.ecjpake_kkpp(), Some([0x41, 0x04, 0xbb].as_slice()));

    let _ = state.next_client_hello_record().unwrap();
    assert_eq!(state.next_record_sequence(), 1);
    assert_eq!(state.next_message_sequence(), 1);

    let cached = DtlsClientHelloState::with_ecjpake_kkpp([0u8; 32], vec![0xaa, 0xbb]);
    assert_eq!(cached.ecjpake_kkpp(), Some([0xaa, 0xbb].as_slice()));
}

#[test]
fn server_hello_validate_thread_profile_rejects_wrong_selections() {
    let mut hello = ServerHello {
        random: [0u8; 32],
        session_id: Vec::new(),
        cipher_suite: TLS_ECJPAKE_WITH_AES_128_CCM_8,
        compression_method: TLS_COMPRESSION_NULL,
        extensions: Vec::new(),
    };
    assert!(hello.validate_thread_profile().is_ok());

    hello.cipher_suite = 0x1301;
    assert!(hello.validate_thread_profile().is_err());

    hello.cipher_suite = TLS_ECJPAKE_WITH_AES_128_CCM_8;
    hello.compression_method = 0x01;
    assert!(hello.validate_thread_profile().is_err());
}

#[test]
fn client_hello_encode_enforces_u8_length_fields() {
    let mut hello = ClientHello::thread_profile([0u8; 32], Vec::new());
    hello.session_id = vec![0u8; u8::MAX as usize];
    assert!(hello.encode().is_ok());

    hello.session_id = vec![0u8; u8::MAX as usize + 1];
    assert!(hello.encode().is_err());
}

#[test]
fn extension_encoding_enforces_u16_length_fields() {
    let make = |data_len: usize| ServerHello {
        random: [0u8; 32],
        session_id: Vec::new(),
        cipher_suite: TLS_ECJPAKE_WITH_AES_128_CCM_8,
        compression_method: TLS_COMPRESSION_NULL,
        extensions: vec![TlsExtension {
            extension_type: 0x00ff,
            data: vec![0u8; data_len],
        }],
    };

    // An extensions block of exactly u16::MAX bytes is accepted.
    assert!(make(u16::MAX as usize - 4).encode().is_ok());
    // A single extension whose data exceeds the u16 length is rejected.
    assert!(make(u16::MAX as usize + 1).encode().is_err());
}

#[test]
fn decode_rejects_trailing_bytes() {
    let mut bytes = HelloVerifyRequest {
        server_version: DTLS_1_2_VERSION,
        cookie: vec![0x01, 0x02],
    }
    .encode()
    .unwrap();
    bytes.push(0xff);
    assert!(HelloVerifyRequest::decode(&bytes).is_err());
}

#[test]
fn read_u24_decodes_big_endian() {
    assert_eq!(read_u24(&[0x12, 0x34, 0x56]), 0x0012_3456);
    assert_eq!(read_u24(&[0x00, 0x00, 0x00]), 0);
    assert_eq!(read_u24(&[0xff, 0xff, 0xff]), MAX_U24);
}

#[test]
fn write_u24_round_trips_and_enforces_bounds() {
    let mut out = [0u8; 3];
    write_u24(0x0012_3456, &mut out).unwrap();
    assert_eq!(out, [0x12, 0x34, 0x56]);
    assert_eq!(read_u24(&out), 0x0012_3456);

    assert!(write_u24(MAX_U24, &mut [0u8; 3]).is_ok());
    assert!(write_u24(MAX_U24 + 1, &mut [0u8; 3]).is_err());
    assert!(write_u24(0, &mut [0u8; 2]).is_err());
    assert!(write_u24(0, &mut [0u8; 4]).is_err());
}
