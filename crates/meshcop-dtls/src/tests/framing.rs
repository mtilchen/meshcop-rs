use super::*;

#[test]
fn record_header_round_trip() {
    let header = RecordHeader {
        content_type: ContentType::Handshake,
        version: DTLS_1_2_VERSION,
        epoch: 2,
        sequence_number: 0x0102_0304_0506,
        length: 42,
    };
    let encoded = header.encode();
    assert_eq!(RecordHeader::parse(&encoded).unwrap(), header);
    assert_eq!(
        header.aead_additional_data(7),
        [
            0x00,
            0x02,
            0x01,
            0x02,
            0x03,
            0x04,
            0x05,
            0x06,
            ContentType::Handshake as u8,
            0xfe,
            0xfd,
            0x00,
            0x07
        ]
    );
}

#[test]
fn parses_multiple_records_from_one_datagram() {
    let first = DtlsRecord::new(ContentType::Handshake, 0, 1, b"one".to_vec()).unwrap();
    let second = DtlsRecord::new(ContentType::ApplicationData, 1, 2, b"two".to_vec()).unwrap();
    let mut datagram = first.encode().unwrap();
    datagram.extend_from_slice(&second.encode().unwrap());

    assert_eq!(
        DtlsRecord::parse_datagram(&datagram).unwrap(),
        vec![first, second]
    );

    datagram.pop();
    assert!(DtlsRecord::parse_datagram(&datagram).is_err());
}

#[test]
fn handshake_header_and_fragment_round_trip() {
    let fragment = HandshakeFragment {
        header: HandshakeHeader {
            message_type: HandshakeType::ClientHello,
            length: 10,
            message_seq: 4,
            fragment_offset: 3,
            fragment_length: 4,
        },
        fragment: b"hell".to_vec(),
    };

    let encoded = fragment.encode().unwrap();
    assert_eq!(HandshakeFragment::parse(&encoded).unwrap(), fragment);
    assert_eq!(&encoded[..12], &[1, 0, 0, 10, 0, 4, 0, 0, 3, 0, 0, 4]);
}

#[test]
fn transcript_uses_single_fragment_dtls_handshake_header() {
    let message = HandshakeMessage {
        message_type: HandshakeType::ClientHello,
        message_seq: 0,
        payload: b"abc".to_vec(),
    };
    assert_eq!(
        message.transcript_bytes().unwrap(),
        hex::decode("010000030000000000000003616263").unwrap()
    );

    let mut transcript = HandshakeTranscript::new();
    transcript.push(&message).unwrap();
    let expected_hash: [u8; 32] =
        hex::decode("a6dd1bc37a0ae6acd89d2fcc1be22d0365f7687d6ecd8c39a16977aae17ea5d5")
            .unwrap()
            .try_into()
            .unwrap();
    assert_eq!(transcript.sha256(), expected_hash);
}

#[test]
fn reassembles_out_of_order_handshake_fragments() {
    let message = HandshakeMessage {
        message_type: HandshakeType::ServerHello,
        message_seq: 2,
        payload: b"abcdefghij".to_vec(),
    };
    let fragments = message.fragment(4).unwrap();
    assert_eq!(fragments.len(), 3);

    let mut reassembler = HandshakeReassembler::default();
    assert!(reassembler.push(fragments[1].clone()).unwrap().is_none());
    assert!(reassembler.push(fragments[0].clone()).unwrap().is_none());
    assert_eq!(
        reassembler.push(fragments[2].clone()).unwrap(),
        Some(message)
    );
}

#[test]
fn rejects_oversized_handshake_message_length() {
    // A fragment header claiming a multi-megabyte message must be rejected
    // before the reassembler allocates a buffer for it.
    let oversized = HandshakeFragment {
        header: HandshakeHeader {
            message_type: HandshakeType::ClientHello,
            length: 1 << 20,
            message_seq: 0,
            fragment_offset: 0,
            fragment_length: 2,
        },
        fragment: b"ab".to_vec(),
    };
    let mut reassembler = HandshakeReassembler::default();
    assert!(reassembler.push(oversized).is_err());
}

#[test]
fn accepts_handshake_message_at_the_reassembly_cap() {
    // The 64 KiB literals below intentionally restate the cap rather than
    // reusing the constant, so a wrongly-computed cap cannot satisfy them.
    assert_eq!(MAX_HANDSHAKE_MESSAGE_LEN, 65536);

    // The cap is inclusive: a message of exactly 64 KiB must still
    // reassemble, and one byte more must be rejected.
    let at_cap = HandshakeFragment {
        header: HandshakeHeader {
            message_type: HandshakeType::ClientHello,
            length: 65536,
            message_seq: 0,
            fragment_offset: 0,
            fragment_length: 65536,
        },
        fragment: vec![0x5a; 65536],
    };
    let mut reassembler = HandshakeReassembler::default();
    let message = reassembler.push(at_cap).unwrap().unwrap();
    assert_eq!(message.payload.len(), 65536);

    let over_cap = HandshakeFragment {
        header: HandshakeHeader {
            message_type: HandshakeType::ClientHello,
            length: 65537,
            message_seq: 0,
            fragment_offset: 0,
            fragment_length: 2,
        },
        fragment: b"ab".to_vec(),
    };
    let mut reassembler = HandshakeReassembler::default();
    assert!(reassembler.push(over_cap).is_err());
}

#[test]
fn rejects_handshake_header_with_any_single_oversized_field() {
    // Each 24-bit field is validated independently: exactly one field past
    // MAX_U24 must fail validation with the 24-bit-field error specifically,
    // not fall through to the fragment-bounds check.
    fn assert_u24_field_error(header: HandshakeHeader) {
        match header.validate() {
            Err(crate::Error::Crypto(message)) => assert!(
                message.contains("24-bit"),
                "expected the 24-bit field error, got: {message}"
            ),
            other => panic!("expected the 24-bit field error, got {other:?}"),
        }
    }

    let base = HandshakeHeader {
        message_type: HandshakeType::ClientHello,
        length: 10,
        message_seq: 0,
        fragment_offset: 0,
        fragment_length: 10,
    };
    assert!(base.validate().is_ok());

    assert_u24_field_error(HandshakeHeader {
        length: MAX_U24 + 1,
        ..base
    });
    assert_u24_field_error(HandshakeHeader {
        fragment_offset: MAX_U24 + 1,
        ..base
    });
    assert_u24_field_error(HandshakeHeader {
        fragment_length: MAX_U24 + 1,
        ..base
    });
}

#[test]
fn rejects_conflicting_handshake_overlap() {
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
    let conflict = HandshakeFragment {
        header: HandshakeHeader {
            message_type: HandshakeType::ClientHello,
            length: 4,
            message_seq: 0,
            fragment_offset: 1,
            fragment_length: 2,
        },
        fragment: b"XY".to_vec(),
    };

    let mut reassembler = HandshakeReassembler::default();
    assert!(reassembler.push(first).unwrap().is_none());
    assert!(reassembler.push(conflict).is_err());
}
