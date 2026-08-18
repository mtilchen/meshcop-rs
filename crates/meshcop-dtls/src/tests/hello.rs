use super::*;

#[test]
fn thread_client_hello_round_trip() {
    let mut random = [0u8; 32];
    random[0] = 0x42;
    let client_hello = ClientHello::thread_profile(random, vec![1, 2, 3, 4]);
    let encoded = client_hello.encode().unwrap();
    let decoded = ClientHello::decode(&encoded).unwrap();

    assert_eq!(decoded, client_hello);
    assert_eq!(
        decoded.cipher_suites,
        vec![
            TLS_ECJPAKE_WITH_AES_128_CCM_8,
            TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
        ]
    );
    assert_eq!(decoded.compression_methods, vec![TLS_COMPRESSION_NULL]);
    assert!(decoded.extensions.iter().any(|extension| {
        extension.extension_type == EXTENSION_SUPPORTED_GROUPS
            && extension.data == [0, 2, 0, NAMED_GROUP_SECP256R1 as u8]
    }));
    assert!(decoded.extensions.iter().any(|extension| {
        extension.extension_type == EXTENSION_EC_POINT_FORMATS
            && extension.data == [1, EC_POINT_FORMAT_UNCOMPRESSED]
    }));
}

#[test]
fn client_hello_carries_ecjpake_kkpp_extension() {
    let mut random = [0u8; 32];
    random[0] = 0x24;
    let kkpp = vec![0x41, 0x04, 0xaa];
    let client_hello = ClientHello::thread_profile_with_ecjpake(random, Vec::new(), kkpp.clone());
    let decoded = ClientHello::decode(&client_hello.encode().unwrap()).unwrap();

    assert_eq!(decoded.ecjpake_kkpp(), Some(kkpp.as_slice()));
    assert_eq!(
        decoded
            .extensions
            .iter()
            .filter(|extension| extension.extension_type == EXTENSION_ECJPAKE_KKPP)
            .count(),
        1
    );

    let mut replaced = decoded;
    replaced.set_ecjpake_kkpp(vec![0xbb]);
    assert_eq!(replaced.ecjpake_kkpp(), Some([0xbb].as_slice()));
    assert_eq!(
        replaced
            .extensions
            .iter()
            .filter(|extension| extension.extension_type == EXTENSION_ECJPAKE_KKPP)
            .count(),
        1
    );
}

#[test]
fn hello_verify_request_round_trip() {
    let hello_verify = HelloVerifyRequest {
        server_version: DTLS_1_2_VERSION,
        cookie: vec![0xde, 0xad, 0xbe, 0xef],
    };

    assert_eq!(
        HelloVerifyRequest::decode(&hello_verify.encode().unwrap()).unwrap(),
        hello_verify
    );
}

#[test]
fn server_hello_round_trip() {
    let mut random = [0u8; 32];
    random[31] = 0x24;
    let server_hello = ServerHello {
        random,
        session_id: vec![1, 2],
        cipher_suite: TLS_ECJPAKE_WITH_AES_128_CCM_8,
        compression_method: TLS_COMPRESSION_NULL,
        extensions: vec![ec_point_formats_extension()],
    };

    assert_eq!(
        ServerHello::decode(&server_hello.encode().unwrap()).unwrap(),
        server_hello
    );
}

#[test]
fn client_hello_rejects_malformed_vectors() {
    let mut bytes = ClientHello::thread_profile([0u8; 32], Vec::new())
        .encode()
        .unwrap();
    let cipher_suite_len_offset = 2 + 32 + 1 + 1;
    bytes[cipher_suite_len_offset] = 0;
    bytes[cipher_suite_len_offset + 1] = 1;

    assert!(ClientHello::decode(&bytes).is_err());
}

#[test]
fn client_hello_state_handles_cookie_retry() {
    let random = [0x42; 32];
    let kkpp = vec![0x41, 0x04, 0xaa];
    let mut state = DtlsClientHelloState::with_ecjpake_kkpp(random, kkpp.clone());

    let first = state.next_client_hello_record().unwrap();
    assert_eq!(first.header.sequence_number, 0);
    let first_handshake =
        parse_unfragmented_handshake_record(&first, HandshakeType::ClientHello).unwrap();
    assert_eq!(first_handshake.message_seq, 0);
    let first_hello = ClientHello::decode(&first_handshake.payload).unwrap();
    assert_eq!(first_hello.random, random);
    assert!(first_hello.cookie.is_empty());
    assert_eq!(first_hello.ecjpake_kkpp(), Some(kkpp.as_slice()));

    let hello_verify = HelloVerifyRequest {
        server_version: DTLS_1_2_VERSION,
        cookie: vec![0xaa, 0xbb],
    };
    let hello_verify_record = DtlsRecord::new(
        ContentType::Handshake,
        0,
        0,
        HandshakeMessage {
            message_type: HandshakeType::HelloVerifyRequest,
            message_seq: 0,
            payload: hello_verify.encode().unwrap(),
        }
        .encode()
        .unwrap(),
    )
    .unwrap();

    assert_eq!(
        state
            .handle_hello_verify_request(&hello_verify_record)
            .unwrap(),
        hello_verify
    );
    assert_eq!(state.cookie(), &[0xaa, 0xbb]);

    let second = state.next_client_hello_record().unwrap();
    assert_eq!(second.header.sequence_number, 1);
    let second_handshake =
        parse_unfragmented_handshake_record(&second, HandshakeType::ClientHello).unwrap();
    assert_eq!(second_handshake.message_seq, 1);
    let second_hello = ClientHello::decode(&second_handshake.payload).unwrap();
    assert_eq!(second_hello.random, random);
    assert_eq!(second_hello.cookie, vec![0xaa, 0xbb]);
    assert_eq!(second_hello.ecjpake_kkpp(), Some(kkpp.as_slice()));
    assert_eq!(second_hello.cipher_suites, first_hello.cipher_suites);
    assert_eq!(
        second_hello.compression_methods,
        first_hello.compression_methods
    );
}

#[test]
fn client_hello_state_rejects_wrong_hello_verify_sequence() {
    let mut state = DtlsClientHelloState::new([0; 32]);
    let _first = state.next_client_hello_record().unwrap();
    let hello_verify_record = DtlsRecord::new(
        ContentType::Handshake,
        0,
        0,
        HandshakeMessage {
            message_type: HandshakeType::HelloVerifyRequest,
            message_seq: 7,
            payload: HelloVerifyRequest {
                server_version: DTLS_1_2_VERSION,
                cookie: vec![1],
            }
            .encode()
            .unwrap(),
        }
        .encode()
        .unwrap(),
    )
    .unwrap();

    assert!(
        state
            .handle_hello_verify_request(&hello_verify_record)
            .is_err()
    );
}
