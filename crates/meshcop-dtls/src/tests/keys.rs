use super::*;

/// Golden vector: the TLS 1.2 PRF (P_SHA-256, RFC 5246 §5) against OpenSSL's
/// `TLS1-PRF` KDF. Provenance and regeneration: docs/VECTORS.md.
#[test]
fn tls12_prf_matches_openssl_tls1_prf_vector() {
    let secret = hex::decode("0102030405060708090a0b0c0d0e0f10").unwrap();
    let seed = hex::decode("1112131415161718191a1b1c1d1e1f20").unwrap();
    let actual = tls12_prf(&secret, b"label", &seed, 64).unwrap();
    let expected = hex::decode(concat!(
        "6f1e214164ea8f30cad635312e2af08967331da73926cecfc0f1307884aa7929",
        "74c5cc463d3293d5fad2a9dab2f58d6f667de184d266b32150fc21a0c464326d",
    ))
    .unwrap();

    assert_eq!(actual, expected);
}

/// Golden vector: the full key-schedule chain seeded by the mbedTLS EC J-PAKE
/// reference premaster secret (`crypto::ecjpake::tests`), with the master
/// secret and key block computed independently by OpenSSL 3.6.2
/// (`openssl kdf ... TLS1-PRF`) and the KEK by SHA-256 over that key block.
/// Provenance and regeneration commands: docs/VECTORS.md.
#[test]
fn key_schedule_chain_matches_openssl_tls1_prf_vectors() {
    let pre_master_secret =
        hex::decode("f3d47f599844db92a569bbe7981e39d931fd743bf22e98f9b438f719d3c4f351").unwrap();
    let client_random: [u8; 32] =
        hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap()
            .try_into()
            .unwrap();
    let server_random: [u8; 32] =
        hex::decode("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
            .unwrap()
            .try_into()
            .unwrap();

    let master_secret =
        derive_master_secret(&pre_master_secret, &client_random, &server_random).unwrap();
    assert_eq!(
        hex::encode(master_secret),
        concat!(
            "e5a288cfe36f82c04a92a820e8e0c768e1d48b9740c8d018f14d9a2b1f7f3e33",
            "30b1a741f2daf5d156144d8170befaa8",
        )
    );

    let key_block =
        derive_aes_128_ccm_8_key_block(&master_secret, &client_random, &server_random).unwrap();
    assert_eq!(
        hex::encode(key_block.client_write_key),
        "710b83fb8d70267ead91effdd7eb79fe"
    );
    assert_eq!(
        hex::encode(key_block.server_write_key),
        "bec55f8c6af131a377e62e471ca5a38c"
    );
    assert_eq!(hex::encode(key_block.client_write_iv), "da24a9d2");
    assert_eq!(hex::encode(key_block.server_write_iv), "95369b74");

    let kek = derive_joiner_router_kek(&master_secret, &client_random, &server_random).unwrap();
    assert_eq!(hex::encode(kek), "adf385fd8aa5cdbd6fe31939ce81d773");
}

/// Golden vector: one protected DTLS 1.2 application-data record, with the
/// AES-128-CCM-8 ciphertext computed independently by OpenSSL (via
/// pyca/cryptography `AESCCM(tag_length=8)`) over this crate's RFC 6655
/// nonce and additional-data layout. Provenance: docs/VECTORS.md.
#[test]
fn record_protection_matches_openssl_aes_ccm_8_vector() {
    let key = RecordProtectionKey::new(
        hex::decode("000102030405060708090a0b0c0d0e0f")
            .unwrap()
            .try_into()
            .unwrap(),
    );
    let fixed_iv: [u8; 4] = hex::decode("a0a1a2a3").unwrap().try_into().unwrap();
    let plaintext = b"thread interop golden vector";

    let record = protect_aes_128_ccm_8_record(
        ContentType::ApplicationData,
        1,
        7,
        key.clone(),
        &fixed_iv,
        plaintext,
    )
    .unwrap();

    // Explicit nonce (epoch || 48-bit sequence) followed by ciphertext + tag.
    assert_eq!(
        hex::encode(&record.payload),
        concat!(
            "0001000000000007",
            "29d63f60549b8fd72853642698a75d5c84d1f291ab3d5928389398364042583c86865c8f",
        )
    );
    assert_eq!(
        open_aes_128_ccm_8_record(&record, key, &fixed_iv).unwrap(),
        plaintext
    );
}

#[test]
fn derives_aes_128_ccm_8_key_block() {
    let pre_master_secret = [0x11; 32];
    let client_random = [0x22; 32];
    let server_random = [0x33; 32];
    let master_secret =
        derive_master_secret(&pre_master_secret, &client_random, &server_random).unwrap();
    let key_block =
        derive_aes_128_ccm_8_key_block(&master_secret, &client_random, &server_random).unwrap();

    assert_ne!(master_secret, [0; 48]);
    assert_ne!(key_block.client_write_key, key_block.server_write_key);
    assert_eq!(
        tls12_prf(
            &master_secret,
            b"key expansion",
            &[server_random, client_random].concat(),
            40,
        )
        .unwrap(),
        [
            key_block.client_write_key.as_slice(),
            key_block.server_write_key.as_slice(),
            key_block.client_write_iv.as_slice(),
            key_block.server_write_iv.as_slice(),
        ]
        .concat()
    );
}

#[test]
fn protects_and_opens_aes_128_ccm_8_records() {
    let key = RecordProtectionKey::new([0x44; 16]);
    let fixed_iv = [0x55; 4];
    let record = protect_aes_128_ccm_8_record(
        ContentType::ApplicationData,
        1,
        2,
        key.clone(),
        &fixed_iv,
        b"meshcop",
    )
    .unwrap();

    assert_eq!(record.header.epoch, 1);
    assert_eq!(record.header.sequence_number, 2);
    assert_eq!(&record.payload[..8], &[0, 1, 0, 0, 0, 0, 0, 2]);
    assert_eq!(
        open_aes_128_ccm_8_record(&record, key.clone(), &fixed_iv).unwrap(),
        b"meshcop"
    );

    let mut tampered = record;
    tampered.payload[8] ^= 0x01;
    assert!(open_aes_128_ccm_8_record(&tampered, key, &fixed_iv).is_err());
}

#[test]
fn meshcop_dtls_handshake_derives_key_material_from_ecjpake_messages() {
    let mut rng = OsRng;
    let pskc = [0x99; 16];
    let mut client = ThreadDtlsHandshake::new(&pskc, &mut rng);
    let server = EcJpakeParty::new_thread(EcJpakeRole::Server, &pskc, &mut rng);
    let server_one = server.round_one(&mut rng);

    let client_hello = ClientHello::thread_profile_with_ecjpake(
        client.client_random(),
        vec![0xaa],
        client.client_round_one().encode_tls_kkpp().unwrap(),
    );
    client
        .record_client_hello(&HandshakeMessage {
            message_type: HandshakeType::ClientHello,
            message_seq: 1,
            payload: client_hello.encode().unwrap(),
        })
        .unwrap();

    let mut server_random = [0u8; 32];
    server_random[0] = 0x33;
    let server_hello = ServerHello {
        random: server_random,
        session_id: Vec::new(),
        cipher_suite: TLS_ECJPAKE_WITH_AES_128_CCM_8,
        compression_method: TLS_COMPRESSION_NULL,
        extensions: vec![TlsExtension {
            extension_type: EXTENSION_ECJPAKE_KKPP,
            data: server_one.encode_tls_kkpp().unwrap(),
        }],
    };
    client
        .handle_server_hello(&HandshakeMessage {
            message_type: HandshakeType::ServerHello,
            message_seq: 1,
            payload: server_hello.encode().unwrap(),
        })
        .unwrap();

    let server_two = server
        .round_two(&server_one, client.client_round_one(), &mut rng)
        .unwrap();
    client
        .handle_server_key_exchange(&HandshakeMessage {
            message_type: HandshakeType::ServerKeyExchange,
            message_seq: 2,
            payload: server_two.encode_tls_key_exchange(true).unwrap(),
        })
        .unwrap();
    client
        .handle_server_hello_done(&HandshakeMessage {
            message_type: HandshakeType::ServerHelloDone,
            message_seq: 3,
            payload: Vec::new(),
        })
        .unwrap();
    let client_key_exchange = client.build_client_key_exchange(4, &mut rng).unwrap();
    let client_two = RoundTwo::decode_tls_key_exchange(
        &client_key_exchange.payload,
        crate::ecjpake::THREAD_CLIENT_ID,
        false,
    )
    .unwrap();
    let server_pre_master = server
        .finish(&server_one, client.client_round_one(), &client_two)
        .unwrap();
    let server_master =
        derive_master_secret(&server_pre_master, &client.client_random(), &server_random).unwrap();
    let client_key_material = client.derive_key_material().unwrap();

    assert_eq!(client_key_material.master_secret, server_master);
    assert!(client.transcript().as_bytes().len() > client_key_exchange.payload.len());

    // client_finished_verify_data must return the genuine transcript-derived
    // value, not a constant stub.
    let expected_client_finished = client
        .transcript()
        .finished_verify_data(&client_key_material.master_secret, FinishedRole::Client)
        .unwrap();
    assert_ne!(expected_client_finished, [0u8; 12]);
    assert_eq!(
        client.client_finished_verify_data().unwrap(),
        expected_client_finished
    );

    // verify_server_finished must accept the correct verify_data and reject
    // both tampered data and non-Finished messages.
    let expected_server_finished = client
        .transcript()
        .finished_verify_data(&client_key_material.master_secret, FinishedRole::Server)
        .unwrap();

    let mut tampered = expected_server_finished;
    tampered[0] ^= 0xff;
    assert!(
        client
            .verify_server_finished(
                &HandshakeMessage {
                    message_type: HandshakeType::Finished,
                    message_seq: 6,
                    payload: tampered.to_vec(),
                },
                &client_key_material,
            )
            .is_err()
    );

    assert!(
        client
            .verify_server_finished(
                &HandshakeMessage {
                    message_type: HandshakeType::ServerHelloDone,
                    message_seq: 6,
                    payload: expected_server_finished.to_vec(),
                },
                &client_key_material,
            )
            .is_err()
    );

    assert!(
        client
            .verify_server_finished(
                &HandshakeMessage {
                    message_type: HandshakeType::Finished,
                    message_seq: 6,
                    payload: expected_server_finished.to_vec(),
                },
                &client_key_material,
            )
            .is_ok()
    );
}

#[test]
fn handshake_record_steps_reject_wrong_message_types() {
    let mut rng = OsRng;
    let pskc = [0x77; 16];
    let mut client = ThreadDtlsHandshake::new(&pskc, &mut rng);

    assert!(
        client
            .record_client_hello(&HandshakeMessage {
                message_type: HandshakeType::ServerHello,
                message_seq: 0,
                payload: Vec::new(),
            })
            .is_err()
    );

    assert!(
        client
            .handle_server_hello(&HandshakeMessage {
                message_type: HandshakeType::ClientHello,
                message_seq: 0,
                payload: Vec::new(),
            })
            .is_err()
    );

    assert!(
        client
            .handle_server_key_exchange(&HandshakeMessage {
                message_type: HandshakeType::ClientHello,
                message_seq: 0,
                payload: Vec::new(),
            })
            .is_err()
    );

    // Wrong message type is rejected.
    assert!(
        client
            .handle_server_hello_done(&HandshakeMessage {
                message_type: HandshakeType::ClientHello,
                message_seq: 0,
                payload: Vec::new(),
            })
            .is_err()
    );

    // Correct type but a non-empty payload is rejected.
    assert!(
        client
            .handle_server_hello_done(&HandshakeMessage {
                message_type: HandshakeType::ServerHelloDone,
                message_seq: 0,
                payload: vec![0x00],
            })
            .is_err()
    );
}

/// Golden vector: the Finished `verify_data` (RFC 5246 §7.4.9) — PRF over this
/// crate's DTLS handshake transcript framing — against OpenSSL's `TLS1-PRF`.
/// Provenance and regeneration: docs/VECTORS.md.
#[test]
fn finished_verify_data_matches_openssl_tls1_prf_vector() {
    let mut transcript = HandshakeTranscript::new();
    transcript
        .push(&HandshakeMessage {
            message_type: HandshakeType::ClientHello,
            message_seq: 0,
            payload: b"abc".to_vec(),
        })
        .unwrap();
    let master_secret = [0x11; 48];
    let expected: [u8; 12] = hex::decode("6e0903525cefac795bc86d2e")
        .unwrap()
        .try_into()
        .unwrap();

    assert_eq!(
        transcript
            .finished_verify_data(&master_secret, FinishedRole::Client)
            .unwrap(),
        expected
    );
}

#[test]
fn derive_master_secret_uses_prf_with_master_secret_label() {
    let pre_master_secret = [0x11; 32];
    let client_random = [0x22; 32];
    let server_random = [0x33; 32];
    let expected = tls12_prf(
        &pre_master_secret,
        b"master secret",
        &[client_random, server_random].concat(),
        48,
    )
    .unwrap();

    let master_secret =
        derive_master_secret(&pre_master_secret, &client_random, &server_random).unwrap();
    assert_eq!(master_secret.as_slice(), expected.as_slice());
}
