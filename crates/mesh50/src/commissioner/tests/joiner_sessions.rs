use std::time::{Duration, Instant};

use rand_core::OsRng;

use super::super::joiner::{
    JOINER_SESSION_TIMEOUT, JoinerSession, JoinerSessionEvent, parse_join_fin,
};
use super::*;
use crate::meshcop::{
    TLV_PROVISIONING_URL, TLV_VENDOR_MODEL, TLV_VENDOR_NAME, TLV_VENDOR_STACK_VERSION,
    TLV_VENDOR_SW_VERSION,
};
use mesh50_dtls::{
    ContentType, DtlsRecord, HandshakeType, RecordProtectionKey, ServerHello, ThreadDtlsHandshake,
    ThreadDtlsKeyMaterial, derive_joiner_router_kek, open_aes_128_ccm_8_record,
    parse_unfragmented_handshake_messages, parse_unfragmented_handshake_record,
    protect_aes_128_ccm_8_record,
};

const JOINER_IID: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
const PSKD: &str = "J01NME";

#[derive(Debug, Default)]
struct RecordingHandler {
    pskd: Option<String>,
    accept: bool,
    connected: Vec<[u8; 8]>,
    finalized: Vec<([u8; 8], JoinerFinalizeInfo)>,
}

impl JoinerHandler for RecordingHandler {
    fn joiner_pskd(&mut self, _joiner_id: &[u8; 8]) -> Option<String> {
        self.pskd.clone()
    }

    fn on_joiner_connected(&mut self, joiner_id: &[u8; 8]) {
        self.connected.push(*joiner_id);
    }

    fn on_joiner_finalize(&mut self, joiner_id: &[u8; 8], info: &JoinerFinalizeInfo) -> bool {
        self.finalized.push((*joiner_id, info.clone()));
        self.accept
    }
}

fn join_fin_payload() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&[crate::meshcop::TLV_STATE, 1, 0x01]);
    payload.extend_from_slice(&[TLV_VENDOR_NAME, 4]);
    payload.extend_from_slice(b"Acme");
    payload.extend_from_slice(&[TLV_VENDOR_MODEL, 6]);
    payload.extend_from_slice(b"Widget");
    payload.extend_from_slice(&[TLV_VENDOR_SW_VERSION, 3]);
    payload.extend_from_slice(b"1.0");
    payload.extend_from_slice(&[TLV_VENDOR_STACK_VERSION, 6, 0, 0, 0x2a, 1, 2, 3]);
    payload.extend_from_slice(&[TLV_PROVISIONING_URL, 11]);
    payload.extend_from_slice(b"example.com");
    payload
}

/// Drives a fake joiner (the production DTLS client state machine) through
/// a complete commissioning session and returns the pieces a JOIN_FIN
/// exchange needs.
struct CommissionedJoiner {
    session: JoinerSession,
    handler: RecordingHandler,
    joiner_keys: ThreadDtlsKeyMaterial,
    server_random: [u8; 32],
    client_random: [u8; 32],
}

fn commission_fake_joiner(accept: bool) -> CommissionedJoiner {
    let mut rng = OsRng;
    let mut handler = RecordingHandler {
        pskd: Some(PSKD.to_string()),
        accept,
        ..RecordingHandler::default()
    };
    let mut session = JoinerSession::new(JOINER_IID, 1000, 0x6800, PSKD, Instant::now(), &mut rng);
    let mut joiner = ThreadDtlsHandshake::new(PSKD.as_bytes(), &mut rng);
    let mut hello_state = joiner.client_hello_state().unwrap();

    // First ClientHello: answered by a HelloVerifyRequest.
    let first_hello = hello_state.next_client_hello_record().unwrap();
    let events = session
        .receive(&first_hello.encode().unwrap(), &mut handler, &mut rng)
        .unwrap();
    let [
        JoinerSessionEvent::Transmit {
            datagram,
            include_kek: false,
        },
    ] = events.as_slice()
    else {
        panic!("expected one HelloVerifyRequest transmission, got {events:?}");
    };
    let records = DtlsRecord::parse_datagram(datagram).unwrap();
    hello_state
        .handle_hello_verify_request(&records[0])
        .unwrap();

    // Cookie-bearing ClientHello: answered by the server flight.
    let second_hello = hello_state.next_client_hello_record().unwrap();
    let second_hello_message =
        parse_unfragmented_handshake_record(&second_hello, HandshakeType::ClientHello).unwrap();
    joiner.record_client_hello(&second_hello_message).unwrap();
    let events = session
        .receive(&second_hello.encode().unwrap(), &mut handler, &mut rng)
        .unwrap();
    let [
        JoinerSessionEvent::Transmit {
            datagram,
            include_kek: false,
        },
    ] = events.as_slice()
    else {
        panic!("expected the server flight, got {events:?}");
    };
    let mut server_random = [0u8; 32];
    for record in DtlsRecord::parse_datagram(datagram).unwrap() {
        for message in parse_unfragmented_handshake_messages(&record).unwrap() {
            match message.message_type {
                HandshakeType::ServerHello => {
                    server_random = ServerHello::decode(&message.payload).unwrap().random;
                    joiner.handle_server_hello(&message).unwrap();
                }
                HandshakeType::ServerKeyExchange => {
                    joiner.handle_server_key_exchange(&message).unwrap();
                }
                HandshakeType::ServerHelloDone => {
                    joiner.handle_server_hello_done(&message).unwrap();
                }
                other => panic!("unexpected server flight message {other:?}"),
            }
        }
    }

    // Client flight: ClientKeyExchange, ChangeCipherSpec, Finished.
    let key_exchange_seq = hello_state.next_message_sequence();
    let key_exchange = joiner
        .build_client_key_exchange(key_exchange_seq, &mut rng)
        .unwrap();
    let joiner_keys = joiner.derive_key_material().unwrap();
    let finished = joiner
        .build_client_finished(key_exchange_seq.wrapping_add(1))
        .unwrap();
    let epoch0 = hello_state.next_record_sequence();
    let mut datagram = DtlsRecord::new(
        ContentType::Handshake,
        0,
        epoch0,
        key_exchange.encode().unwrap(),
    )
    .unwrap()
    .encode()
    .unwrap();
    datagram.extend_from_slice(
        &DtlsRecord::new(
            ContentType::ChangeCipherSpec,
            0,
            epoch0.wrapping_add(1),
            vec![1],
        )
        .unwrap()
        .encode()
        .unwrap(),
    );
    datagram.extend_from_slice(
        &protect_aes_128_ccm_8_record(
            ContentType::Handshake,
            1,
            0,
            RecordProtectionKey::new(joiner_keys.key_block.client_write_key),
            &joiner_keys.key_block.client_write_iv,
            &finished.encode().unwrap(),
        )
        .unwrap()
        .encode()
        .unwrap(),
    );
    let events = session.receive(&datagram, &mut handler, &mut rng).unwrap();
    let [
        JoinerSessionEvent::Transmit {
            datagram,
            include_kek: false,
        },
        JoinerSessionEvent::Connected,
    ] = events.as_slice()
    else {
        panic!("expected the Finished flight and a Connected event, got {events:?}");
    };
    assert_eq!(handler.connected, Vec::<[u8; 8]>::new());

    // The joiner verifies the server's ChangeCipherSpec + Finished.
    let records = DtlsRecord::parse_datagram(datagram).unwrap();
    assert_eq!(
        records[0].header.content_type,
        ContentType::ChangeCipherSpec
    );
    let plaintext = open_aes_128_ccm_8_record(
        &records[1],
        RecordProtectionKey::new(joiner_keys.key_block.server_write_key),
        &joiner_keys.key_block.server_write_iv,
    )
    .unwrap();
    let plain_record = DtlsRecord::new(ContentType::Handshake, 1, 0, plaintext).unwrap();
    let server_finished =
        parse_unfragmented_handshake_record(&plain_record, HandshakeType::Finished).unwrap();
    joiner
        .verify_server_finished(&server_finished, &joiner_keys)
        .unwrap();

    CommissionedJoiner {
        session,
        handler,
        client_random: joiner.client_random(),
        joiner_keys,
        server_random,
    }
}

fn encrypted_join_fin(joiner: &CommissionedJoiner, message_id: u16) -> Vec<u8> {
    let mut request = CoapMessage {
        ty: CoapType::Confirmable,
        code: CoapCode::POST,
        message_id,
        token: vec![0x77],
        options: Vec::new(),
        payload: join_fin_payload(),
    };
    request.set_uri_path(crate::meshcop::uri::JOIN_FIN).unwrap();
    protect_aes_128_ccm_8_record(
        ContentType::ApplicationData,
        1,
        u64::from(message_id),
        RecordProtectionKey::new(joiner.joiner_keys.key_block.client_write_key),
        &joiner.joiner_keys.key_block.client_write_iv,
        &request.encode().unwrap(),
    )
    .unwrap()
    .encode()
    .unwrap()
}

fn decrypt_join_fin_response(joiner: &CommissionedJoiner, datagram: &[u8]) -> CoapMessage {
    let records = DtlsRecord::parse_datagram(datagram).unwrap();
    let plaintext = open_aes_128_ccm_8_record(
        &records[0],
        RecordProtectionKey::new(joiner.joiner_keys.key_block.server_write_key),
        &joiner.joiner_keys.key_block.server_write_iv,
    )
    .unwrap();
    CoapMessage::decode(&plaintext).unwrap()
}

#[test]
fn joiner_session_commissions_and_entrusts_an_accepted_joiner() {
    let mut joiner = commission_fake_joiner(true);
    let expected_joiner_id = {
        let mut id = JOINER_IID;
        id[0] ^= 0x02;
        id
    };
    assert_eq!(joiner.session.joiner_id(), expected_joiner_id);
    assert_eq!(joiner_id_from_iid(&JOINER_IID), expected_joiner_id);

    let datagram = encrypted_join_fin(&joiner, 7);
    let events = joiner
        .session
        .receive(&datagram, &mut joiner.handler, &mut OsRng)
        .unwrap();
    let [
        JoinerSessionEvent::Transmit {
            datagram,
            include_kek: true,
        },
        JoinerSessionEvent::Finalized {
            accepted: true,
            info,
        },
    ] = events.as_slice()
    else {
        panic!("expected an entrusting JOIN_FIN.rsp, got {events:?}");
    };
    assert_eq!(info.vendor_name, "Acme");
    assert_eq!(info.vendor_model, "Widget");
    assert_eq!(info.vendor_sw_version, "1.0");
    assert_eq!(info.vendor_stack_version, [0, 0, 0x2a, 1, 2, 3]);
    assert_eq!(info.provisioning_url.as_deref(), Some("example.com"));
    assert_eq!(info.vendor_data, None);
    assert_eq!(joiner.handler.finalized.len(), 1);

    let response = decrypt_join_fin_response(&joiner, datagram);
    assert_eq!(response.ty, CoapType::Acknowledgement);
    assert_eq!(response.code, CoapCode::CHANGED);
    assert_eq!(response.message_id, 7);
    assert_eq!(response.token, [0x77]);
    assert_eq!(response.payload, [TLV_STATE, 1, 0x01]);

    // Both ends derive the same Joiner Router KEK.
    let session_kek = joiner.session.joiner_router_kek().unwrap();
    let joiner_kek = derive_joiner_router_kek(
        &joiner.joiner_keys.master_secret,
        &joiner.client_random,
        &joiner.server_random,
    )
    .unwrap();
    assert_eq!(session_kek, joiner_kek);

    // A retransmitted JOIN_FIN.req is answered with the same decision but
    // does not re-finalize.
    let retransmission = encrypted_join_fin(&joiner, 8);
    let events = joiner
        .session
        .receive(&retransmission, &mut joiner.handler, &mut OsRng)
        .unwrap();
    assert!(matches!(
        events.as_slice(),
        [JoinerSessionEvent::Transmit {
            include_kek: true,
            ..
        }]
    ));
    assert_eq!(joiner.handler.finalized.len(), 1);
}

#[test]
fn joiner_session_rejects_a_denied_joiner_without_the_kek() {
    let mut joiner = commission_fake_joiner(false);
    let datagram = encrypted_join_fin(&joiner, 9);
    let events = joiner
        .session
        .receive(&datagram, &mut joiner.handler, &mut OsRng)
        .unwrap();
    let [
        JoinerSessionEvent::Transmit {
            datagram,
            include_kek: false,
        },
        JoinerSessionEvent::Finalized {
            accepted: false, ..
        },
    ] = events.as_slice()
    else {
        panic!("expected a rejecting JOIN_FIN.rsp without the KEK, got {events:?}");
    };
    let response = decrypt_join_fin_response(&joiner, datagram);
    assert_eq!(response.payload, [TLV_STATE, 1, 0xff]);
}

#[test]
fn joiner_session_timeout_matches_the_reference_deadline() {
    assert_eq!(JOINER_SESSION_TIMEOUT, Duration::from_secs(80));
}

#[test]
fn retransmitted_client_hello_repeats_the_server_flight() {
    let mut rng = OsRng;
    let mut handler = RecordingHandler {
        pskd: Some(PSKD.to_string()),
        accept: true,
        ..RecordingHandler::default()
    };
    let mut session = JoinerSession::new(JOINER_IID, 1000, 0x6800, PSKD, Instant::now(), &mut rng);
    let joiner = ThreadDtlsHandshake::new(PSKD.as_bytes(), &mut rng);
    let mut hello_state = joiner.client_hello_state().unwrap();

    let first_hello = hello_state.next_client_hello_record().unwrap();
    let events = session
        .receive(&first_hello.encode().unwrap(), &mut handler, &mut rng)
        .unwrap();
    let [JoinerSessionEvent::Transmit { datagram, .. }] = events.as_slice() else {
        panic!("expected a HelloVerifyRequest");
    };
    let records = DtlsRecord::parse_datagram(datagram).unwrap();
    hello_state
        .handle_hello_verify_request(&records[0])
        .unwrap();

    let second_hello = hello_state
        .next_client_hello_record()
        .unwrap()
        .encode()
        .unwrap();
    let events = session
        .receive(&second_hello, &mut handler, &mut rng)
        .unwrap();
    let [
        JoinerSessionEvent::Transmit {
            datagram: flight, ..
        },
    ] = events.as_slice()
    else {
        panic!("expected the server flight");
    };
    let flight = flight.clone();

    // If the flight is lost, the joiner retransmits its hello and must
    // receive the identical flight again.
    let events = session
        .receive(&second_hello, &mut handler, &mut rng)
        .unwrap();
    let [
        JoinerSessionEvent::Transmit {
            datagram: repeated, ..
        },
    ] = events.as_slice()
    else {
        panic!("expected the repeated server flight");
    };
    assert_eq!(*repeated, flight);
}

#[test]
fn joiner_sessions_expire_and_reject_malformed_traffic() {
    let mut rng = OsRng;
    let now = Instant::now();
    let mut session = JoinerSession::new(JOINER_IID, 1000, 0x6800, PSKD, now, &mut rng);
    assert!(!session.expired(now));
    assert!(session.expired(now + JOINER_SESSION_TIMEOUT));
    assert!(session.expired(now + JOINER_SESSION_TIMEOUT + Duration::from_secs(1)));

    let mut handler = RecordingHandler {
        pskd: Some(PSKD.to_string()),
        accept: true,
        ..RecordingHandler::default()
    };
    // Garbage bytes are not a DTLS record.
    assert!(
        session
            .receive(&[0xff, 0x00], &mut handler, &mut rng)
            .is_err()
    );
    // Application data before the handshake completes is rejected.
    let early = DtlsRecord::new(ContentType::ApplicationData, 1, 0, vec![0; 24])
        .unwrap()
        .encode()
        .unwrap();
    assert!(session.receive(&early, &mut handler, &mut rng).is_err());
    // Alerts tear the session down.
    let alert = DtlsRecord::new(ContentType::Alert, 0, 0, vec![2, 40])
        .unwrap()
        .encode()
        .unwrap();
    assert!(session.receive(&alert, &mut handler, &mut rng).is_err());
}

#[test]
fn join_fin_parser_requires_vendor_identification() {
    let mut request = CoapMessage {
        ty: CoapType::Confirmable,
        code: CoapCode::POST,
        message_id: 1,
        token: vec![0x01],
        options: Vec::new(),
        payload: join_fin_payload(),
    };
    request.set_uri_path(crate::meshcop::uri::JOIN_FIN).unwrap();
    let info = parse_join_fin(&request).unwrap();
    assert_eq!(info.vendor_name, "Acme");

    for missing in [
        crate::meshcop::TLV_STATE,
        TLV_VENDOR_NAME,
        TLV_VENDOR_MODEL,
        TLV_VENDOR_SW_VERSION,
        TLV_VENDOR_STACK_VERSION,
    ] {
        let mut altered = Dataset::from_bytes(&join_fin_payload()).unwrap();
        altered.remove_all(missing);
        let mut request = request.clone();
        request.payload = altered.to_bytes().unwrap();
        assert!(parse_join_fin(&request).is_err(), "missing TLV {missing}");
    }
}

#[test]
fn static_joiner_handler_matches_ids_and_wildcards() {
    let mut handler = StaticJoinerHandler::new();
    let joiner_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
    assert_eq!(handler.joiner_pskd(&joiner_id), None);

    handler.enable_joiner_id(joiner_id, "ABCDE1");
    assert_eq!(handler.joiner_pskd(&joiner_id).as_deref(), Some("ABCDE1"));
    assert_eq!(handler.joiner_pskd(&[9u8; 8]), None);

    handler.enable_all("WILDCD");
    assert_eq!(handler.joiner_pskd(&joiner_id).as_deref(), Some("ABCDE1"));
    assert_eq!(handler.joiner_pskd(&[9u8; 8]).as_deref(), Some("WILDCD"));

    handler.disable_joiner_id(&joiner_id);
    assert_eq!(handler.joiner_pskd(&joiner_id).as_deref(), Some("WILDCD"));
    handler.disable_all();
    assert_eq!(handler.joiner_pskd(&joiner_id), None);

    // EUI-64 enablement goes through the joiner-ID derivation.
    let mut by_eui = StaticJoinerHandler::new();
    by_eui.enable_eui64(0x0011_2233_4455_6677, "EUIPSK");
    let derived = crate::crypto::compute_joiner_id(0x0011_2233_4455_6677);
    assert_eq!(by_eui.joiner_pskd(&derived).as_deref(), Some("EUIPSK"));
}

#[tokio::test]
async fn commissioner_routes_relay_rx_into_joiner_sessions() {
    let mut rng = OsRng;
    let joiner = ThreadDtlsHandshake::new(PSKD.as_bytes(), &mut rng);
    let mut hello_state = joiner.client_hello_state().unwrap();
    let client_hello = hello_state.next_client_hello_record().unwrap();
    let relay_rx = relay_rx_message(&JOINER_IID, &client_hello.encode().unwrap());

    let script = ScriptedMeshcopTransport::new([
        exchange(
            CommissionerOperation::Petition,
            [ScriptedResponse::petition_accept(0x1234)],
        ),
        exchange(
            CommissionerOperation::GetActiveDataset,
            [
                ScriptedResponse::Raw(relay_rx),
                ScriptedResponse::content(dataset_with_name("after").to_bytes().unwrap()),
            ],
        ),
    ]);
    let mut commissioner = scripted_commissioner(script, []).await;
    let mut handler = StaticJoinerHandler::new();
    handler.enable_all(PSKD);
    commissioner.set_joiner_handler(handler);
    commissioner.petition().await.unwrap();
    commissioner
        .get_active_dataset(DatasetFlags::NETWORK_NAME)
        .await
        .unwrap();

    // The HelloVerifyRequest must have been relayed back via RLY_TX.
    let harness = commissioner.scripted_transport().unwrap();
    let relay_tx = harness
        .sent_messages()
        .iter()
        .find(|message| {
            message.uri_path().unwrap().as_deref() == Some(crate::meshcop::uri::RELAY_TX)
        })
        .expect("no RLY_TX was sent for the joiner");
    assert_eq!(
        tlv_value(relay_tx, TLV_JOINER_IID),
        Some(JOINER_IID.to_vec())
    );
    assert_eq!(
        tlv_value(relay_tx, TLV_JOINER_UDP_PORT),
        Some(1000u16.to_be_bytes().to_vec())
    );
    assert_eq!(
        tlv_value(relay_tx, crate::meshcop::TLV_JOINER_ROUTER_LOCATOR),
        Some(0x6800u16.to_be_bytes().to_vec())
    );
    assert_eq!(
        tlv_value(relay_tx, crate::meshcop::TLV_JOINER_ROUTER_KEK),
        None
    );
    let encapsulated = tlv_value(relay_tx, TLV_JOINER_DTLS_ENCAPSULATION).unwrap();
    let records = DtlsRecord::parse_datagram(&encapsulated).unwrap();
    parse_unfragmented_handshake_record(&records[0], HandshakeType::HelloVerifyRequest).unwrap();

    // No raw joiner event is surfaced while a handler drives sessions.
    assert!(matches!(
        commissioner.next_event().await.unwrap_err(),
        Error::InvalidState("DTLS session is not established")
    ));
}

#[tokio::test]
async fn joiner_session_survives_the_expiry_sweep_between_relay_messages() {
    let mut rng = OsRng;
    let joiner = ThreadDtlsHandshake::new(PSKD.as_bytes(), &mut rng);
    let mut hello_state = joiner.client_hello_state().unwrap();
    let client_hello = hello_state
        .next_client_hello_record()
        .unwrap()
        .encode()
        .unwrap();

    // The same cookie-less ClientHello arrives twice; the expiry sweep that
    // runs on every relay message must keep the live session in between.
    let script = ScriptedMeshcopTransport::new([
        exchange(
            CommissionerOperation::Petition,
            [ScriptedResponse::petition_accept(0x1234)],
        ),
        exchange(
            CommissionerOperation::GetActiveDataset,
            [
                ScriptedResponse::Raw(relay_rx_message(&JOINER_IID, &client_hello)),
                ScriptedResponse::Raw(relay_rx_message(&JOINER_IID, &client_hello)),
                ScriptedResponse::content(dataset_with_name("after").to_bytes().unwrap()),
            ],
        ),
    ]);
    let mut commissioner = scripted_commissioner(script, []).await;
    let mut handler = StaticJoinerHandler::new();
    handler.enable_all(PSKD);
    commissioner.set_joiner_handler(handler);
    commissioner.petition().await.unwrap();
    commissioner
        .get_active_dataset(DatasetFlags::NETWORK_NAME)
        .await
        .unwrap();

    let harness = commissioner.scripted_transport().unwrap();
    let hello_verifies: Vec<(u64, Vec<u8>)> = harness
        .sent_messages()
        .iter()
        .filter(|message| {
            message.uri_path().unwrap().as_deref() == Some(crate::meshcop::uri::RELAY_TX)
        })
        .map(|relay_tx| {
            let encapsulated = tlv_value(relay_tx, TLV_JOINER_DTLS_ENCAPSULATION).unwrap();
            let records = DtlsRecord::parse_datagram(&encapsulated).unwrap();
            let message =
                parse_unfragmented_handshake_record(&records[0], HandshakeType::HelloVerifyRequest)
                    .unwrap();
            // HelloVerifyRequest body: 2-byte server version, 1-byte cookie
            // length, cookie.
            let cookie = message.payload[3..3 + message.payload[2] as usize].to_vec();
            (records[0].header.sequence_number, cookie)
        })
        .collect();

    // A persistent session keeps counting epoch-0 record sequence numbers and
    // keeps its per-session cookie key; a session recreated between the two
    // messages would restart at sequence zero with a fresh key.
    let [(first_seq, first_cookie), (second_seq, second_cookie)] = hello_verifies.as_slice() else {
        panic!(
            "expected two relayed HelloVerifyRequests, got {}",
            hello_verifies.len()
        );
    };
    assert_eq!(*first_seq, 0);
    assert_eq!(*second_seq, 1);
    assert_eq!(first_cookie, second_cookie);
}

#[tokio::test]
async fn commissioner_ignores_disabled_joiners_and_keeps_legacy_events() {
    let mut rng = OsRng;
    let joiner = ThreadDtlsHandshake::new(PSKD.as_bytes(), &mut rng);
    let mut hello_state = joiner.client_hello_state().unwrap();
    let client_hello = hello_state
        .next_client_hello_record()
        .unwrap()
        .encode()
        .unwrap();

    // A handler that knows no PSKd ignores the joiner entirely.
    let script = ScriptedMeshcopTransport::new([
        exchange(
            CommissionerOperation::Petition,
            [ScriptedResponse::petition_accept(0x1234)],
        ),
        exchange(
            CommissionerOperation::GetActiveDataset,
            [
                ScriptedResponse::Raw(relay_rx_message(&JOINER_IID, &client_hello)),
                ScriptedResponse::content(dataset_with_name("after").to_bytes().unwrap()),
            ],
        ),
    ]);
    let mut commissioner = scripted_commissioner(script, []).await;
    commissioner.set_joiner_handler(StaticJoinerHandler::new());
    commissioner.petition().await.unwrap();
    commissioner
        .get_active_dataset(DatasetFlags::NETWORK_NAME)
        .await
        .unwrap();
    assert!(
        commissioner
            .scripted_transport()
            .unwrap()
            .sent_messages()
            .is_empty()
    );

    // Without any handler, the raw relay payload surfaces as an event.
    let script = ScriptedMeshcopTransport::new([
        exchange(
            CommissionerOperation::Petition,
            [ScriptedResponse::petition_accept(0x1234)],
        ),
        exchange(
            CommissionerOperation::GetActiveDataset,
            [
                ScriptedResponse::Raw(relay_rx_message(&JOINER_IID, &client_hello)),
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
    assert_eq!(
        commissioner.next_event().await.unwrap(),
        Some(CommissionerEvent::JoinerMessage {
            joiner_id: JOINER_IID.to_vec(),
            port: 1000,
            payload: client_hello.clone(),
        })
    );
}

pub(super) fn relay_rx_message(joiner_iid: &[u8; 8], encapsulated: &[u8]) -> CoapMessage {
    let mut payload = Vec::new();
    payload.extend_from_slice(&[TLV_JOINER_UDP_PORT, 2]);
    payload.extend_from_slice(&1000u16.to_be_bytes());
    payload.extend_from_slice(&[crate::meshcop::TLV_JOINER_ROUTER_LOCATOR, 2]);
    payload.extend_from_slice(&0x6800u16.to_be_bytes());
    payload.extend_from_slice(&[TLV_JOINER_IID, 8]);
    payload.extend_from_slice(joiner_iid);
    // The encapsulation can exceed 255 bytes, so use the real encoder for
    // its extended-length form.
    crate::tlv::TlvEntry::new(TLV_JOINER_DTLS_ENCAPSULATION, encapsulated)
        .encode(&mut payload)
        .unwrap();
    CoapMessage::post_request(
        CoapType::NonConfirmable,
        0x5050,
        Vec::new(),
        crate::meshcop::uri::RELAY_RX,
        payload,
    )
    .unwrap()
}
