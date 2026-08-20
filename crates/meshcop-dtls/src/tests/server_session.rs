use super::*;
use std::sync::{Arc, Mutex};

#[test]
fn server_handshake_completes_against_client_and_derives_matching_kek() {
    let mut rng = OsRng;
    let pskd = b"J01NME";
    let mut client = ThreadDtlsHandshake::new(pskd, &mut rng);
    let mut server = ThreadDtlsServerHandshake::new(pskd, &mut rng);
    let cookies = DtlsCookieGenerator::new(&mut rng);

    // Cookie exchange: the first ClientHello is met with a HelloVerifyRequest
    // and neither message enters the transcript.
    let mut hello_state = client.client_hello_state().unwrap();
    let first_record = hello_state.next_client_hello_record().unwrap();
    let first =
        parse_unfragmented_handshake_record(&first_record, HandshakeType::ClientHello).unwrap();
    let first_hello = ClientHello::decode(&first.payload).unwrap();
    assert!(first_hello.cookie.is_empty());
    let cookie = cookies.cookie(&first_hello.random).unwrap();
    assert!(cookies.verify(&first_hello.random, &cookie));
    assert!(!cookies.verify(&first_hello.random, &[0u8; DTLS_COOKIE_LEN]));

    let hello_verify = HandshakeMessage {
        message_type: HandshakeType::HelloVerifyRequest,
        message_seq: first.message_seq,
        payload: HelloVerifyRequest {
            server_version: DTLS_1_2_VERSION,
            cookie: cookie.to_vec(),
        }
        .encode()
        .unwrap(),
    };
    let hello_verify_record =
        DtlsRecord::new(ContentType::Handshake, 0, 0, hello_verify.encode().unwrap()).unwrap();
    hello_state
        .handle_hello_verify_request(&hello_verify_record)
        .unwrap();

    let second_record = hello_state.next_client_hello_record().unwrap();
    let second =
        parse_unfragmented_handshake_record(&second_record, HandshakeType::ClientHello).unwrap();
    client.record_client_hello(&second).unwrap();
    let accepted = server.handle_client_hello(&second).unwrap();
    assert!(cookies.verify(&accepted.random, &accepted.cookie));
    assert_eq!(server.client_random(), Some(accepted.random));

    // Server flight.
    let server_hello = server.build_server_hello(1).unwrap();
    client.handle_server_hello(&server_hello).unwrap();
    let server_key_exchange = server.build_server_key_exchange(2, &mut rng).unwrap();
    client
        .handle_server_key_exchange(&server_key_exchange)
        .unwrap();
    let server_hello_done = server.build_server_hello_done(3).unwrap();
    client.handle_server_hello_done(&server_hello_done).unwrap();

    // Client flight.
    let client_key_exchange = client.build_client_key_exchange(2, &mut rng).unwrap();
    server
        .handle_client_key_exchange(&client_key_exchange)
        .unwrap();

    let client_keys = client.derive_key_material().unwrap();
    let server_keys = server.derive_key_material().unwrap();
    assert_eq!(client_keys.master_secret, server_keys.master_secret);
    assert_eq!(client_keys.key_block, server_keys.key_block);

    let client_finished = client.build_client_finished(3).unwrap();
    server
        .verify_client_finished(&client_finished, &server_keys)
        .unwrap();
    let server_finished = server.build_server_finished(4, &server_keys).unwrap();
    client
        .verify_server_finished(&server_finished, &client_keys)
        .unwrap();

    // The Joiner Router KEK must come out identical on both ends.
    let server_kek = server.derive_joiner_router_kek(&server_keys).unwrap();
    let client_kek = derive_joiner_router_kek(
        &client_keys.master_secret,
        &client.client_random(),
        &server.server_random(),
    )
    .unwrap();
    assert_eq!(server_kek, client_kek);
    assert_ne!(server_kek, [0u8; 16]);

    // Application data flows in both directions with role-swapped keys.
    let to_server = protect_aes_128_ccm_8_record(
        ContentType::ApplicationData,
        1,
        1,
        RecordProtectionKey::new(client_keys.key_block.client_write_key),
        &client_keys.key_block.client_write_iv,
        b"join-fin-request",
    )
    .unwrap();
    assert_eq!(
        open_aes_128_ccm_8_record(
            &to_server,
            RecordProtectionKey::new(server_keys.key_block.client_write_key),
            &server_keys.key_block.client_write_iv,
        )
        .unwrap(),
        b"join-fin-request"
    );
    let to_client = protect_aes_128_ccm_8_record(
        ContentType::ApplicationData,
        1,
        1,
        RecordProtectionKey::new(server_keys.key_block.server_write_key),
        &server_keys.key_block.server_write_iv,
        b"join-fin-response",
    )
    .unwrap();
    assert_eq!(
        open_aes_128_ccm_8_record(
            &to_client,
            RecordProtectionKey::new(client_keys.key_block.server_write_key),
            &client_keys.key_block.server_write_iv,
        )
        .unwrap(),
        b"join-fin-response"
    );
}

#[test]
fn server_handshake_rejects_invalid_client_hellos_and_wrong_secrets() {
    let mut rng = OsRng;

    // ClientHello without the ECJPAKE KKPP extension.
    let mut server = ThreadDtlsServerHandshake::new(b"J01NME", &mut rng);
    let bare_hello = ClientHello::thread_profile([0x21; 32], Vec::new());
    assert!(
        server
            .handle_client_hello(&HandshakeMessage {
                message_type: HandshakeType::ClientHello,
                message_seq: 1,
                payload: bare_hello.encode().unwrap(),
            })
            .is_err()
    );
    // Without an accepted ClientHello the server flight cannot start.
    assert!(server.build_server_hello(1).is_err());
    assert!(server.build_server_key_exchange(2, &mut rng).is_err());
    assert!(server.derive_key_material().is_err());

    // ClientHello offering only foreign cipher suites.
    let client = ThreadDtlsHandshake::new(b"J01NME", &mut rng);
    let mut wrong_suite = ClientHello::thread_profile_with_ecjpake(
        client.client_random(),
        Vec::new(),
        client.client_round_one().encode_tls_kkpp().unwrap(),
    );
    wrong_suite.cipher_suites = vec![0x1301];
    assert!(
        server
            .handle_client_hello(&HandshakeMessage {
                message_type: HandshakeType::ClientHello,
                message_seq: 1,
                payload: wrong_suite.encode().unwrap(),
            })
            .is_err()
    );

    // A joiner with the wrong PSKd derives different keys, so its Finished
    // message must be rejected.
    let mut wrong_client = ThreadDtlsHandshake::new(b"WRONGPSK", &mut rng);
    let mut server = ThreadDtlsServerHandshake::new(b"J01NME", &mut rng);
    let mut hello_state = wrong_client.client_hello_state().unwrap();
    let hello_record = hello_state.next_client_hello_record().unwrap();
    let hello =
        parse_unfragmented_handshake_record(&hello_record, HandshakeType::ClientHello).unwrap();
    wrong_client.record_client_hello(&hello).unwrap();
    server.handle_client_hello(&hello).unwrap();
    wrong_client
        .handle_server_hello(&server.build_server_hello(1).unwrap())
        .unwrap();
    wrong_client
        .handle_server_key_exchange(&server.build_server_key_exchange(2, &mut rng).unwrap())
        .unwrap();
    wrong_client
        .handle_server_hello_done(&server.build_server_hello_done(3).unwrap())
        .unwrap();
    server
        .handle_client_key_exchange(&wrong_client.build_client_key_exchange(1, &mut rng).unwrap())
        .unwrap();
    let server_keys = server.derive_key_material().unwrap();
    let client_finished = wrong_client.build_client_finished(2).unwrap();
    assert!(
        server
            .verify_client_finished(&client_finished, &server_keys)
            .is_err()
    );
}

#[tokio::test]
async fn dtls_session_connect_completes_against_in_process_server() -> crate::Result<()> {
    let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let server_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    client_socket.connect(server_socket.local_addr()?).await?;
    server_socket.connect(client_socket.local_addr()?).await?;

    let pskc = [0x42; 16];
    let server = tokio::spawn(async move {
        test_support::loopback_dtls_server(
            &server_socket,
            &pskc,
            test_support::LoopbackEnd::Complete,
        )
        .await
    });
    let session =
        DtlsSession::connect(&client_socket, &pskc, core::time::Duration::from_secs(2)).await?;
    let server_keys = server.await.expect("server task panicked")?.expect("keys");
    assert_eq!(
        server_keys.master_secret,
        session.key_material().master_secret
    );

    // The negotiated key material is non-trivial.
    assert_ne!(session.key_material().master_secret, [0u8; 48]);
    Ok(())
}

#[tokio::test]
async fn dtls_session_connect_fails_against_wrong_pskc_server() -> crate::Result<()> {
    let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let server_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    client_socket.connect(server_socket.local_addr()?).await?;
    server_socket.connect(client_socket.local_addr()?).await?;

    let server = tokio::spawn(async move {
        test_support::loopback_dtls_server(
            &server_socket,
            &[0x42; 16],
            test_support::LoopbackEnd::Complete,
        )
        .await
    });
    let client = DtlsSession::connect(
        &client_socket,
        &[0x43; 16],
        core::time::Duration::from_secs(2),
    )
    .await;
    assert!(client.is_err(), "mismatched PSKc must not negotiate");
    // The server side must also refuse the client's Finished.
    assert!(server.await.expect("server task panicked").is_err());
    Ok(())
}

#[tokio::test]
async fn dtls_server_accepts_cookie_retry_and_echoes_protected_payload() -> crate::Result<()> {
    let server = DtlsServer::bind("127.0.0.1:0").await?;
    let server_addr = server.local_addr();
    let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    client_socket.connect(server_addr).await?;
    let pskc = [0x42; 16];

    let server_task = async move {
        let mut session = server
            .accept(&pskc, core::time::Duration::from_secs(2))
            .await?;
        let request = session
            .recv_application_data(core::time::Duration::from_secs(2))
            .await
            .map_err(crate::Error::from)?;
        session
            .send_application_data(&request)
            .await
            .map_err(crate::Error::from)?;
        crate::Result::Ok(session.key_material().master_secret)
    };
    let client_task = async {
        let mut session =
            DtlsSession::connect(&client_socket, &pskc, core::time::Duration::from_secs(2)).await?;
        let response = session
            .request_application_data(
                &client_socket,
                b"cookie-verified echo",
                core::time::Duration::from_secs(2),
            )
            .await?;
        crate::Result::Ok((response, session.key_material().master_secret))
    };

    let (server_result, client_result) = tokio::join!(server_task, client_task);
    let server_secret = server_result?;
    let (response, client_secret) = client_result?;
    assert_eq!(response, b"cookie-verified echo");
    assert_eq!(server_secret, client_secret);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlightDirection {
    ClientToServer,
    ServerToClient,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlightFault {
    Drop,
    ForwardFirstRecord,
}

#[derive(Debug, Default)]
struct LossObservation {
    dropped: Option<Vec<u8>>,
    saw_fresh_semantic_retry: bool,
}

#[tokio::test]
async fn dtls_handshake_recovers_when_each_flight_is_dropped_once() -> crate::Result<()> {
    for (direction, ordinal) in [
        (FlightDirection::ClientToServer, 1),
        (FlightDirection::ServerToClient, 1),
        (FlightDirection::ClientToServer, 2),
        (FlightDirection::ServerToClient, 2),
        (FlightDirection::ClientToServer, 3),
        (FlightDirection::ServerToClient, 3),
    ] {
        run_flight_fault_case(direction, ordinal, FlightFault::Drop).await?;
    }
    Ok(())
}

#[tokio::test]
async fn dtls_handshake_recovers_from_a_partially_delivered_client_flight() -> crate::Result<()> {
    run_flight_fault_case(
        FlightDirection::ClientToServer,
        3,
        FlightFault::ForwardFirstRecord,
    )
    .await
}

async fn run_flight_fault_case(
    direction: FlightDirection,
    ordinal: usize,
    fault: FlightFault,
) -> crate::Result<()> {
    let server = DtlsServer::bind("127.0.0.1:0").await?;
    let server_addr = server.local_addr();
    let proxy = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let proxy_addr = proxy.local_addr()?;
    let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let client_addr = client_socket.local_addr()?;
    client_socket.connect(proxy_addr).await?;

    let observation = Arc::new(Mutex::new(LossObservation::default()));
    let proxy_observation = Arc::clone(&observation);
    let proxy_task = tokio::spawn(async move {
        run_lossy_proxy(
            proxy,
            client_addr,
            server_addr,
            direction,
            ordinal,
            fault,
            proxy_observation,
        )
        .await
    });

    let pskc = [0x42; 16];
    let deadline = core::time::Duration::from_secs(12);
    let server_task = async move {
        let mut session = server.accept(&pskc, deadline).await?;
        let request = session
            .recv_application_data(deadline)
            .await
            .map_err(crate::Error::from)?;
        session
            .send_application_data(&request)
            .await
            .map_err(crate::Error::from)?;
        crate::Result::Ok(session.key_material().master_secret)
    };
    let client_task = async {
        let mut session = DtlsSession::connect(&client_socket, &pskc, deadline).await?;
        let response = session
            .request_application_data(&client_socket, b"lossy echo", deadline)
            .await?;
        crate::Result::Ok((response, session.key_material().master_secret))
    };

    let (server_result, client_result) = tokio::join!(server_task, client_task);
    proxy_task.abort();
    let server_secret = server_result?;
    let (response, client_secret) = client_result?;
    assert_eq!(response, b"lossy echo");
    assert_eq!(server_secret, client_secret);

    let observation = observation.lock().expect("loss observation lock poisoned");
    assert!(
        observation.dropped.is_some(),
        "proxy did not fault {direction:?} flight {ordinal}"
    );
    assert!(
        observation.saw_fresh_semantic_retry,
        "{direction:?} flight {ordinal} was not retransmitted with fresh record sequences"
    );
    Ok(())
}

async fn run_lossy_proxy(
    socket: tokio::net::UdpSocket,
    client_addr: core::net::SocketAddr,
    server_addr: core::net::SocketAddr,
    drop_direction: FlightDirection,
    drop_ordinal: usize,
    fault: FlightFault,
    observation: Arc<Mutex<LossObservation>>,
) -> crate::Result<()> {
    let mut client_to_server = 0usize;
    let mut server_to_client = 0usize;
    let mut buffer = [0u8; crate::driver::MAX_DATAGRAM_SIZE];
    loop {
        let (length, source) = socket.recv_from(&mut buffer).await?;
        let (direction, ordinal, destination) = if source == client_addr {
            client_to_server += 1;
            (
                FlightDirection::ClientToServer,
                client_to_server,
                server_addr,
            )
        } else if source == server_addr {
            server_to_client += 1;
            (
                FlightDirection::ServerToClient,
                server_to_client,
                client_addr,
            )
        } else {
            continue;
        };
        let datagram = &buffer[..length];
        let fingerprint = handshake_flight_fingerprint(datagram)?;

        let mut should_drop = false;
        {
            let mut observed = observation.lock().expect("loss observation lock poisoned");
            if direction == drop_direction && ordinal == drop_ordinal {
                observed.dropped = Some(datagram.to_vec());
                should_drop = true;
            } else if direction == drop_direction
                && observed.dropped.as_deref().is_some_and(|dropped| {
                    dropped != datagram
                        && handshake_flight_fingerprint(dropped)
                            .is_ok_and(|dropped_fingerprint| dropped_fingerprint == fingerprint)
                        && record_sequences_are_fresh(dropped, datagram)
                })
            {
                observed.saw_fresh_semantic_retry = true;
            }
        }
        if !should_drop {
            socket.send_to(datagram, destination).await?;
        } else if fault == FlightFault::ForwardFirstRecord {
            let records = DtlsRecord::parse_datagram(datagram)?;
            let first = records
                .first()
                .ok_or(Error::Crypto("faulted DTLS flight is empty".into()))?;
            socket.send_to(&first.encode()?, destination).await?;
        }
    }
}

fn record_sequences_are_fresh(previous: &[u8], retransmission: &[u8]) -> bool {
    let Ok(previous) = DtlsRecord::parse_datagram(previous) else {
        return false;
    };
    let Ok(retransmission) = DtlsRecord::parse_datagram(retransmission) else {
        return false;
    };
    previous.len() == retransmission.len()
        && previous.iter().zip(&retransmission).all(|(before, after)| {
            before.header.epoch == after.header.epoch
                && before.header.content_type == after.header.content_type
                && before.header.sequence_number != after.header.sequence_number
        })
}

fn handshake_flight_fingerprint(
    datagram: &[u8],
) -> crate::Result<Vec<(u16, ContentType, Vec<u8>)>> {
    DtlsRecord::parse_datagram(datagram).map(|records| {
        records
            .into_iter()
            .map(|record| {
                let payload = if record.header.epoch == 0 {
                    record.payload
                } else {
                    Vec::new()
                };
                (record.header.epoch, record.header.content_type, payload)
            })
            .collect()
    })
}

#[tokio::test]
async fn dtls_server_and_client_reject_wrong_pskc() -> crate::Result<()> {
    let server = DtlsServer::bind("127.0.0.1:0").await?;
    let server_addr = server.local_addr();
    let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    client_socket.connect(server_addr).await?;

    let server_task = server.accept(&[0x42; 16], core::time::Duration::from_secs(2));
    let client_task = DtlsSession::connect(
        &client_socket,
        &[0x43; 16],
        core::time::Duration::from_secs(2),
    );
    let (server_result, client_result) = tokio::join!(server_task, client_task);
    assert!(
        server_result.is_err(),
        "server must reject the client's Finished"
    );
    assert!(
        client_result.is_err(),
        "client must reject the server alert"
    );
    Ok(())
}

#[tokio::test]
async fn dtls_server_ignores_invalid_records_before_cookie_exchange() -> crate::Result<()> {
    let server = DtlsServer::bind("127.0.0.1:0").await?;
    let server_addr = server.local_addr();
    let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    client_socket.connect(server_addr).await?;
    let pskc = [0x42; 16];
    let server_task = tokio::spawn(async move {
        server
            .accept(&pskc, core::time::Duration::from_secs(2))
            .await
    });
    let ignored = DtlsRecord::new(ContentType::Handshake, 1, 0, vec![0xff])?;
    client_socket.send(&ignored.encode()?).await?;
    let mut rng = OsRng;
    let wrong_epoch_client = ThreadDtlsHandshake::new(&pskc, &mut rng);
    let mut wrong_epoch_hello = wrong_epoch_client
        .client_hello_state()?
        .next_client_hello_record()?;
    wrong_epoch_hello.header.epoch = 1;
    client_socket.send(&wrong_epoch_hello.encode()?).await?;
    let malformed_hello = HandshakeMessage {
        message_type: HandshakeType::ClientHello,
        message_seq: 0,
        payload: vec![0xff],
    };
    let malformed_record =
        DtlsRecord::new(ContentType::Handshake, 0, 0, malformed_hello.encode()?)?;
    client_socket.send(&malformed_record.encode()?).await?;

    let mut unexpected = [0u8; 4096];
    assert!(
        tokio::time::timeout(
            core::time::Duration::from_millis(50),
            client_socket.recv(&mut unexpected)
        )
        .await
        .is_err(),
        "invalid pre-cookie records must not receive a response"
    );

    let client_session =
        DtlsSession::connect(&client_socket, &pskc, core::time::Duration::from_secs(2)).await?;
    let server_session = server_task.await.expect("server task panicked")?;
    assert_eq!(
        server_session.key_material().master_secret,
        client_session.key_material().master_secret
    );
    Ok(())
}

#[tokio::test]
async fn dtls_server_reports_client_alert_after_cookie_validation() -> crate::Result<()> {
    let server = DtlsServer::bind("127.0.0.1:0").await?;
    let server_addr = server.local_addr();
    let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    client_socket.connect(server_addr).await?;
    let pskc = [0x42; 16];

    let client_task = async {
        let mut rng = OsRng;
        let client = ThreadDtlsHandshake::new(&pskc, &mut rng);
        let mut hello_state = client.client_hello_state()?;
        client_socket
            .send(&hello_state.next_client_hello_record()?.encode()?)
            .await?;
        let verify_datagram = recv_one(&client_socket).await?;
        let verify_records = DtlsRecord::parse_datagram(&verify_datagram)?;
        hello_state.handle_hello_verify_request(&verify_records[0])?;
        client_socket
            .send(&hello_state.next_client_hello_record()?.encode()?)
            .await?;

        // Receiving the server flight proves that the server has committed to
        // this cookie-validated peer and entered its session handshake loop.
        let _server_flight = recv_one(&client_socket).await?;
        let alert = DtlsRecord::new(ContentType::Alert, 0, 2, vec![2, 90])?;
        client_socket.send(&alert.encode()?).await?;
        crate::Result::Ok(())
    };
    let (server_result, client_result) = tokio::join!(
        server.accept(&pskc, core::time::Duration::from_secs(2)),
        client_task
    );
    client_result?;
    assert!(
        matches!(
            server_result,
            Err(crate::Error::Crypto(message)) if message.contains("description=90")
        ),
        "server must surface the selected peer's alert"
    );
    Ok(())
}

#[tokio::test]
async fn established_dtls_server_session_reports_client_alerts() -> crate::Result<()> {
    let server = DtlsServer::bind("127.0.0.1:0").await?;
    let server_addr = server.local_addr();
    let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    client_socket.connect(server_addr).await?;
    let pskc = [0x42; 16];

    let server_task = async move {
        let mut session = server
            .accept(&pskc, core::time::Duration::from_secs(2))
            .await?;
        session
            .recv_application_data(core::time::Duration::from_secs(2))
            .await
            .map_err(crate::Error::from)
    };
    let client_task = async {
        let session =
            DtlsSession::connect(&client_socket, &pskc, core::time::Duration::from_secs(2)).await?;
        let unauthenticated = DtlsRecord::new(ContentType::Alert, 1, 1, vec![2, 40])?;
        client_socket.send(&unauthenticated.encode()?).await?;
        let authenticated = protect_aes_128_ccm_8_record(
            ContentType::Alert,
            1,
            1,
            RecordProtectionKey::new(session.key_material().key_block.client_write_key),
            &session.key_material().key_block.client_write_iv,
            &[2, 40],
        )?;
        client_socket.send(&authenticated.encode()?).await?;
        crate::Result::Ok(())
    };
    let (server_result, client_result) = tokio::join!(server_task, client_task);
    client_result?;
    assert!(
        matches!(
            server_result,
            Err(crate::Error::Crypto(message)) if message.contains("description=40")
        ),
        "established session must surface a client alert"
    );
    Ok(())
}

#[test]
fn cookie_generator_binds_cookies_to_the_client_random() {
    let mut rng = OsRng;
    let cookies = DtlsCookieGenerator::new(&mut rng);
    let cookie_a = cookies.cookie(&[0xaa; 32]).unwrap();
    let cookie_b = cookies.cookie(&[0xbb; 32]).unwrap();
    // Cookies must depend on the random, not be a fixed value.
    assert_ne!(cookie_a, cookie_b);
    assert!(cookies.verify(&[0xaa; 32], &cookie_a));
    assert!(!cookies.verify(&[0xbb; 32], &cookie_a));

    // Two generators must not accept each other's cookies.
    let other = DtlsCookieGenerator::new(&mut rng);
    assert!(!other.verify(&[0xaa; 32], &cookie_a));
}

#[test]
fn server_handshake_debug_output_redacts_secrets() {
    let mut rng = OsRng;
    let cookies = DtlsCookieGenerator::new(&mut rng);
    let rendered = format!("{cookies:?}");
    assert!(rendered.contains("DtlsCookieGenerator"));
    assert!(rendered.contains("<redacted>"));

    let server = ThreadDtlsServerHandshake::new(b"J01NME", &mut rng);
    let rendered = format!("{server:?}");
    assert!(rendered.contains("ThreadDtlsServerHandshake"));
    assert!(rendered.contains("client_hello_seen"));
    assert!(!rendered.contains("J01NME"));
}

#[test]
fn handshake_header_validate_rejects_oversized_lengths() {
    // A length above the 24-bit field must fail validation even when the
    // fragment bounds are individually small.
    let header = HandshakeHeader {
        message_type: HandshakeType::ClientHello,
        length: MAX_U24 + 1,
        message_seq: 0,
        fragment_offset: 0,
        fragment_length: 0,
    };
    assert!(header.validate().is_err());

    let header = HandshakeHeader {
        message_type: HandshakeType::ClientHello,
        length: 4,
        message_seq: 0,
        fragment_offset: MAX_U24 + 1,
        fragment_length: 0,
    };
    assert!(header.validate().is_err());
}

/// Connected loopback socket pair for negative handshake tests.
async fn loopback_pair() -> crate::Result<(tokio::net::UdpSocket, tokio::net::UdpSocket)> {
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    client.connect(server.local_addr()?).await?;
    server.connect(client.local_addr()?).await?;
    Ok((client, server))
}

async fn recv_one(socket: &tokio::net::UdpSocket) -> crate::Result<Vec<u8>> {
    let mut buf = [0u8; 4096];
    let len = tokio::time::timeout(core::time::Duration::from_secs(2), socket.recv(&mut buf))
        .await
        .map_err(|_| crate::Error::Timeout("test server receive timed out"))??;
    Ok(buf[..len].to_vec())
}

#[tokio::test]
async fn connect_reports_alert_while_waiting_for_hello_verify() -> crate::Result<()> {
    let (client, server) = loopback_pair().await?;
    let alerting_server = tokio::spawn(async move {
        recv_one(&server).await?;
        let alert = DtlsRecord::new(ContentType::Alert, 0, 0, vec![2, 40])?;
        server.send(&alert.encode()?).await?;
        crate::Result::Ok(())
    });

    let err = DtlsSession::connect(&client, &[0x42; 16], core::time::Duration::from_secs(2))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, crate::Error::Crypto(message) if message.contains("alert")),
        "expected an alert error, got {err:?}"
    );
    alerting_server.await.expect("server task panicked")
}

#[tokio::test]
async fn connect_reports_alert_and_repeat_cookie_during_server_flight() -> crate::Result<()> {
    // An alert in place of the server flight must surface as an alert error.
    let (client, server) = loopback_pair().await?;
    let alerting_server = tokio::spawn(async move {
        respond_with_cookie(&server, 0).await?;
        recv_one(&server).await?;
        let alert = DtlsRecord::new(ContentType::Alert, 0, 1, vec![2, 40])?;
        server.send(&alert.encode()?).await?;
        crate::Result::Ok(())
    });
    let err = DtlsSession::connect(&client, &[0x42; 16], core::time::Duration::from_secs(2))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, crate::Error::Crypto(message) if message.contains("alert")),
        "expected an alert error, got {err:?}"
    );
    alerting_server.await.expect("server task panicked")?;

    // A new HelloVerifyRequest means the server rejected the previous cookie.
    // The client must adopt the replacement instead of replaying a stale one.
    let (client, server) = loopback_pair().await?;
    let looping_server = tokio::spawn(async move {
        respond_with_cookie(&server, 0).await?;
        let second_client_hello = recv_one(&server).await?;
        let second_records = DtlsRecord::parse_datagram(&second_client_hello)?;
        let second_message =
            parse_unfragmented_handshake_record(&second_records[0], HandshakeType::ClientHello)?;
        let replacement_cookie = vec![0xca, 0xfe];
        send_cookie_message(
            &server,
            second_message.message_seq,
            second_records[0].header.sequence_number,
            replacement_cookie.clone(),
        )
        .await?;
        let repeated_client_hello = recv_one(&server).await?;
        assert_ne!(repeated_client_hello, second_client_hello);
        let repeated_records = DtlsRecord::parse_datagram(&repeated_client_hello)?;
        let repeated_message =
            parse_unfragmented_handshake_record(&repeated_records[0], HandshakeType::ClientHello)?;
        assert_eq!(
            ClientHello::decode(&repeated_message.payload)?.cookie,
            replacement_cookie
        );
        let alert = DtlsRecord::new(ContentType::Alert, 0, 2, vec![2, 40])?;
        server.send(&alert.encode()?).await?;
        crate::Result::Ok(())
    });
    let err = DtlsSession::connect(&client, &[0x42; 16], core::time::Duration::from_secs(2))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, crate::Error::Crypto(message) if message.contains("alert")),
        "expected the terminating alert, got {err:?}"
    );
    looping_server.await.expect("server task panicked")
}

#[tokio::test]
async fn connect_completes_after_the_server_replaces_its_cookie() -> crate::Result<()> {
    let (client, server) = loopback_pair().await?;
    let replacing_server = tokio::spawn(async move {
        test_support::loopback_dtls_server(
            &server,
            &[0x42; 16],
            test_support::LoopbackEnd::ReplaceCookieThenComplete,
        )
        .await
    });
    let session =
        DtlsSession::connect(&client, &[0x42; 16], core::time::Duration::from_secs(2)).await?;
    let server_keys = replacing_server
        .await
        .expect("server task panicked")?
        .expect("replacement-cookie handshake returns keys");
    assert_eq!(
        session.key_material().master_secret,
        server_keys.master_secret
    );
    Ok(())
}

#[tokio::test]
async fn connect_reports_alert_instead_of_server_finished() -> crate::Result<()> {
    let (client, server) = loopback_pair().await?;
    let alerting_server = tokio::spawn(async move {
        test_support::loopback_dtls_server(
            &server,
            &[0x42; 16],
            test_support::LoopbackEnd::AlertInsteadOfFinished,
        )
        .await
    });
    let err = DtlsSession::connect(&client, &[0x42; 16], core::time::Duration::from_secs(2))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, crate::Error::Crypto(message) if message.contains("alert")),
        "expected an alert error, got {err:?}"
    );
    assert!(
        alerting_server
            .await
            .expect("server task panicked")?
            .is_none()
    );
    Ok(())
}

/// Answers one incoming ClientHello with a HelloVerifyRequest.
async fn respond_with_cookie(socket: &tokio::net::UdpSocket, record_seq: u64) -> crate::Result<()> {
    let datagram = recv_one(socket).await?;
    send_cookie_for(socket, &datagram, record_seq).await
}

async fn send_cookie_for(
    socket: &tokio::net::UdpSocket,
    datagram: &[u8],
    record_seq: u64,
) -> crate::Result<()> {
    let records = DtlsRecord::parse_datagram(datagram)?;
    let hello = parse_unfragmented_handshake_record(&records[0], HandshakeType::ClientHello)?;
    send_cookie_message(
        socket,
        hello.message_seq,
        record_seq,
        vec![0xc0, 0x0c, 0x1e],
    )
    .await
}

async fn send_cookie_message(
    socket: &tokio::net::UdpSocket,
    message_seq: u16,
    record_seq: u64,
    cookie: Vec<u8>,
) -> crate::Result<()> {
    let verify = HandshakeMessage {
        message_type: HandshakeType::HelloVerifyRequest,
        message_seq,
        payload: HelloVerifyRequest {
            server_version: DTLS_1_2_VERSION,
            cookie,
        }
        .encode()?,
    };
    let record = DtlsRecord::new(ContentType::Handshake, 0, record_seq, verify.encode()?)?;
    socket.send(&record.encode()?).await?;
    Ok(())
}
