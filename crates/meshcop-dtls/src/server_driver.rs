//! Runtime-neutral asynchronous DTLS server driver.

use alloc::{string::ToString, vec, vec::Vec};
use core::{net::SocketAddr, time::Duration};

use rand_core::{CryptoRng, RngCore};

use crate::{
    ClientHello, ContentType, DTLS_1_2_VERSION, DtlsCookieGenerator, DtlsRecord, Error,
    HandshakeMessage, HandshakeType, HelloVerifyRequest, RecordProtectionKey,
    ThreadDtlsKeyMaterial, ThreadDtlsServerHandshake,
    driver::{
        DelayNs, DriverError, DriverResult, DuplicateRetransmitBudget, RetransmitSchedule,
        SessionRole, SessionState, UnconnectedUdp, decode_alert_error, recv_records_from,
        recv_records_from_unbounded, recv_records_unbounded, renumber_epoch_zero_flight,
        send_records, take_record_sequence, with_timeout,
    },
    open_aes_128_ccm_8_record, parse_unfragmented_handshake_messages,
    parse_unfragmented_handshake_record,
};

const ALERT_LEVEL_FATAL: u8 = 2;
const ALERT_HANDSHAKE_FAILURE: u8 = 40;

/// A runtime-neutral single-peer DTLS acceptor.
///
/// The transport must already be bound. The acceptor remains stateless while
/// answering initial ClientHello messages and commits to the first peer that
/// returns a valid cookie. It is consumed by [`Self::accept_with_rng`], which
/// yields an established [`DtlsServerSession`] owning the transport.
#[derive(Debug)]
pub struct DtlsServer<U, D> {
    transport: U,
    delay: D,
    local: SocketAddr,
}

impl<U, D> DtlsServer<U, D>
where
    U: UnconnectedUdp,
    D: DelayNs,
{
    /// Creates an acceptor over an already-bound datagram transport.
    pub const fn new(transport: U, delay: D, local: SocketAddr) -> Self {
        Self {
            transport,
            delay,
            local,
        }
    }

    /// Returns the configured local transport address.
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Accepts the first cookie-validated peer using caller-supplied randomness.
    ///
    /// `timeout` is an absolute deadline for the complete handshake. Outbound
    /// flights are retransmitted with bounded exponential backoff inside that
    /// deadline.
    pub async fn accept_with_rng(
        mut self,
        rng: &mut (impl RngCore + CryptoRng),
        pskc: &[u8],
        timeout: Duration,
    ) -> DriverResult<DtlsServerSession<U, D>, U::Error>
    where
        D: Clone,
    {
        let accepted =
            accept_with_rng(rng, &mut self.transport, &mut self.delay, pskc, timeout).await?;
        Ok(DtlsServerSession {
            transport: self.transport,
            delay: self.delay,
            local: accepted.local,
            peer: accepted.peer,
            state: accepted.state,
            server_finished: accepted.server_finished,
            next_epoch_zero_record: accepted.next_epoch_zero_record,
        })
    }

    /// Returns the transport and timer without accepting a peer.
    pub fn into_parts(self) -> (U, D) {
        (self.transport, self.delay)
    }
}

/// Established runtime-neutral Thread DTLS server session.
#[derive(Debug)]
pub struct DtlsServerSession<U, D> {
    transport: U,
    delay: D,
    local: SocketAddr,
    peer: SocketAddr,
    state: SessionState,
    server_finished: Vec<u8>,
    next_epoch_zero_record: u64,
}

impl<U, D> DtlsServerSession<U, D>
where
    U: UnconnectedUdp,
    D: DelayNs,
{
    /// Returns the derived key material.
    pub const fn key_material(&self) -> &ThreadDtlsKeyMaterial {
        self.state.key_material()
    }

    /// Returns the peer selected by the cookie exchange.
    pub const fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// Sends one protected application-data record.
    pub async fn send_application_data(&mut self, plaintext: &[u8]) -> DriverResult<(), U::Error> {
        let record = self.state.protect_application_data(plaintext)?;
        send_records(&mut self.transport, self.local, self.peer, &[record]).await
    }

    /// Receives and opens the next protected application-data record.
    pub async fn recv_application_data(
        &mut self,
        timeout: Duration,
    ) -> DriverResult<Vec<u8>, U::Error>
    where
        D: Clone,
    {
        let deadline = self.delay.clone();
        with_timeout(self.recv_application_data_inner(), deadline, timeout).await
    }

    async fn recv_application_data_inner(&mut self) -> DriverResult<Vec<u8>, U::Error> {
        let mut duplicate_retransmissions = DuplicateRetransmitBudget::new();
        loop {
            let (records, _, _) =
                recv_records_from_unbounded(&mut self.transport, self.peer).await?;
            if take_server_finished_retry(
                &self.server_finished,
                &records,
                &mut duplicate_retransmissions,
            ) {
                let flight = build_server_finished_flight(
                    &mut self.state,
                    &self.server_finished,
                    &mut self.next_epoch_zero_record,
                )?;
                send_records(&mut self.transport, self.local, self.peer, &flight).await?;
            }
            for record in records {
                match (record.header.epoch, record.header.content_type) {
                    (1, ContentType::ApplicationData) => {
                        if let Ok(Some(plaintext)) = self.state.open_application_data(&record) {
                            self.server_finished.clear();
                            return Ok(plaintext);
                        }
                    }
                    (1, ContentType::Alert) => {
                        if let Ok(Some(plaintext)) = self.state.open_protected_record(&record) {
                            let alert = DtlsRecord::new(
                                ContentType::Alert,
                                1,
                                record.header.sequence_number,
                                plaintext,
                            )?;
                            return Err(decode_alert_error(&alert).into());
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Receives protected application data and sends a protected response.
    pub async fn respond_application_data(
        &mut self,
        response: &[u8],
        timeout: Duration,
    ) -> DriverResult<Vec<u8>, U::Error>
    where
        D: Clone,
    {
        let request = self.recv_application_data(timeout).await?;
        self.send_application_data(response).await?;
        Ok(request)
    }

    /// Returns the transport and timer, consuming the session.
    pub fn into_parts(self) -> (U, D) {
        (self.transport, self.delay)
    }
}

struct Accepted {
    local: SocketAddr,
    peer: SocketAddr,
    state: SessionState,
    server_finished: Vec<u8>,
    next_epoch_zero_record: u64,
}

async fn accept_with_rng<U, D>(
    rng: &mut (impl RngCore + CryptoRng),
    transport: &mut U,
    delay: &mut D,
    pskc: &[u8],
    timeout: Duration,
) -> DriverResult<Accepted, U::Error>
where
    U: UnconnectedUdp,
    D: DelayNs + Clone,
{
    let deadline = delay.clone();
    with_timeout(accept_inner(rng, transport, delay, pskc), deadline, timeout).await
}

async fn accept_inner<U, D>(
    rng: &mut (impl RngCore + CryptoRng),
    transport: &mut U,
    delay: &D,
    pskc: &[u8],
) -> DriverResult<Accepted, U::Error>
where
    U: UnconnectedUdp,
    D: DelayNs + Clone,
{
    let cookies = DtlsCookieGenerator::new_with_rng(rng);
    let (local, peer, client_hello, client_hello_record_sequence) = loop {
        let (records, local, peer) = recv_records_unbounded(transport).await?;
        let mut accepted = None;
        for record in records {
            if record.header.epoch != 0 || record.header.content_type != ContentType::Handshake {
                continue;
            }
            let Ok(messages) = parse_unfragmented_handshake_messages(&record) else {
                continue;
            };
            for message in messages {
                if message.message_type != HandshakeType::ClientHello {
                    continue;
                }
                let Ok(hello) = ClientHello::decode(&message.payload) else {
                    continue;
                };
                if cookies.verify(&hello.random, &hello.cookie) {
                    accepted = Some((message, record.header.sequence_number));
                    break;
                }
                let verify = HandshakeMessage {
                    message_type: HandshakeType::HelloVerifyRequest,
                    message_seq: message.message_seq,
                    payload: HelloVerifyRequest {
                        server_version: DTLS_1_2_VERSION,
                        cookie: cookies.cookie(&hello.random)?.to_vec(),
                    }
                    .encode()?,
                };
                let verify_record = DtlsRecord::new(
                    ContentType::Handshake,
                    0,
                    record.header.sequence_number,
                    verify.encode()?,
                )?;
                send_records(transport, local, peer, &[verify_record]).await?;
            }
            if accepted.is_some() {
                break;
            }
        }
        if let Some((message, record_sequence)) = accepted {
            break (local, peer, message, record_sequence);
        }
    };

    let mut handshake = ThreadDtlsServerHandshake::new_with_rng(rng, pskc);
    handshake.handle_client_hello(&client_hello)?;
    let mut next_epoch_zero_record = client_hello_record_sequence;
    let server_message_sequence = client_hello.message_seq;
    let mut server_flight = Vec::new();
    for message in [
        handshake.build_server_hello(server_message_sequence)?,
        handshake.build_server_key_exchange(server_message_sequence.wrapping_add(1), rng)?,
        handshake.build_server_hello_done(server_message_sequence.wrapping_add(2))?,
    ] {
        server_flight.push(DtlsRecord::new(
            ContentType::Handshake,
            0,
            next_epoch_zero_record,
            message.encode()?,
        )?);
        next_epoch_zero_record = next_epoch_zero_record.wrapping_add(1);
    }
    send_records(transport, local, peer, &server_flight).await?;

    let mut schedule = RetransmitSchedule::new();
    let mut duplicate_retransmissions = DuplicateRetransmitBudget::new();
    let mut saw_change_cipher_spec = false;
    let mut key_material = None;
    let mut client_key_exchange = None;
    loop {
        let (records, _, _) =
            match recv_records_from(transport, delay, peer, schedule.timeout()).await {
                Ok(received) => received,
                Err(DriverError::Timeout) => {
                    renumber_epoch_zero_flight(&mut server_flight, &mut next_epoch_zero_record);
                    send_records(transport, local, peer, &server_flight).await?;
                    schedule.back_off();
                    continue;
                }
                Err(error) => return Err(error),
            };

        if contains_client_hello(&records, &client_hello) {
            if duplicate_retransmissions.take() {
                renumber_epoch_zero_flight(&mut server_flight, &mut next_epoch_zero_record);
                send_records(transport, local, peer, &server_flight).await?;
            }
            continue;
        }
        for record in records {
            match (record.header.epoch, record.header.content_type) {
                (0, ContentType::Handshake) => {
                    let Ok(messages) = parse_unfragmented_handshake_messages(&record) else {
                        continue;
                    };
                    for message in messages {
                        if message.message_type != HandshakeType::ClientKeyExchange {
                            continue;
                        }
                        if client_key_exchange.as_ref() == Some(&message) {
                            continue;
                        }
                        handshake.handle_client_key_exchange(&message)?;
                        key_material = Some(handshake.derive_key_material()?);
                        client_key_exchange = Some(message);
                    }
                }
                (0, ContentType::ChangeCipherSpec) => {
                    if record.payload != [1] {
                        return Err(
                            Error::Crypto("invalid ChangeCipherSpec payload".to_string()).into(),
                        );
                    }
                    saw_change_cipher_spec = true;
                }
                (1, ContentType::Handshake) => {
                    if !saw_change_cipher_spec {
                        continue;
                    }
                    let keys = key_material
                        .as_ref()
                        .ok_or(Error::InvalidState("client key material is missing"))?;
                    let plaintext = match open_aes_128_ccm_8_record(
                        &record,
                        RecordProtectionKey::new(keys.key_block.client_write_key),
                        &keys.key_block.client_write_iv,
                    ) {
                        Ok(plaintext) => plaintext,
                        Err(error) => {
                            send_fatal_handshake_alert(
                                transport,
                                local,
                                peer,
                                next_epoch_zero_record,
                            )
                            .await?;
                            return Err(error.into());
                        }
                    };
                    let plain_record = DtlsRecord::new(ContentType::Handshake, 1, 0, plaintext)?;
                    let finished = parse_unfragmented_handshake_record(
                        &plain_record,
                        HandshakeType::Finished,
                    )?;
                    if let Err(error) = handshake.verify_client_finished(&finished, keys) {
                        send_fatal_handshake_alert(transport, local, peer, next_epoch_zero_record)
                            .await?;
                        return Err(error.into());
                    }
                    let server_finished = handshake
                        .build_server_finished(server_message_sequence.wrapping_add(3), keys)?;
                    let server_finished = server_finished.encode()?;
                    let key_material = key_material
                        .take()
                        .ok_or(Error::InvalidState("client key material is missing"))?;
                    let mut state =
                        SessionState::during_handshake(key_material, SessionRole::Server);
                    let server_finished_flight = build_server_finished_flight(
                        &mut state,
                        &server_finished,
                        &mut next_epoch_zero_record,
                    )?;
                    send_records(transport, local, peer, &server_finished_flight).await?;
                    return Ok(Accepted {
                        local,
                        peer,
                        state,
                        server_finished,
                        next_epoch_zero_record,
                    });
                }
                (0, ContentType::Alert) => return Err(decode_alert_error(&record).into()),
                _ => {}
            }
        }
    }
}

fn contains_client_hello(records: &[DtlsRecord], expected: &HandshakeMessage) -> bool {
    for record in records {
        if record.header.epoch != 0 || record.header.content_type != ContentType::Handshake {
            continue;
        }
        let Ok(messages) = parse_unfragmented_handshake_messages(record) else {
            continue;
        };
        if messages.iter().any(|message| message == expected) {
            return true;
        }
    }
    false
}

fn is_client_finished_flight(records: &[DtlsRecord]) -> bool {
    records.iter().any(
        |record| match (record.header.epoch, record.header.content_type) {
            (0, ContentType::Handshake) => {
                parse_unfragmented_handshake_messages(record).is_ok_and(|messages| {
                    messages
                        .iter()
                        .any(|message| message.message_type == HandshakeType::ClientKeyExchange)
                })
            }
            (1, ContentType::Handshake) => true,
            _ => false,
        },
    )
}

fn take_server_finished_retry(
    server_finished: &[u8],
    records: &[DtlsRecord],
    budget: &mut DuplicateRetransmitBudget,
) -> bool {
    !server_finished.is_empty() && is_client_finished_flight(records) && budget.take()
}

fn build_server_finished_flight(
    state: &mut SessionState,
    server_finished: &[u8],
    next_epoch_zero_record: &mut u64,
) -> crate::Result<Vec<DtlsRecord>> {
    Ok(vec![
        DtlsRecord::new(
            ContentType::ChangeCipherSpec,
            0,
            take_record_sequence(next_epoch_zero_record),
            vec![1],
        )?,
        state.protect_record(ContentType::Handshake, server_finished)?,
    ])
}

async fn send_fatal_handshake_alert<U>(
    transport: &mut U,
    local: SocketAddr,
    peer: SocketAddr,
    sequence_number: u64,
) -> DriverResult<(), U::Error>
where
    U: UnconnectedUdp,
{
    let alert = DtlsRecord::new(
        ContentType::Alert,
        0,
        sequence_number,
        vec![ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE],
    )?;
    send_records(transport, local, peer, &[alert]).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handshake_record(message: &HandshakeMessage, epoch: u16) -> DtlsRecord {
        DtlsRecord::new(
            ContentType::Handshake,
            epoch,
            1,
            message.encode().expect("encode handshake message"),
        )
        .expect("build handshake record")
    }

    #[test]
    fn duplicate_client_hello_requires_the_expected_epoch_zero_handshake() {
        let expected = HandshakeMessage {
            message_type: HandshakeType::ClientHello,
            message_seq: 1,
            payload: vec![1, 2, 3],
        };
        let record = handshake_record(&expected, 0);
        assert!(contains_client_hello(
            core::slice::from_ref(&record),
            &expected
        ));

        let wrong_epoch = handshake_record(&expected, 1);
        assert!(!contains_client_hello(&[wrong_epoch], &expected));
        let wrong_content = DtlsRecord::new(
            ContentType::ApplicationData,
            0,
            1,
            expected.encode().expect("encode handshake message"),
        )
        .expect("build wrong-content record");
        assert!(!contains_client_hello(&[wrong_content], &expected));
    }

    #[test]
    fn recognizes_each_meaningful_client_finished_flight_record() {
        let key_exchange = HandshakeMessage {
            message_type: HandshakeType::ClientKeyExchange,
            message_seq: 2,
            payload: Vec::new(),
        };
        assert!(is_client_finished_flight(&[handshake_record(
            &key_exchange,
            0
        )]));

        let server_hello = HandshakeMessage {
            message_type: HandshakeType::ServerHello,
            message_seq: 1,
            payload: Vec::new(),
        };
        assert!(!is_client_finished_flight(&[handshake_record(
            &server_hello,
            0
        )]));
        let encrypted_finished =
            DtlsRecord::new(ContentType::Handshake, 1, 1, vec![0xaa]).expect("finished record");
        assert!(is_client_finished_flight(&[encrypted_finished]));
        let change_cipher_spec =
            DtlsRecord::new(ContentType::ChangeCipherSpec, 0, 2, vec![1]).expect("CCS record");
        assert!(!is_client_finished_flight(&[change_cipher_spec]));
    }

    #[test]
    fn server_finished_retry_requires_cached_data_client_flight_and_budget() {
        let key_exchange = HandshakeMessage {
            message_type: HandshakeType::ClientKeyExchange,
            message_seq: 2,
            payload: Vec::new(),
        };
        let client_finished = handshake_record(&key_exchange, 0);
        let application = DtlsRecord::new(ContentType::ApplicationData, 1, 1, vec![0xaa])
            .expect("application record");

        let mut budget = DuplicateRetransmitBudget::new();
        assert!(!take_server_finished_retry(
            &[],
            core::slice::from_ref(&client_finished),
            &mut budget,
        ));
        assert!(!take_server_finished_retry(
            b"cached Finished",
            &[application],
            &mut budget,
        ));
        for _ in 0..crate::driver::MAX_DUPLICATE_RETRANSMISSIONS {
            assert!(take_server_finished_retry(
                b"cached Finished",
                core::slice::from_ref(&client_finished),
                &mut budget,
            ));
        }
        assert!(!take_server_finished_retry(
            b"cached Finished",
            &[client_finished],
            &mut budget,
        ));
    }
}
