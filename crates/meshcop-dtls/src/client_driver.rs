//! Runtime-neutral asynchronous DTLS client driver.

use alloc::{format, string::ToString, vec, vec::Vec};
use core::{net::SocketAddr, time::Duration};

use rand_core::{CryptoRng, RngCore};

use crate::{
    ContentType, DtlsClientHelloState, DtlsRecord, Error, HandshakeType, RecordProtectionKey,
    ThreadDtlsHandshake, ThreadDtlsKeyMaterial,
    driver::{
        DelayNs, DriverError, DriverResult, DuplicateRetransmitBudget, RetransmitSchedule,
        SessionRole, SessionState, UnconnectedUdp, decode_alert_error, recv_application_data,
        recv_records_from, renumber_epoch_zero_flight, send_records, take_record_sequence,
        with_timeout,
    },
    open_aes_128_ccm_8_record, parse_unfragmented_handshake_messages,
    parse_unfragmented_handshake_record,
    util::dtls_trace,
};

/// A runtime-neutral DTLS client before its handshake is run.
///
/// The transport must already be bound. `local` is the address the transport
/// expects on sends and `peer` is the DTLS server.
#[derive(Debug)]
pub struct DtlsClient<U, D> {
    transport: U,
    delay: D,
    local: SocketAddr,
    peer: SocketAddr,
}

impl<U, D> DtlsClient<U, D>
where
    U: UnconnectedUdp,
    D: DelayNs,
{
    /// Creates a client over an already-bound datagram transport.
    pub const fn new(transport: U, delay: D, local: SocketAddr, peer: SocketAddr) -> Self {
        Self {
            transport,
            delay,
            local,
            peer,
        }
    }

    /// Runs the Thread PSKc/ECJPAKE handshake with caller-supplied randomness.
    ///
    /// `timeout` is an absolute deadline for the complete handshake. Outbound
    /// flights are retransmitted with bounded exponential backoff inside that
    /// deadline.
    pub async fn connect_with_rng(
        mut self,
        rng: &mut (impl RngCore + CryptoRng),
        pskc: &[u8],
        timeout: Duration,
    ) -> DriverResult<DtlsClientSession<U, D>, U::Error>
    where
        D: Clone,
    {
        let state = connect_with_rng(
            rng,
            &mut self.transport,
            &mut self.delay,
            self.local,
            self.peer,
            pskc,
            timeout,
        )
        .await?;
        Ok(DtlsClientSession {
            transport: self.transport,
            delay: self.delay,
            local: self.local,
            peer: self.peer,
            state,
        })
    }
}

/// Established runtime-neutral Thread DTLS client session.
#[derive(Debug)]
pub struct DtlsClientSession<U, D> {
    transport: U,
    delay: D,
    local: SocketAddr,
    peer: SocketAddr,
    state: SessionState,
}

impl<U, D> DtlsClientSession<U, D>
where
    U: UnconnectedUdp,
    D: DelayNs,
{
    /// Returns the derived key material.
    pub const fn key_material(&self) -> &ThreadDtlsKeyMaterial {
        self.state.key_material()
    }

    /// Returns the server address selected for this session.
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
        recv_application_data(
            &mut self.state,
            &mut self.transport,
            &self.delay,
            self.peer,
            timeout,
        )
        .await
    }

    /// Sends protected application data and waits for the next protected response.
    pub async fn request_application_data(
        &mut self,
        plaintext: &[u8],
        timeout: Duration,
    ) -> DriverResult<Vec<u8>, U::Error>
    where
        D: Clone,
    {
        self.send_application_data(plaintext).await?;
        self.recv_application_data(timeout).await
    }

    /// Returns the transport and timer, consuming the session.
    pub fn into_parts(self) -> (U, D) {
        (self.transport, self.delay)
    }
}

pub(crate) async fn connect_with_rng<U, D>(
    rng: &mut (impl RngCore + CryptoRng),
    transport: &mut U,
    delay: &mut D,
    local: SocketAddr,
    peer: SocketAddr,
    pskc: &[u8],
    timeout: Duration,
) -> DriverResult<SessionState, U::Error>
where
    U: UnconnectedUdp,
    D: DelayNs + Clone,
{
    let deadline = delay.clone();
    with_timeout(
        connect_inner(rng, transport, delay, local, peer, pskc),
        deadline,
        timeout,
    )
    .await
}

async fn connect_inner<U, D>(
    rng: &mut (impl RngCore + CryptoRng),
    transport: &mut U,
    delay: &mut D,
    local: SocketAddr,
    peer: SocketAddr,
    pskc: &[u8],
) -> DriverResult<SessionState, U::Error>
where
    U: UnconnectedUdp,
    D: DelayNs + Clone,
{
    let mut handshake = ThreadDtlsHandshake::new_with_rng(rng, pskc);
    let mut hello_state = handshake.client_hello_state()?;
    let mut next_epoch_zero_record = 0u64;

    let mut first_client_flight = vec![hello_state.next_client_hello_record()?];
    renumber_epoch_zero_flight(&mut first_client_flight, &mut next_epoch_zero_record);
    dtls_trace(format_args!(
        "send first ClientHello record_seq={}",
        first_client_flight[0].header.sequence_number
    ));
    send_records(transport, local, peer, &first_client_flight).await?;
    wait_for_hello_verify(
        ClientHandshakeIo {
            transport,
            delay,
            local,
            peer,
            next_epoch_zero_record: &mut next_epoch_zero_record,
        },
        &mut first_client_flight,
        &mut hello_state,
    )
    .await?;

    let mut second_client_flight = vec![hello_state.next_client_hello_record()?];
    renumber_epoch_zero_flight(&mut second_client_flight, &mut next_epoch_zero_record);
    let mut client_hello_message =
        parse_unfragmented_handshake_record(&second_client_flight[0], HandshakeType::ClientHello)?;
    dtls_trace(format_args!(
        "send second ClientHello record_seq={} message_seq={}",
        second_client_flight[0].header.sequence_number, client_hello_message.message_seq
    ));
    send_records(transport, local, peer, &second_client_flight).await?;

    let server_flight = wait_for_server_flight(
        ClientHandshakeIo {
            transport,
            delay,
            local,
            peer,
            next_epoch_zero_record: &mut next_epoch_zero_record,
        },
        &mut second_client_flight,
        &mut hello_state,
        &mut client_hello_message,
        &mut handshake,
    )
    .await?;

    let client_key_exchange_seq = hello_state.next_message_sequence();
    let client_key_exchange = handshake.build_client_key_exchange(client_key_exchange_seq, rng)?;
    let key_material = handshake.derive_key_material()?;
    let client_finished =
        handshake.build_client_finished(client_key_exchange_seq.wrapping_add(1))?;

    let mut state = SessionState::during_handshake(key_material, SessionRole::Client);
    let mut client_finished_flight = build_client_finished_flight(
        &client_key_exchange,
        &client_finished,
        &mut state,
        &mut next_epoch_zero_record,
    )?;
    dtls_trace(format_args!(
        "send ClientKeyExchange message_seq={} record_seq={}, CCS record_seq={}, Finished message_seq={} epoch1_record_seq=0",
        client_key_exchange.message_seq,
        client_finished_flight[0].header.sequence_number,
        client_finished_flight[1].header.sequence_number,
        client_finished.message_seq
    ));
    send_records(transport, local, peer, &client_finished_flight).await?;

    wait_for_server_finished(
        ClientHandshakeIo {
            transport,
            delay,
            local,
            peer,
            next_epoch_zero_record: &mut next_epoch_zero_record,
        },
        &mut client_finished_flight,
        &client_key_exchange,
        &client_finished,
        &server_flight,
        &mut handshake,
        &mut state,
    )
    .await?;
    Ok(state)
}

struct ClientHandshakeIo<'a, U, D> {
    transport: &'a mut U,
    delay: &'a D,
    local: SocketAddr,
    peer: SocketAddr,
    next_epoch_zero_record: &'a mut u64,
}

async fn wait_for_hello_verify<U, D>(
    io: ClientHandshakeIo<'_, U, D>,
    client_flight: &mut [DtlsRecord],
    hello_state: &mut DtlsClientHelloState,
) -> DriverResult<(), U::Error>
where
    U: UnconnectedUdp,
    D: DelayNs + Clone,
{
    let mut schedule = RetransmitSchedule::new();
    loop {
        let (records, _, _) =
            match recv_records_from(io.transport, io.delay, io.peer, schedule.timeout()).await {
                Ok(received) => received,
                Err(DriverError::Timeout) => {
                    renumber_epoch_zero_flight(client_flight, io.next_epoch_zero_record);
                    send_records(io.transport, io.local, io.peer, client_flight).await?;
                    schedule.back_off();
                    continue;
                }
                Err(error) => return Err(error),
            };
        for record in records {
            match record.header.content_type {
                ContentType::Handshake => {
                    let messages = parse_unfragmented_handshake_messages(&record)?;
                    if messages
                        .iter()
                        .any(|message| message.message_type == HandshakeType::HelloVerifyRequest)
                    {
                        hello_state.handle_hello_verify_request(&record)?;
                        dtls_trace(format_args!(
                            "recv HelloVerifyRequest cookie_len={}",
                            hello_state.cookie().len()
                        ));
                        return Ok(());
                    }
                }
                ContentType::Alert => return Err(decode_alert_error(&record).into()),
                _ => {}
            }
        }
    }
}

async fn wait_for_server_flight<U, D>(
    io: ClientHandshakeIo<'_, U, D>,
    client_flight: &mut Vec<DtlsRecord>,
    hello_state: &mut DtlsClientHelloState,
    client_hello_message: &mut crate::HandshakeMessage,
    handshake: &mut ThreadDtlsHandshake,
) -> DriverResult<Vec<crate::HandshakeMessage>, U::Error>
where
    U: UnconnectedUdp,
    D: DelayNs + Clone,
{
    let mut schedule = RetransmitSchedule::new();
    let mut duplicate_retransmissions = DuplicateRetransmitBudget::new();
    let mut recorded_client_hello = false;
    let mut server_flight = Vec::new();
    'receive: loop {
        let (records, _, _) =
            match recv_records_from(io.transport, io.delay, io.peer, schedule.timeout()).await {
                Ok(received) => received,
                Err(DriverError::Timeout) => {
                    renumber_epoch_zero_flight(client_flight, io.next_epoch_zero_record);
                    send_records(io.transport, io.local, io.peer, client_flight).await?;
                    schedule.back_off();
                    continue;
                }
                Err(error) => return Err(error),
            };
        for record in records {
            match record.header.content_type {
                ContentType::Handshake => {
                    for message in parse_unfragmented_handshake_messages(&record)? {
                        if server_flight.contains(&message) {
                            continue;
                        }
                        dtls_trace(format_args!(
                            "recv handshake {:?} message_seq={} len={}",
                            message.message_type,
                            message.message_seq,
                            message.payload.len()
                        ));
                        match message.message_type {
                            HandshakeType::ServerHello => {
                                if !recorded_client_hello {
                                    handshake.record_client_hello(client_hello_message)?;
                                    recorded_client_hello = true;
                                }
                                let hello = handshake.handle_server_hello(&message)?;
                                dtls_trace(format_args!(
                                    "server extensions={:?}",
                                    hello
                                        .extensions
                                        .iter()
                                        .map(|extension| extension.extension_type)
                                        .collect::<Vec<_>>()
                                ));
                                server_flight.push(message);
                            }
                            HandshakeType::ServerKeyExchange => {
                                if !recorded_client_hello {
                                    continue;
                                }
                                handshake.handle_server_key_exchange(&message)?;
                                server_flight.push(message);
                            }
                            HandshakeType::ServerHelloDone => {
                                let has_server_key_exchange = server_flight.iter().any(|message| {
                                    message.message_type == HandshakeType::ServerKeyExchange
                                });
                                if !recorded_client_hello || !has_server_key_exchange {
                                    continue;
                                }
                                handshake.handle_server_hello_done(&message)?;
                                server_flight.push(message);
                                return Ok(server_flight);
                            }
                            HandshakeType::HelloVerifyRequest => {
                                // Once ServerHello has committed the peer to
                                // this cookie exchange, a reordered HVR is
                                // stale and must not rewrite the transcript.
                                if recorded_client_hello {
                                    continue;
                                }
                                if !duplicate_retransmissions.take() {
                                    continue;
                                }
                                if hello_state.handle_hello_verify_request(&record).is_ok() {
                                    *client_flight = vec![hello_state.next_client_hello_record()?];
                                    renumber_epoch_zero_flight(
                                        client_flight,
                                        io.next_epoch_zero_record,
                                    );
                                    *client_hello_message = parse_unfragmented_handshake_record(
                                        &client_flight[0],
                                        HandshakeType::ClientHello,
                                    )?;
                                    schedule = RetransmitSchedule::new();
                                } else {
                                    renumber_epoch_zero_flight(
                                        client_flight,
                                        io.next_epoch_zero_record,
                                    );
                                }
                                send_records(io.transport, io.local, io.peer, client_flight)
                                    .await?;
                                continue 'receive;
                            }
                            _ => {
                                return Err(Error::Crypto(format!(
                                    "unexpected DTLS handshake message {:?}",
                                    message.message_type
                                ))
                                .into());
                            }
                        }
                    }
                }
                ContentType::Alert => return Err(decode_alert_error(&record).into()),
                _ => {}
            }
        }
    }
}

async fn wait_for_server_finished<U, D>(
    io: ClientHandshakeIo<'_, U, D>,
    client_flight: &mut Vec<DtlsRecord>,
    client_key_exchange: &crate::HandshakeMessage,
    client_finished: &crate::HandshakeMessage,
    server_flight: &[crate::HandshakeMessage],
    handshake: &mut ThreadDtlsHandshake,
    state: &mut SessionState,
) -> DriverResult<(), U::Error>
where
    U: UnconnectedUdp,
    D: DelayNs + Clone,
{
    let mut schedule = RetransmitSchedule::new();
    let mut duplicate_retransmissions = DuplicateRetransmitBudget::new();
    let mut saw_change_cipher_spec = false;
    loop {
        let (records, _, _) =
            match recv_records_from(io.transport, io.delay, io.peer, schedule.timeout()).await {
                Ok(received) => received,
                Err(DriverError::Timeout) => {
                    *client_flight = build_client_finished_flight(
                        client_key_exchange,
                        client_finished,
                        state,
                        io.next_epoch_zero_record,
                    )?;
                    send_records(io.transport, io.local, io.peer, client_flight).await?;
                    schedule.back_off();
                    continue;
                }
                Err(error) => return Err(error),
            };

        if is_retransmitted_server_flight(&records, server_flight) {
            if duplicate_retransmissions.take() {
                *client_flight = build_client_finished_flight(
                    client_key_exchange,
                    client_finished,
                    state,
                    io.next_epoch_zero_record,
                )?;
                send_records(io.transport, io.local, io.peer, client_flight).await?;
            }
            continue;
        }
        for record in records {
            match (record.header.epoch, record.header.content_type) {
                (0, ContentType::ChangeCipherSpec) => {
                    if record.payload != [1] {
                        return Err(
                            Error::Crypto("invalid ChangeCipherSpec payload".to_string()).into(),
                        );
                    }
                    dtls_trace(format_args!(
                        "recv ChangeCipherSpec epoch={} seq={}",
                        record.header.epoch, record.header.sequence_number
                    ));
                    saw_change_cipher_spec = true;
                }
                (1, ContentType::Handshake) => {
                    if !saw_change_cipher_spec {
                        continue;
                    }
                    let plaintext = open_aes_128_ccm_8_record(
                        &record,
                        RecordProtectionKey::new(state.key_material().key_block.server_write_key),
                        &state.key_material().key_block.server_write_iv,
                    )?;
                    let plain_record = DtlsRecord::new(ContentType::Handshake, 1, 0, plaintext)?;
                    for message in parse_unfragmented_handshake_messages(&plain_record)? {
                        dtls_trace(format_args!(
                            "recv encrypted handshake {:?} message_seq={} len={}",
                            message.message_type,
                            message.message_seq,
                            message.payload.len()
                        ));
                        if message.message_type == HandshakeType::Finished {
                            handshake.verify_server_finished(&message, state.key_material())?;
                            return Ok(());
                        }
                    }
                }
                (0, ContentType::Alert) => return Err(decode_alert_error(&record).into()),
                (1, ContentType::Alert) => {
                    let plaintext = open_aes_128_ccm_8_record(
                        &record,
                        RecordProtectionKey::new(state.key_material().key_block.server_write_key),
                        &state.key_material().key_block.server_write_iv,
                    )?;
                    let alert = DtlsRecord::new(
                        ContentType::Alert,
                        1,
                        record.header.sequence_number,
                        plaintext,
                    )?;
                    return Err(decode_alert_error(&alert).into());
                }
                _ => {}
            }
        }
    }
}

fn is_retransmitted_server_flight(
    records: &[DtlsRecord],
    expected: &[crate::HandshakeMessage],
) -> bool {
    let mut messages = Vec::new();
    for record in records {
        if record.header.epoch != 0 || record.header.content_type != ContentType::Handshake {
            continue;
        }
        let Ok(parsed) = parse_unfragmented_handshake_messages(record) else {
            return false;
        };
        messages.extend(parsed);
    }
    messages == expected
}

fn build_client_finished_flight(
    client_key_exchange: &crate::HandshakeMessage,
    client_finished: &crate::HandshakeMessage,
    state: &mut SessionState,
    next_epoch_zero_record: &mut u64,
) -> crate::Result<Vec<DtlsRecord>> {
    Ok(vec![
        DtlsRecord::new(
            ContentType::Handshake,
            0,
            take_record_sequence(next_epoch_zero_record),
            client_key_exchange.encode()?,
        )?,
        DtlsRecord::new(
            ContentType::ChangeCipherSpec,
            0,
            take_record_sequence(next_epoch_zero_record),
            vec![1],
        )?,
        state.protect_record(ContentType::Handshake, &client_finished.encode()?)?,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HandshakeMessage;

    #[test]
    fn identifies_only_the_expected_epoch_zero_server_handshake_flight() {
        let server_hello = HandshakeMessage {
            message_type: HandshakeType::ServerHello,
            message_seq: 1,
            payload: Vec::new(),
        };
        let server_record = DtlsRecord::new(
            ContentType::Handshake,
            0,
            1,
            server_hello.clone().encode().expect("encode server hello"),
        )
        .expect("build server record");
        assert!(is_retransmitted_server_flight(
            core::slice::from_ref(&server_record),
            core::slice::from_ref(&server_hello)
        ));

        let mut wrong_epoch = server_record;
        wrong_epoch.header.epoch = 1;
        assert!(!is_retransmitted_server_flight(
            &[wrong_epoch],
            core::slice::from_ref(&server_hello)
        ));
        let application = DtlsRecord::new(ContentType::ApplicationData, 1, 1, Vec::new())
            .expect("build application record");
        assert!(!is_retransmitted_server_flight(
            &[application],
            core::slice::from_ref(&server_hello)
        ));

        let malformed = DtlsRecord::new(ContentType::Handshake, 0, 2, vec![0xff])
            .expect("build malformed handshake record");
        assert!(!is_retransmitted_server_flight(
            &[malformed],
            core::slice::from_ref(&server_hello)
        ));
    }
}
