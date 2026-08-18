//! Runtime-neutral asynchronous DTLS client driver.

use alloc::{format, string::ToString, vec, vec::Vec};
use core::{net::SocketAddr, time::Duration};

use rand_core::{CryptoRng, RngCore};

use crate::{
    ContentType, DtlsClientHelloState, DtlsRecord, Error, HandshakeType, RecordProtectionKey,
    ThreadDtlsHandshake, ThreadDtlsKeyMaterial,
    driver::{
        DelayNs, DriverResult, SessionRole, SessionState, UnconnectedUdp, decode_alert_error,
        recv_application_data, recv_records, send_records,
    },
    open_aes_128_ccm_8_record, parse_unfragmented_handshake_messages,
    parse_unfragmented_handshake_record, protect_aes_128_ccm_8_record,
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
    pub async fn connect_with_rng(
        mut self,
        rng: &mut (impl RngCore + CryptoRng),
        pskc: &[u8],
        timeout: Duration,
    ) -> DriverResult<DtlsClientSession<U, D>, U::Error> {
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
    ) -> DriverResult<Vec<u8>, U::Error> {
        recv_application_data(
            &mut self.state,
            &mut self.transport,
            &mut self.delay,
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
    ) -> DriverResult<Vec<u8>, U::Error> {
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
    D: DelayNs,
{
    let mut handshake = ThreadDtlsHandshake::new_with_rng(rng, pskc);
    let mut hello_state = handshake.client_hello_state()?;

    let first_client_hello = hello_state.next_client_hello_record()?;
    dtls_trace(format_args!(
        "send first ClientHello record_seq={}",
        first_client_hello.header.sequence_number
    ));
    send_records(transport, local, peer, &[first_client_hello]).await?;
    wait_for_hello_verify(transport, delay, peer, &mut hello_state, timeout).await?;

    let second_client_hello = hello_state.next_client_hello_record()?;
    let client_hello_message =
        parse_unfragmented_handshake_record(&second_client_hello, HandshakeType::ClientHello)?;
    dtls_trace(format_args!(
        "send second ClientHello record_seq={} message_seq={}",
        second_client_hello.header.sequence_number, client_hello_message.message_seq
    ));
    handshake.record_client_hello(&client_hello_message)?;
    send_records(transport, local, peer, &[second_client_hello]).await?;

    wait_for_server_flight(transport, delay, peer, &mut handshake, timeout).await?;

    let client_key_exchange_seq = hello_state.next_message_sequence();
    let client_key_exchange = handshake.build_client_key_exchange(client_key_exchange_seq, rng)?;
    let key_material = handshake.derive_key_material()?;
    let client_finished =
        handshake.build_client_finished(client_key_exchange_seq.wrapping_add(1))?;

    let next_epoch_zero_record = hello_state.next_record_sequence();
    let client_key_exchange_record = DtlsRecord::new(
        ContentType::Handshake,
        0,
        next_epoch_zero_record,
        client_key_exchange.encode()?,
    )?;
    let change_cipher_spec = DtlsRecord::new(
        ContentType::ChangeCipherSpec,
        0,
        next_epoch_zero_record.wrapping_add(1),
        vec![1],
    )?;
    let client_finished_record = protect_aes_128_ccm_8_record(
        ContentType::Handshake,
        1,
        0,
        RecordProtectionKey::new(key_material.key_block.client_write_key),
        &key_material.key_block.client_write_iv,
        &client_finished.encode()?,
    )?;
    dtls_trace(format_args!(
        "send ClientKeyExchange message_seq={} record_seq={}, CCS record_seq={}, Finished message_seq={} epoch1_record_seq=0",
        client_key_exchange.message_seq,
        client_key_exchange_record.header.sequence_number,
        change_cipher_spec.header.sequence_number,
        client_finished.message_seq
    ));
    send_records(
        transport,
        local,
        peer,
        &[
            client_key_exchange_record,
            change_cipher_spec,
            client_finished_record,
        ],
    )
    .await?;

    wait_for_server_finished(
        transport,
        delay,
        peer,
        &mut handshake,
        &key_material,
        timeout,
    )
    .await?;
    Ok(SessionState::new(key_material, SessionRole::Client))
}

async fn wait_for_hello_verify<U, D>(
    transport: &mut U,
    delay: &mut D,
    peer: SocketAddr,
    hello_state: &mut DtlsClientHelloState,
    duration: Duration,
) -> DriverResult<(), U::Error>
where
    U: UnconnectedUdp,
    D: DelayNs,
{
    loop {
        let (records, _, source) = recv_records(transport, delay, duration).await?;
        if source != peer {
            continue;
        }
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
    transport: &mut U,
    delay: &mut D,
    peer: SocketAddr,
    handshake: &mut ThreadDtlsHandshake,
    duration: Duration,
) -> DriverResult<(), U::Error>
where
    U: UnconnectedUdp,
    D: DelayNs,
{
    loop {
        let (records, _, source) = recv_records(transport, delay, duration).await?;
        if source != peer {
            continue;
        }
        for record in records {
            match record.header.content_type {
                ContentType::Handshake => {
                    for message in parse_unfragmented_handshake_messages(&record)? {
                        dtls_trace(format_args!(
                            "recv handshake {:?} message_seq={} len={}",
                            message.message_type,
                            message.message_seq,
                            message.payload.len()
                        ));
                        match message.message_type {
                            HandshakeType::ServerHello => {
                                let hello = handshake.handle_server_hello(&message)?;
                                dtls_trace(format_args!(
                                    "server extensions={:?}",
                                    hello
                                        .extensions
                                        .iter()
                                        .map(|extension| extension.extension_type)
                                        .collect::<Vec<_>>()
                                ));
                            }
                            HandshakeType::ServerKeyExchange => {
                                handshake.handle_server_key_exchange(&message)?;
                            }
                            HandshakeType::ServerHelloDone => {
                                handshake.handle_server_hello_done(&message)?;
                                return Ok(());
                            }
                            HandshakeType::HelloVerifyRequest => {
                                return Err(Error::Crypto(
                                    "received unexpected second HelloVerifyRequest".to_string(),
                                )
                                .into());
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
    transport: &mut U,
    delay: &mut D,
    peer: SocketAddr,
    handshake: &mut ThreadDtlsHandshake,
    key_material: &ThreadDtlsKeyMaterial,
    duration: Duration,
) -> DriverResult<(), U::Error>
where
    U: UnconnectedUdp,
    D: DelayNs,
{
    let mut saw_change_cipher_spec = false;
    loop {
        let (records, _, source) = recv_records(transport, delay, duration).await?;
        if source != peer {
            continue;
        }
        for record in records {
            match (record.header.epoch, record.header.content_type) {
                (_, ContentType::ChangeCipherSpec) => {
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
                        return Err(Error::Crypto(
                            "received encrypted Finished before ChangeCipherSpec".to_string(),
                        )
                        .into());
                    }
                    let plaintext = open_aes_128_ccm_8_record(
                        &record,
                        RecordProtectionKey::new(key_material.key_block.server_write_key),
                        &key_material.key_block.server_write_iv,
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
                            handshake.verify_server_finished(&message, key_material)?;
                            return Ok(());
                        }
                    }
                }
                (_, ContentType::Alert) => return Err(decode_alert_error(&record).into()),
                _ => {}
            }
        }
    }
}
