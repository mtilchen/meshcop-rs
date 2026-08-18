//! Runtime-neutral asynchronous DTLS server driver.

use alloc::{format, string::ToString, vec, vec::Vec};
use core::{net::SocketAddr, time::Duration};

use rand_core::{CryptoRng, RngCore};

use crate::{
    ClientHello, ContentType, DTLS_1_2_VERSION, DtlsCookieGenerator, DtlsRecord, Error,
    HandshakeMessage, HandshakeType, HelloVerifyRequest, RecordProtectionKey,
    ThreadDtlsKeyMaterial, ThreadDtlsServerHandshake,
    driver::{
        DelayNs, DriverResult, SessionRole, SessionState, UnconnectedUdp, decode_alert_error,
        recv_application_data, recv_records, send_records,
    },
    open_aes_128_ccm_8_record, parse_unfragmented_handshake_messages,
    parse_unfragmented_handshake_record, protect_aes_128_ccm_8_record,
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
    pub async fn accept_with_rng(
        mut self,
        rng: &mut (impl RngCore + CryptoRng),
        pskc: &[u8],
        timeout: Duration,
    ) -> DriverResult<DtlsServerSession<U, D>, U::Error> {
        let accepted =
            accept_with_rng(rng, &mut self.transport, &mut self.delay, pskc, timeout).await?;
        Ok(DtlsServerSession {
            transport: self.transport,
            delay: self.delay,
            local: accepted.local,
            peer: accepted.peer,
            state: SessionState::new(accepted.key_material, SessionRole::Server),
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

    /// Receives protected application data and sends a protected response.
    pub async fn respond_application_data(
        &mut self,
        response: &[u8],
        timeout: Duration,
    ) -> DriverResult<Vec<u8>, U::Error> {
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
    key_material: ThreadDtlsKeyMaterial,
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
    D: DelayNs,
{
    let cookies = DtlsCookieGenerator::new_with_rng(rng);
    let mut next_epoch_zero_record = 0u64;
    let (local, peer, client_hello) = loop {
        let (records, local, peer) = recv_records(transport, delay, timeout).await?;
        let mut accepted = None;
        for record in records {
            if record.header.epoch != 0 || record.header.content_type != ContentType::Handshake {
                continue;
            }
            for message in parse_unfragmented_handshake_messages(&record)? {
                if message.message_type != HandshakeType::ClientHello {
                    continue;
                }
                let hello = ClientHello::decode(&message.payload)?;
                if cookies.verify(&hello.random, &hello.cookie) {
                    accepted = Some(message);
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
                    next_epoch_zero_record,
                    verify.encode()?,
                )?;
                next_epoch_zero_record = next_epoch_zero_record.wrapping_add(1);
                send_records(transport, local, peer, &[verify_record]).await?;
            }
            if accepted.is_some() {
                break;
            }
        }
        if let Some(message) = accepted {
            break (local, peer, message);
        }
    };

    let mut handshake = ThreadDtlsServerHandshake::new_with_rng(rng, pskc);
    handshake.handle_client_hello(&client_hello)?;
    let mut server_flight = Vec::new();
    for message in [
        handshake.build_server_hello(1)?,
        handshake.build_server_key_exchange(2, rng)?,
        handshake.build_server_hello_done(3)?,
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

    let mut saw_change_cipher_spec = false;
    let mut key_material = None;
    loop {
        let (records, _, source) = recv_records(transport, delay, timeout).await?;
        if source != peer {
            continue;
        }
        for record in records {
            match (record.header.epoch, record.header.content_type) {
                (0, ContentType::Handshake) => {
                    for message in parse_unfragmented_handshake_messages(&record)? {
                        if message.message_type != HandshakeType::ClientKeyExchange {
                            return Err(Error::Crypto(format!(
                                "unexpected DTLS handshake message {:?}",
                                message.message_type
                            ))
                            .into());
                        }
                        handshake.handle_client_key_exchange(&message)?;
                        key_material = Some(handshake.derive_key_material()?);
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
                        return Err(Error::Crypto(
                            "client Finished before ChangeCipherSpec".to_string(),
                        )
                        .into());
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
                    let server_finished = handshake.build_server_finished(4, keys)?;
                    let change_cipher_spec = DtlsRecord::new(
                        ContentType::ChangeCipherSpec,
                        0,
                        next_epoch_zero_record,
                        vec![1],
                    )?;
                    let protected_finished = protect_aes_128_ccm_8_record(
                        ContentType::Handshake,
                        1,
                        0,
                        RecordProtectionKey::new(keys.key_block.server_write_key),
                        &keys.key_block.server_write_iv,
                        &server_finished.encode()?,
                    )?;
                    send_records(
                        transport,
                        local,
                        peer,
                        &[change_cipher_spec, protected_finished],
                    )
                    .await?;
                    let key_material = key_material
                        .ok_or(Error::InvalidState("client key material is missing"))?;
                    return Ok(Accepted {
                        local,
                        peer,
                        key_material,
                    });
                }
                (_, ContentType::Alert) => return Err(decode_alert_error(&record).into()),
                _ => {}
            }
        }
    }
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
