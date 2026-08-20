//! In-process DTLS loopback server shared by this crate's and the
//! commissioner's tests.
//!
//! This module is gated behind the `test-support` feature (and always built
//! under `cfg(test)`). It is unstable test scaffolding for this workspace's
//! suites, not a supported public API, and carries no stability guarantees.

use alloc::{format, string::ToString, vec, vec::Vec};

use tokio::net::UdpSocket;

use crate::{Error, Result, ccm::RecordProtectionKey};

use super::{
    ContentType, DTLS_1_2_VERSION, DtlsCookieGenerator, DtlsRecord, HandshakeMessage,
    HandshakeType, HelloVerifyRequest, ThreadDtlsKeyMaterial, ThreadDtlsServerHandshake,
    hello::ClientHello, open_aes_128_ccm_8_record, parse_unfragmented_handshake_messages,
    parse_unfragmented_handshake_record, protect_aes_128_ccm_8_record,
};

/// Returns the initial retransmit interval compiled into this driver build.
///
/// This accessor lets cross-crate and integration tests gate the production
/// default while unit tests scale the same state machines to a shorter wall
/// clock interval.
pub const fn driver_initial_retransmit_timeout() -> core::time::Duration {
    crate::driver::DRIVER_INITIAL_RETRANSMIT_TIMEOUT
}

/// How the loopback server finishes the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopbackEnd {
    /// Complete the handshake and return the session keys.
    Complete,
    /// Replace the first cookie, then complete the handshake.
    ReplaceCookieThenComplete,
    /// Send a plaintext fatal alert instead of the ChangeCipherSpec + Finished flight.
    AlertInsteadOfFinished,
    /// Send a protected fatal alert instead of the ChangeCipherSpec + Finished flight.
    ProtectedAlertInsteadOfFinished,
}

/// Serves one commissioner DTLS handshake over a connected UDP socket.
///
/// Returns the negotiated key material when the handshake completes.
pub async fn loopback_dtls_server(
    socket: &UdpSocket,
    psk: &[u8],
    end: LoopbackEnd,
) -> Result<Option<ThreadDtlsKeyMaterial>> {
    let mut rng = rand_core::OsRng;
    loopback_dtls_server_with_rng(&mut rng, socket, psk, end).await
}

/// Serves one commissioner handshake using caller-supplied randomness.
pub async fn loopback_dtls_server_with_rng(
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    socket: &UdpSocket,
    psk: &[u8],
    end: LoopbackEnd,
) -> Result<Option<ThreadDtlsKeyMaterial>> {
    let mut server = ThreadDtlsServerHandshake::new_with_rng(rng, psk);
    let cookies = DtlsCookieGenerator::new_with_rng(rng);
    let mut buf = [0u8; 4096];
    let mut epoch0_seq = 0u64;
    let mut saw_change_cipher_spec = false;
    let mut key_material: Option<ThreadDtlsKeyMaterial> = None;
    let replacement_cookie = vec![0xca, 0xfe, 0xba, 0xbe];
    let mut replacement_sent = false;
    let mut server_message_sequence = 1u16;

    loop {
        let len = tokio::time::timeout(core::time::Duration::from_secs(2), socket.recv(&mut buf))
            .await
            .map_err(|_| Error::Timeout("loopback server receive timed out"))??;
        for record in DtlsRecord::parse_datagram(&buf[..len])? {
            match (record.header.epoch, record.header.content_type) {
                (0, ContentType::Handshake) => {
                    for message in parse_unfragmented_handshake_messages(&record)? {
                        match message.message_type {
                            HandshakeType::ClientHello => {
                                let hello = ClientHello::decode(&message.payload)?;
                                let cookie_is_valid = if replacement_sent {
                                    hello.cookie == replacement_cookie
                                } else {
                                    cookies.verify(&hello.random, &hello.cookie)
                                };
                                let replace_cookie = end == LoopbackEnd::ReplaceCookieThenComplete
                                    && !hello.cookie.is_empty()
                                    && !replacement_sent;
                                if !cookie_is_valid || replace_cookie {
                                    let cookie = if replace_cookie {
                                        replacement_sent = true;
                                        replacement_cookie.clone()
                                    } else {
                                        cookies.cookie(&hello.random)?.to_vec()
                                    };
                                    let verify = HandshakeMessage {
                                        message_type: HandshakeType::HelloVerifyRequest,
                                        message_seq: message.message_seq,
                                        payload: HelloVerifyRequest {
                                            server_version: DTLS_1_2_VERSION,
                                            cookie,
                                        }
                                        .encode()?,
                                    };
                                    let record = DtlsRecord::new(
                                        ContentType::Handshake,
                                        0,
                                        record.header.sequence_number,
                                        verify.encode()?,
                                    )?;
                                    socket.send(&record.encode()?).await?;
                                    continue;
                                }
                                server.handle_client_hello(&message)?;
                                epoch0_seq = record.header.sequence_number;
                                server_message_sequence = message.message_seq;
                                let mut datagram = Vec::new();
                                for built in [
                                    server.build_server_hello(server_message_sequence)?,
                                    server.build_server_key_exchange(
                                        server_message_sequence.wrapping_add(1),
                                        rng,
                                    )?,
                                    server.build_server_hello_done(
                                        server_message_sequence.wrapping_add(2),
                                    )?,
                                ] {
                                    let record = DtlsRecord::new(
                                        ContentType::Handshake,
                                        0,
                                        epoch0_seq,
                                        built.encode()?,
                                    )?;
                                    epoch0_seq += 1;
                                    datagram.extend_from_slice(&record.encode()?);
                                }
                                socket.send(&datagram).await?;
                            }
                            HandshakeType::ClientKeyExchange => {
                                server.handle_client_key_exchange(&message)?;
                                key_material = Some(server.derive_key_material()?);
                            }
                            other => {
                                return Err(Error::Crypto(format!(
                                    "loopback server got {other:?}"
                                )));
                            }
                        }
                    }
                }
                (0, ContentType::ChangeCipherSpec) => saw_change_cipher_spec = true,
                (1, ContentType::Handshake) => {
                    let keys = key_material
                        .as_ref()
                        .ok_or(Error::InvalidState("no key material"))?;
                    if !saw_change_cipher_spec {
                        return Err(Error::Crypto(
                            "client Finished before ChangeCipherSpec".to_string(),
                        ));
                    }
                    if matches!(
                        end,
                        LoopbackEnd::AlertInsteadOfFinished
                            | LoopbackEnd::ProtectedAlertInsteadOfFinished
                    ) {
                        let alert = if end == LoopbackEnd::ProtectedAlertInsteadOfFinished {
                            protect_aes_128_ccm_8_record(
                                ContentType::Alert,
                                1,
                                0,
                                RecordProtectionKey::new(keys.key_block.server_write_key),
                                &keys.key_block.server_write_iv,
                                &[2, 40],
                            )?
                        } else {
                            DtlsRecord::new(ContentType::Alert, 0, epoch0_seq, vec![2, 40])?
                        };
                        socket.send(&alert.encode()?).await?;
                        return Ok(None);
                    }
                    let plaintext = match open_aes_128_ccm_8_record(
                        &record,
                        RecordProtectionKey::new(keys.key_block.client_write_key),
                        &keys.key_block.client_write_iv,
                    ) {
                        Ok(plaintext) => plaintext,
                        Err(error) => {
                            send_fatal_handshake_alert(socket, epoch0_seq).await?;
                            return Err(error);
                        }
                    };
                    let plain_record = DtlsRecord::new(ContentType::Handshake, 1, 0, plaintext)?;
                    let finished = parse_unfragmented_handshake_record(
                        &plain_record,
                        HandshakeType::Finished,
                    )?;
                    if let Err(error) = server.verify_client_finished(&finished, keys) {
                        send_fatal_handshake_alert(socket, epoch0_seq).await?;
                        return Err(error);
                    }
                    let server_finished = server
                        .build_server_finished(server_message_sequence.wrapping_add(3), keys)?;
                    let mut datagram =
                        DtlsRecord::new(ContentType::ChangeCipherSpec, 0, epoch0_seq, vec![1])?
                            .encode()?;
                    datagram.extend_from_slice(
                        &protect_aes_128_ccm_8_record(
                            ContentType::Handshake,
                            1,
                            0,
                            RecordProtectionKey::new(keys.key_block.server_write_key),
                            &keys.key_block.server_write_iv,
                            &server_finished.encode()?,
                        )?
                        .encode()?,
                    );
                    socket.send(&datagram).await?;
                    return Ok(key_material);
                }
                _ => {}
            }
        }
    }
}

/// Sends a fatal handshake-failure alert, mirroring the production
/// `server_driver` acceptor's behavior when the client's Finished fails to
/// decrypt or verify. Without this, a caller that intentionally sends a
/// Finished the server will reject (e.g. a mismatched-PSKc test) gets no
/// response at all and must wait out its full receive timeout instead of
/// observing a prompt alert.
async fn send_fatal_handshake_alert(socket: &UdpSocket, sequence_number: u64) -> Result<()> {
    const ALERT_LEVEL_FATAL: u8 = 2;
    const ALERT_HANDSHAKE_FAILURE: u8 = 40;
    let alert = DtlsRecord::new(
        ContentType::Alert,
        0,
        sequence_number,
        vec![ALERT_LEVEL_FATAL, ALERT_HANDSHAKE_FAILURE],
    )?;
    socket.send(&alert.encode()?).await?;
    Ok(())
}
