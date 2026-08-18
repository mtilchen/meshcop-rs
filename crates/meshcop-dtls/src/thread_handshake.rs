//! Runtime-neutral Thread DTLS handshake state.

use alloc::string::ToString;

use rand_core::{CryptoRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    Result,
    ecjpake::{EcJpakeParty, EcJpakeRole, RoundOne, RoundTwo, THREAD_SERVER_ID},
    error::Error,
};

use super::{
    handshake::{FinishedRole, HandshakeMessage, HandshakeTranscript, HandshakeType},
    hello::{DtlsClientHelloState, ServerHello},
    key_schedule::{ThreadDtlsKeyMaterial, derive_aes_128_ccm_8_key_block, derive_master_secret},
    util::dtls_trace_secret,
};

/// Runtime-neutral client-side Thread DTLS 1.2 handshake state machine.
///
/// Callers feed in complete handshake messages and send out the messages it
/// builds; record framing and protection stay at the driver layer.
pub struct ThreadDtlsHandshake {
    ecjpake: EcJpakeParty,
    client_round_one: RoundOne,
    server_round_one: Option<RoundOne>,
    server_round_two: Option<RoundTwo>,
    client_random: [u8; 32],
    server_random: Option<[u8; 32]>,
    transcript: HandshakeTranscript,
}

impl ThreadDtlsHandshake {
    /// Creates a client-side Thread DTLS handshake state.
    pub fn new(pskc: &[u8], rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self::new_with_rng(rng, pskc)
    }

    /// Creates a client-side handshake with randomness supplied by the caller.
    pub fn new_with_rng(rng: &mut (impl RngCore + CryptoRng), pskc: &[u8]) -> Self {
        let mut client_random = [0u8; 32];
        rng.fill_bytes(&mut client_random);
        let ecjpake = EcJpakeParty::new_thread_with_rng(rng, EcJpakeRole::Client, pskc);
        let client_round_one = ecjpake.round_one(rng);
        Self {
            ecjpake,
            client_round_one,
            server_round_one: None,
            server_round_two: None,
            client_random,
            server_random: None,
            transcript: HandshakeTranscript::new(),
        }
    }

    /// Returns the client random used in ClientHello.
    pub const fn client_random(&self) -> [u8; 32] {
        self.client_random
    }

    /// Returns the client ECJPAKE round-one message.
    pub const fn client_round_one(&self) -> &RoundOne {
        &self.client_round_one
    }

    /// Returns the current handshake transcript.
    pub const fn transcript(&self) -> &HandshakeTranscript {
        &self.transcript
    }

    /// Builds a ClientHello cookie-retry state with cached ECJPAKE KKPP bytes.
    pub fn client_hello_state(&self) -> Result<DtlsClientHelloState> {
        Ok(DtlsClientHelloState::with_ecjpake_kkpp(
            self.client_random,
            self.client_round_one.encode_tls_kkpp()?,
        ))
    }

    /// Records an outgoing ClientHello after the cookie exchange.
    pub fn record_client_hello(&mut self, message: &HandshakeMessage) -> Result<()> {
        if message.message_type != HandshakeType::ClientHello {
            return Err(Error::Crypto("expected ClientHello message".to_string()));
        }
        self.transcript.push(message)
    }

    /// Parses and records the server's ServerHello and ECJPAKE KKPP extension.
    pub fn handle_server_hello(&mut self, message: &HandshakeMessage) -> Result<ServerHello> {
        if message.message_type != HandshakeType::ServerHello {
            return Err(Error::Crypto("expected ServerHello message".to_string()));
        }
        let hello = ServerHello::decode(&message.payload)?;
        hello.validate_thread_profile()?;
        let kkpp = hello
            .ecjpake_kkpp()
            .ok_or_else(|| Error::Crypto("ServerHello missing ECJPAKE KKPP".to_string()))?;
        self.server_round_one = Some(RoundOne::decode_tls_kkpp(kkpp, THREAD_SERVER_ID)?);
        self.server_random = Some(hello.random);
        self.transcript.push(message)?;
        Ok(hello)
    }

    /// Parses and records the server's ECJPAKE ServerKeyExchange.
    pub fn handle_server_key_exchange(&mut self, message: &HandshakeMessage) -> Result<RoundTwo> {
        if message.message_type != HandshakeType::ServerKeyExchange {
            return Err(Error::Crypto(
                "expected ServerKeyExchange message".to_string(),
            ));
        }
        let server_round_two =
            RoundTwo::decode_tls_key_exchange(&message.payload, THREAD_SERVER_ID, true)?;
        self.server_round_two = Some(server_round_two.clone());
        self.transcript.push(message)?;
        Ok(server_round_two)
    }

    /// Records the server's empty ServerHelloDone message.
    pub fn handle_server_hello_done(&mut self, message: &HandshakeMessage) -> Result<()> {
        if message.message_type != HandshakeType::ServerHelloDone || !message.payload.is_empty() {
            return Err(Error::Crypto(
                "expected empty ServerHelloDone message".to_string(),
            ));
        }
        self.transcript.push(message)
    }

    /// Builds and records the client's ECJPAKE ClientKeyExchange.
    pub fn build_client_key_exchange(
        &mut self,
        message_seq: u16,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<HandshakeMessage> {
        let server_round_one = self
            .server_round_one
            .as_ref()
            .ok_or(Error::InvalidState("server ECJPAKE round one is missing"))?;
        let client_round_two =
            self.ecjpake
                .round_two(&self.client_round_one, server_round_one, rng)?;
        let message = HandshakeMessage {
            message_type: HandshakeType::ClientKeyExchange,
            message_seq,
            payload: client_round_two.encode_tls_key_exchange(false)?,
        };
        self.transcript.push(&message)?;
        Ok(message)
    }

    /// Derives DTLS key material after server round two has been processed.
    pub fn derive_key_material(&self) -> Result<ThreadDtlsKeyMaterial> {
        let server_round_one = self
            .server_round_one
            .as_ref()
            .ok_or(Error::InvalidState("server ECJPAKE round one is missing"))?;
        let server_round_two = self
            .server_round_two
            .as_ref()
            .ok_or(Error::InvalidState("server ECJPAKE round two is missing"))?;
        let server_random = self
            .server_random
            .ok_or(Error::InvalidState("server random is missing"))?;
        let pre_master_secret = Zeroizing::new(self.ecjpake.finish(
            &self.client_round_one,
            server_round_one,
            server_round_two,
        )?);
        dtls_trace_secret("pre_master_secret", &*pre_master_secret);
        dtls_trace_secret("client_random", &self.client_random);
        dtls_trace_secret("server_random", &server_random);
        let master_secret =
            derive_master_secret(&*pre_master_secret, &self.client_random, &server_random)?;
        dtls_trace_secret("master_secret", &master_secret);
        let key_block =
            derive_aes_128_ccm_8_key_block(&master_secret, &self.client_random, &server_random)?;
        dtls_trace_secret("client_write_key", &key_block.client_write_key);
        dtls_trace_secret("server_write_key", &key_block.server_write_key);
        dtls_trace_secret("client_write_iv", &key_block.client_write_iv);
        dtls_trace_secret("server_write_iv", &key_block.server_write_iv);
        Ok(ThreadDtlsKeyMaterial {
            master_secret,
            key_block,
        })
    }

    /// Computes the client's Finished verify_data for the current transcript.
    pub fn client_finished_verify_data(&self) -> Result<[u8; 12]> {
        let key_material = self.derive_key_material()?;
        self.transcript
            .finished_verify_data(&key_material.master_secret, FinishedRole::Client)
    }

    /// Builds and records the client's encrypted-handshake Finished message.
    pub fn build_client_finished(&mut self, message_seq: u16) -> Result<HandshakeMessage> {
        let verify_data = self.client_finished_verify_data()?;
        dtls_trace_secret("client_finished_verify_data", &verify_data);
        let message = HandshakeMessage {
            message_type: HandshakeType::Finished,
            message_seq,
            payload: verify_data.to_vec(),
        };
        self.transcript.push(&message)?;
        Ok(message)
    }

    /// Verifies and records the server's Finished message.
    pub fn verify_server_finished(
        &mut self,
        message: &HandshakeMessage,
        key_material: &ThreadDtlsKeyMaterial,
    ) -> Result<()> {
        if message.message_type != HandshakeType::Finished {
            return Err(Error::Crypto("expected Finished message".to_string()));
        }
        let expected = self
            .transcript
            .finished_verify_data(&key_material.master_secret, FinishedRole::Server)?;
        if expected.ct_eq(message.payload.as_slice()).unwrap_u8() != 1 {
            return Err(Error::Crypto(
                "server Finished verify_data mismatch".to_string(),
            ));
        }
        self.transcript.push(message)
    }
}
