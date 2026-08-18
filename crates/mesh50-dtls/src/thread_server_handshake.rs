//! Runtime-neutral Thread DTLS server-side handshake state.
//!
//! The commissioner acts as a DTLS 1.2 server towards joiners relayed through
//! RLY_RX/RLY_TX, authenticating with EC J-PAKE over the joiner PSKd. This
//! mirrors [`super::thread_handshake::ThreadDtlsHandshake`] for the server
//! role: callers feed complete handshake messages in and send the built
//! messages out, while record framing and protection stay at the driver layer.

use alloc::{string::ToString, vec, vec::Vec};

use hmac::{Hmac, Mac};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    Result,
    ecjpake::{EcJpakeParty, EcJpakeRole, RoundOne, RoundTwo, THREAD_CLIENT_ID},
    error::Error,
};

use super::{
    constants::*,
    handshake::{FinishedRole, HandshakeMessage, HandshakeTranscript, HandshakeType},
    hello::{ClientHello, ServerHello, TlsExtension, ec_point_formats_extension},
    key_schedule::{ThreadDtlsKeyMaterial, derive_aes_128_ccm_8_key_block, derive_master_secret},
    util::dtls_trace_secret,
};

/// Stateless HelloVerifyRequest cookie generator.
///
/// Cookies are an HMAC over the ClientHello random, so the server commits no
/// per-client state until a client proves it can receive datagrams.
pub struct DtlsCookieGenerator {
    key: [u8; 32],
}

impl core::fmt::Debug for DtlsCookieGenerator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DtlsCookieGenerator")
            .field("key", &"<redacted>")
            .finish()
    }
}

/// Cookie length included in HelloVerifyRequest messages.
pub const DTLS_COOKIE_LEN: usize = 16;

impl DtlsCookieGenerator {
    /// Creates a generator with a random HMAC key.
    pub fn new(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self::new_with_rng(rng)
    }

    /// Creates a generator with an HMAC key from caller-supplied randomness.
    pub fn new_with_rng(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        Self { key }
    }

    /// Computes the cookie for a ClientHello random.
    pub fn cookie(&self, client_random: &[u8; 32]) -> Result<[u8; DTLS_COOKIE_LEN]> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key)
            .map_err(|_| Error::Crypto("invalid cookie HMAC key".to_string()))?;
        mac.update(client_random);
        let digest = mac.finalize().into_bytes();
        let mut out = [0u8; DTLS_COOKIE_LEN];
        out.copy_from_slice(&digest[..DTLS_COOKIE_LEN]);
        Ok(out)
    }

    /// Verifies a cookie echoed in a ClientHello.
    ///
    /// Returns `false` if the cookie does not match (or, defensively, if the
    /// HMAC key is somehow unusable) rather than panicking.
    pub fn verify(&self, client_random: &[u8; 32], cookie: &[u8]) -> bool {
        match self.cookie(client_random) {
            Ok(expected) => expected.ct_eq(cookie).unwrap_u8() == 1,
            Err(_) => false,
        }
    }
}

/// Server-side Thread DTLS handshake state machine.
pub struct ThreadDtlsServerHandshake {
    ecjpake: EcJpakeParty,
    server_round_one: RoundOne,
    client_round_one: Option<RoundOne>,
    client_round_two: Option<RoundTwo>,
    server_random: [u8; 32],
    client_random: Option<[u8; 32]>,
    transcript: HandshakeTranscript,
}

impl ThreadDtlsServerHandshake {
    /// Creates a server-side handshake authenticated by `shared_secret`.
    ///
    /// For joiner sessions the shared secret is the joiner PSKd bytes; for
    /// commissioner sessions it would be the PSKc.
    pub fn new(shared_secret: &[u8], rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self::new_with_rng(rng, shared_secret)
    }

    /// Creates a server-side handshake with randomness supplied by the caller.
    pub fn new_with_rng(rng: &mut (impl RngCore + CryptoRng), shared_secret: &[u8]) -> Self {
        let mut server_random = [0u8; 32];
        rng.fill_bytes(&mut server_random);
        let ecjpake = EcJpakeParty::new_thread_with_rng(rng, EcJpakeRole::Server, shared_secret);
        let server_round_one = ecjpake.round_one(rng);
        Self {
            ecjpake,
            server_round_one,
            client_round_one: None,
            client_round_two: None,
            server_random,
            client_random: None,
            transcript: HandshakeTranscript::new(),
        }
    }

    /// Returns the server random used in ServerHello.
    pub const fn server_random(&self) -> [u8; 32] {
        self.server_random
    }

    /// Returns the client random once a ClientHello has been accepted.
    pub const fn client_random(&self) -> Option<[u8; 32]> {
        self.client_random
    }

    /// Returns the current handshake transcript.
    pub const fn transcript(&self) -> &HandshakeTranscript {
        &self.transcript
    }

    /// Validates and records the cookie-bearing ClientHello.
    ///
    /// The cookie exchange itself is handled by the caller: per RFC 6347 the
    /// initial ClientHello and HelloVerifyRequest are excluded from the
    /// handshake transcript, so only the retried ClientHello enters here.
    pub fn handle_client_hello(&mut self, message: &HandshakeMessage) -> Result<ClientHello> {
        if message.message_type != HandshakeType::ClientHello {
            return Err(Error::Crypto("expected ClientHello message".to_string()));
        }
        let hello = ClientHello::decode(&message.payload)?;
        if !hello
            .cipher_suites
            .contains(&TLS_ECJPAKE_WITH_AES_128_CCM_8)
        {
            return Err(Error::Crypto(
                "ClientHello does not offer TLS_ECJPAKE_WITH_AES_128_CCM_8".to_string(),
            ));
        }
        if !hello.compression_methods.contains(&TLS_COMPRESSION_NULL) {
            return Err(Error::Crypto(
                "ClientHello does not offer null compression".to_string(),
            ));
        }
        let kkpp = hello
            .ecjpake_kkpp()
            .ok_or_else(|| Error::Crypto("ClientHello missing ECJPAKE KKPP".to_string()))?;
        self.client_round_one = Some(RoundOne::decode_tls_kkpp(kkpp, THREAD_CLIENT_ID)?);
        self.client_random = Some(hello.random);
        self.transcript.push(message)?;
        Ok(hello)
    }

    /// Builds and records the ServerHello carrying the server's ECJPAKE KKPP.
    pub fn build_server_hello(&mut self, message_seq: u16) -> Result<HandshakeMessage> {
        if self.client_random.is_none() {
            return Err(Error::InvalidState("ClientHello has not been accepted"));
        }
        let hello = ServerHello {
            random: self.server_random,
            session_id: Vec::new(),
            cipher_suite: TLS_ECJPAKE_WITH_AES_128_CCM_8,
            compression_method: TLS_COMPRESSION_NULL,
            extensions: vec![
                TlsExtension {
                    extension_type: EXTENSION_ECJPAKE_KKPP,
                    data: self.server_round_one.encode_tls_kkpp()?,
                },
                ec_point_formats_extension(),
            ],
        };
        let message = HandshakeMessage {
            message_type: HandshakeType::ServerHello,
            message_seq,
            payload: hello.encode()?,
        };
        self.transcript.push(&message)?;
        Ok(message)
    }

    /// Builds and records the ECJPAKE ServerKeyExchange.
    pub fn build_server_key_exchange(
        &mut self,
        message_seq: u16,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<HandshakeMessage> {
        let client_round_one = self
            .client_round_one
            .as_ref()
            .ok_or(Error::InvalidState("client ECJPAKE round one is missing"))?;
        let server_round_two =
            self.ecjpake
                .round_two(&self.server_round_one, client_round_one, rng)?;
        let message = HandshakeMessage {
            message_type: HandshakeType::ServerKeyExchange,
            message_seq,
            payload: server_round_two.encode_tls_key_exchange(true)?,
        };
        self.transcript.push(&message)?;
        Ok(message)
    }

    /// Builds and records the empty ServerHelloDone.
    pub fn build_server_hello_done(&mut self, message_seq: u16) -> Result<HandshakeMessage> {
        let message = HandshakeMessage {
            message_type: HandshakeType::ServerHelloDone,
            message_seq,
            payload: Vec::new(),
        };
        self.transcript.push(&message)?;
        Ok(message)
    }

    /// Parses and records the client's ECJPAKE ClientKeyExchange.
    pub fn handle_client_key_exchange(&mut self, message: &HandshakeMessage) -> Result<()> {
        if message.message_type != HandshakeType::ClientKeyExchange {
            return Err(Error::Crypto(
                "expected ClientKeyExchange message".to_string(),
            ));
        }
        let client_round_two =
            RoundTwo::decode_tls_key_exchange(&message.payload, THREAD_CLIENT_ID, false)?;
        self.client_round_two = Some(client_round_two);
        self.transcript.push(message)?;
        Ok(())
    }

    /// Derives DTLS key material after the ClientKeyExchange was processed.
    pub fn derive_key_material(&self) -> Result<ThreadDtlsKeyMaterial> {
        let client_round_one = self
            .client_round_one
            .as_ref()
            .ok_or(Error::InvalidState("client ECJPAKE round one is missing"))?;
        let client_round_two = self
            .client_round_two
            .as_ref()
            .ok_or(Error::InvalidState("client ECJPAKE round two is missing"))?;
        let client_random = self
            .client_random
            .ok_or(Error::InvalidState("client random is missing"))?;
        let pre_master_secret = Zeroizing::new(self.ecjpake.finish(
            &self.server_round_one,
            client_round_one,
            client_round_two,
        )?);
        dtls_trace_secret("server pre_master_secret", &*pre_master_secret);
        let master_secret =
            derive_master_secret(&*pre_master_secret, &client_random, &self.server_random)?;
        let key_block =
            derive_aes_128_ccm_8_key_block(&master_secret, &client_random, &self.server_random)?;
        Ok(ThreadDtlsKeyMaterial {
            master_secret,
            key_block,
        })
    }

    /// Verifies and records the client's Finished message.
    pub fn verify_client_finished(
        &mut self,
        message: &HandshakeMessage,
        key_material: &ThreadDtlsKeyMaterial,
    ) -> Result<()> {
        if message.message_type != HandshakeType::Finished {
            return Err(Error::Crypto("expected Finished message".to_string()));
        }
        let expected = self
            .transcript
            .finished_verify_data(&key_material.master_secret, FinishedRole::Client)?;
        if expected.ct_eq(message.payload.as_slice()).unwrap_u8() != 1 {
            return Err(Error::Crypto(
                "client Finished verify_data mismatch".to_string(),
            ));
        }
        self.transcript.push(message)
    }

    /// Builds and records the server's encrypted-handshake Finished message.
    pub fn build_server_finished(
        &mut self,
        message_seq: u16,
        key_material: &ThreadDtlsKeyMaterial,
    ) -> Result<HandshakeMessage> {
        let verify_data = self
            .transcript
            .finished_verify_data(&key_material.master_secret, FinishedRole::Server)?;
        let message = HandshakeMessage {
            message_type: HandshakeType::Finished,
            message_seq,
            payload: verify_data.to_vec(),
        };
        self.transcript.push(&message)?;
        Ok(message)
    }

    /// Derives the Joiner Router KEK for this session.
    ///
    /// Thread derives the KEK by hashing the AES-128-CCM-8 key block:
    /// `SHA-256(PRF(master_secret, "key expansion", server_random ||
    /// client_random)[0..40])` truncated to 16 bytes, matching mbedTLS-based
    /// stacks on both sides of the JOIN_FIN exchange.
    pub fn derive_joiner_router_kek(
        &self,
        key_material: &ThreadDtlsKeyMaterial,
    ) -> Result<[u8; 16]> {
        let client_random = self
            .client_random
            .ok_or(Error::InvalidState("client random is missing"))?;
        super::key_schedule::derive_joiner_router_kek(
            &key_material.master_secret,
            &client_random,
            &self.server_random,
        )
    }
}

impl core::fmt::Debug for ThreadDtlsServerHandshake {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ThreadDtlsServerHandshake")
            .field("client_hello_seen", &self.client_random.is_some())
            .field("client_key_exchange_seen", &self.client_round_two.is_some())
            .finish_non_exhaustive()
    }
}
