//! Mesh Five-O's Thread MeshCoP DTLS 1.2 profile.
//!
//! This crate implements the DTLS 1.2 handshake and record-protection profile
//! that Thread commissioner sessions use: EC J-PAKE authentication over the
//! commissioner PSKc (and the joiner PSKd), the TLS 1.2 PRF key schedule, and
//! AES-128-CCM-8 record protection. It exposes runtime-neutral client and
//! server handshake state machines plus runtime-generic async client and
//! server drivers ([`DtlsClient`] and [`DtlsServer`]). The existing
//! Tokio-backed [`DtlsSession`] API is retained as a convenience wrapper.
//!
//! The EC J-PAKE party and Schnorr NIZK primitives live in the public
//! [`ecjpake`] module. The `test-support` feature exposes an in-process
//! loopback DTLS server used by this workspace's deterministic handshake
//! tests; it is unstable scaffolding, not a supported public API.
//!
//! # Feature flags
//!
//! - `default` enables the Tokio client and server drivers.
//! - `tokio` enables Tokio transport adapters and implies `std`.
//! - `embedded` enables the runtime-neutral `embedded-nal-async` UDP and
//!   `embedded-hal-async` timer driver APIs without enabling `std`.
//! - `std` enables standard-library errors, tracing, and OS-backed randomness.
//! - `test-support` enables the Tokio-based loopback test server.
//!
//! With default features disabled, the runtime-neutral protocol and
//! cryptographic APIs support `no_std` environments with an allocator. The
//! crate's test suite expects default features because its loopback tests use
//! Tokio.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::unwrap_used, clippy::expect_used)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod ccm;
#[cfg(any(feature = "tokio", feature = "embedded"))]
mod client_driver;
mod constants;
#[cfg(any(feature = "tokio", feature = "embedded"))]
pub mod driver;
pub mod ecjpake;
mod error;
mod handshake;
mod hello;
mod key_schedule;
mod record;
mod record_protection;
#[cfg(any(feature = "tokio", feature = "embedded"))]
mod server_driver;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
mod thread_handshake;
mod thread_server_handshake;
#[cfg(feature = "tokio")]
mod tokio_session;
#[cfg(feature = "tokio")]
mod tokio_transport;
mod util;

pub use ccm::{
    AesCcm8, RecordProtectionKey, TLS_CCM_8_TAG_LEN, TLS_CCM_EXPLICIT_NONCE_LEN,
    TLS_CCM_FIXED_IV_LEN, TLS_CCM_NONCE_LEN, dtls_ccm_nonce,
};
#[cfg(any(feature = "tokio", feature = "embedded"))]
pub use client_driver::{DtlsClient, DtlsClientSession};
pub use constants::*;
pub use error::{Error, Result};
pub use handshake::{
    FinishedRole, HandshakeFragment, HandshakeHeader, HandshakeMessage, HandshakeReassembler,
    HandshakeTranscript, HandshakeType, parse_unfragmented_handshake_messages,
    parse_unfragmented_handshake_record,
};
pub use hello::{ClientHello, DtlsClientHelloState, HelloVerifyRequest, ServerHello, TlsExtension};
pub use key_schedule::{
    ThreadDtlsKeyMaterial, Tls12Aes128Ccm8KeyBlock, derive_aes_128_ccm_8_key_block,
    derive_joiner_router_kek, derive_master_secret, finished_verify_data, tls12_prf,
};
pub use record::{ContentType, DtlsRecord, RecordHeader};
pub use record_protection::{open_aes_128_ccm_8_record, protect_aes_128_ccm_8_record};
#[cfg(any(feature = "tokio", feature = "embedded"))]
pub use server_driver::{DtlsServer, DtlsServerSession};
pub use thread_handshake::ThreadDtlsHandshake;
pub use thread_server_handshake::{
    DTLS_COOKIE_LEN, DtlsCookieGenerator, ThreadDtlsServerHandshake,
};
#[cfg(feature = "tokio")]
pub use tokio_session::DtlsSession;
#[cfg(feature = "tokio")]
pub use tokio_transport::{TokioDelay, TokioUdpTransport};

#[cfg(test)]
mod tests;
