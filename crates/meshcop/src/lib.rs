//! MeshCoP for Rust: a pure-Rust Thread MeshCoP commissioner.
//!
//! The crate provides the non-CCM commissioner feature set of the C++
//! `ot-commissioner` reference: dataset TLV codecs, MeshCoP/CoAP message
//! primitives, PSKc helpers, EC J-PAKE/Schnorr NIZK, AES-CCM-8 record
//! protection, and a Tokio-facing commissioner API. A commissioner session
//! can petition a border agent, keep the session alive, read and write
//! operational and commissioner datasets, run scans and network diagnostics
//! through the UDP proxy, and commission joiners end to end over the relay
//! (DTLS server handshake over PSKd, JOIN_FIN, and KEK entrustment).
//! See `docs/PARITY.md` for the feature matrix against the C++ reference.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// `unwrap`/`expect` are prohibited in production code (allowed in tests via
// `allow-{unwrap,expect}-in-tests` in `clippy.toml`). `cargo clippy -- -D
// warnings` promotes these to hard errors.
#![warn(clippy::unwrap_used, clippy::expect_used)]

//! # Public API
//!
//! The primary, supported surface is the high-level commissioner:
//! [`commissioner`] (the [`Commissioner`](commissioner::Commissioner) client,
//! its configuration, events, and flags), [`dataset`] (the operational
//! [`Dataset`](dataset::Dataset) and its typed accessors), [`error`], and the
//! network-diagnostic data model in [`meshcop::diag`] (surfaced through
//! commissioner events).
//!
//! The remaining modules — [`crypto`], [`tlv`], and the CoAP/MeshCoP codecs in
//! [`meshcop`] — are lower-level protocol building blocks. They are exported so
//! the coverage-guided fuzz harnesses can drive the wire parsers directly and
//! so advanced users can build or inspect MeshCoP messages, but they are not
//! the recommended entry point. The DTLS 1.2 profile and EC J-PAKE handshake
//! live in the separate `meshcop-dtls` crate. The example interactive REPL that
//! reimplements the C++ `ot-commissioner` CLI on top of this library lives in
//! the separate `ot-commissioner-cli` crate.

#[macro_use]
mod flags;

pub mod commissioner;
pub mod crypto;
pub mod dataset;
pub mod error;
pub mod meshcop;
pub mod tlv;
mod wire;

pub use error::{Error, Result};

/// Returns this crate's version string.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_reports_the_package_version() {
        let version = super::version();
        assert!(!version.is_empty());
        assert!(version.split('.').count() >= 3);
        assert_eq!(version, env!("CARGO_PKG_VERSION"));
    }
}
