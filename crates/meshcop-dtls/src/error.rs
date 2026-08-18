//! Error and result types for the Thread DTLS profile.

use alloc::string::String;

/// Crate-wide result alias.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors returned by this crate.
///
/// Display strings match the variants this code produced before it became a
/// separate crate, so wrapped errors render identically downstream.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A cryptographic input or verification failed.
    #[error("crypto error: {0}")]
    Crypto(String),
    /// The session or handshake is not in the state the operation requires.
    #[error("invalid state: {0}")]
    InvalidState(&'static str),
    /// A protocol operation timed out.
    #[error("timeout: {0}")]
    Timeout(&'static str),
    /// An I/O operation failed.
    #[cfg(feature = "std")]
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
