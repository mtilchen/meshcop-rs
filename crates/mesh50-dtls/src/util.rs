//! Shared DTLS utility helpers.

use alloc::string::ToString;

use crate::{Result, error::Error};

pub(crate) const MAX_U24: u32 = 0x00ff_ffff;

pub(crate) fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}

pub(crate) fn read_u24(bytes: &[u8]) -> u32 {
    ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32
}

pub(crate) fn write_u24(value: u32, out: &mut [u8]) -> Result<()> {
    if value > MAX_U24 || out.len() != 3 {
        return Err(Error::Crypto("invalid 24-bit integer".to_string()));
    }
    out[0] = (value >> 16) as u8;
    out[1] = (value >> 8) as u8;
    out[2] = value as u8;
    Ok(())
}

#[cfg(feature = "std")]
pub(crate) fn dtls_trace(args: core::fmt::Arguments<'_>) {
    trace("MESH50_TRACE", "dtls", args);
}

#[cfg(not(feature = "std"))]
#[inline]
pub(crate) fn dtls_trace(_args: core::fmt::Arguments<'_>) {}

#[cfg(feature = "std")]
pub(crate) fn dtls_trace_secret(label: &str, bytes: &[u8]) {
    trace(
        "MESH50_TRACE_SECRETS",
        "dtls-secret",
        format_args!("{label}={}", hex::encode(bytes)),
    );
}

#[cfg(feature = "std")]
fn trace(env_var: &str, tag: &str, args: core::fmt::Arguments<'_>) {
    if std::env::var_os(env_var).is_some() {
        eprintln!("[{tag}] {args}");
    }
}

#[cfg(not(feature = "std"))]
#[inline]
pub(crate) fn dtls_trace_secret(label: &str, _bytes: &[u8]) {
    dtls_trace(format_args!("{label}"));
}
