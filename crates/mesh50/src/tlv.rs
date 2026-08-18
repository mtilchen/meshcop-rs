//! Lightweight Thread-style TLV parsing and serialization.

use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

/// Maximum length encoded by the one-byte TLV length field.
pub const MAX_STANDARD_TLV_LENGTH: usize = 254;

/// Marker byte that switches a TLV to the extended two-byte length form.
pub const EXTENDED_TLV_MARKER: u8 = 0xff;

/// Maximum payload length in the extended TLV form.
pub const MAX_EXTENDED_TLV_LENGTH: usize = u16::MAX as usize;

/// TLV parser/encoder errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TlvError {
    /// A TLV header or value ended before enough bytes were available.
    #[error("buffer too small")]
    BufferTooSmall,

    /// A TLV value length is invalid for the target representation.
    #[error("invalid TLV length")]
    InvalidLength,

    /// A TLV value is not valid for the target representation.
    #[error("invalid TLV value")]
    InvalidValue,

    /// The TLV value is too long to encode.
    #[error("TLV value too large: {0} bytes")]
    ValueTooLarge(usize),
}

/// One parsed TLV entry.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize)]
pub struct TlvEntry {
    /// Numeric TLV type.
    pub ty: u8,
    /// Raw value bytes.
    pub value: Vec<u8>,
}

impl TlvEntry {
    /// Creates a new TLV entry.
    pub fn new(ty: u8, value: impl Into<Vec<u8>>) -> Self {
        Self {
            ty,
            value: value.into(),
        }
    }

    /// Writes this TLV to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), TlvError> {
        encode_header(self.ty, self.value.len(), out)?;
        out.extend_from_slice(&self.value);
        Ok(())
    }
}

/// Ordered TLV collection that preserves unknown TLVs and duplicate order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Zeroize)]
pub struct TlvSet {
    entries: Vec<TlvEntry>,
}

impl TlvSet {
    /// Parses all TLVs in `bytes`.
    pub fn parse(bytes: &[u8]) -> Result<Self, TlvError> {
        let mut entries = Zeroizing::new(Vec::new());
        let mut remaining = bytes;

        while !remaining.is_empty() {
            let (entry, rest) = parse_one(remaining)?;
            entries.push(entry);
            remaining = rest;
        }

        Ok(Self {
            entries: core::mem::take(&mut *entries),
        })
    }

    /// Encodes all entries in their current order.
    pub fn encode(&self) -> Result<Vec<u8>, TlvError> {
        let mut out = Zeroizing::new(Vec::new());
        for entry in &self.entries {
            entry.encode(&mut out)?;
        }
        Ok(core::mem::take(&mut *out))
    }

    /// Returns all TLV entries in order.
    pub fn entries(&self) -> &[TlvEntry] {
        &self.entries
    }

    /// Returns mutable TLV entries in order.
    pub fn entries_mut(&mut self) -> &mut Vec<TlvEntry> {
        &mut self.entries
    }

    /// Pushes an entry without removing existing entries of the same type.
    pub fn push(&mut self, entry: TlvEntry) {
        self.entries.push(entry);
    }

    /// Returns the last value for a TLV type, matching Thread dataset override behavior.
    pub fn last_value(&self, ty: u8) -> Option<&[u8]> {
        self.entries
            .iter()
            .rev()
            .find(|entry| entry.ty == ty)
            .map(|entry| entry.value.as_slice())
    }

    /// Replaces all existing TLVs of `ty` with one new value at the end.
    pub fn set_last(&mut self, ty: u8, value: impl Into<Vec<u8>>) {
        self.entries.retain(|entry| entry.ty != ty);
        self.entries.push(TlvEntry::new(ty, value));
    }
}

/// Parses a single TLV entry and returns the remaining bytes.
pub fn parse_one(bytes: &[u8]) -> Result<(TlvEntry, &[u8]), TlvError> {
    if bytes.len() < 2 {
        return Err(TlvError::BufferTooSmall);
    }

    let ty = bytes[0];
    let length_byte = bytes[1];
    let (length, header_len) = if length_byte == EXTENDED_TLV_MARKER {
        if bytes.len() < 4 {
            return Err(TlvError::BufferTooSmall);
        }
        (u16::from_be_bytes([bytes[2], bytes[3]]) as usize, 4usize)
    } else {
        (length_byte as usize, 2usize)
    };

    let end = header_len
        .checked_add(length)
        .ok_or(TlvError::InvalidLength)?;
    if bytes.len() < end {
        return Err(TlvError::BufferTooSmall);
    }

    Ok((
        TlvEntry::new(ty, bytes[header_len..end].to_vec()),
        &bytes[end..],
    ))
}

/// Writes a TLV header for `ty` and `length`.
pub fn encode_header(ty: u8, length: usize, out: &mut Vec<u8>) -> Result<(), TlvError> {
    out.push(ty);
    if length <= MAX_STANDARD_TLV_LENGTH {
        out.push(length as u8);
    } else if length <= MAX_EXTENDED_TLV_LENGTH {
        out.push(EXTENDED_TLV_MARKER);
        out.extend_from_slice(&(length as u16).to_be_bytes());
    } else {
        return Err(TlvError::ValueTooLarge(length));
    }
    Ok(())
}

pub(crate) fn read_u16(value: &[u8]) -> Result<u16, TlvError> {
    crate::wire::read_u16(value).ok_or(TlvError::InvalidLength)
}

pub(crate) fn read_u32(value: &[u8]) -> Result<u32, TlvError> {
    crate::wire::read_u32(value).ok_or(TlvError::InvalidLength)
}

pub(crate) fn read_u64(value: &[u8]) -> Result<u64, TlvError> {
    crate::wire::read_u64(value).ok_or(TlvError::InvalidLength)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_standard_and_extended_tlvs() {
        let mut set = TlvSet::default();
        set.push(TlvEntry::new(1, vec![0xaa, 0xbb]));
        set.push(TlvEntry::new(2, vec![0x11; 255]));

        let encoded = set.encode().unwrap();
        assert_eq!(&encoded[..4], &[1, 2, 0xaa, 0xbb]);
        assert_eq!(&encoded[4..8], &[2, 0xff, 0x00, 0xff]);

        let decoded = TlvSet::parse(&encoded).unwrap();
        assert_eq!(decoded, set);
    }

    #[test]
    fn preserves_duplicate_order_and_returns_last_value() {
        let decoded = TlvSet::parse(&[1, 1, 0xaa, 2, 1, 0xbb, 1, 1, 0xcc]).unwrap();
        assert_eq!(decoded.entries()[0].ty, 1);
        assert_eq!(decoded.entries()[1].ty, 2);
        assert_eq!(decoded.entries()[2].ty, 1);
        assert_eq!(decoded.last_value(1), Some(&[0xcc][..]));
    }

    #[test]
    fn rejects_malformed_tlv_streams() {
        let cases = [
            ("empty standard header", vec![1], TlvError::BufferTooSmall),
            (
                "standard value truncated",
                vec![1, 2, 0xaa],
                TlvError::BufferTooSmall,
            ),
            (
                "extended header truncated",
                vec![1, EXTENDED_TLV_MARKER, 0],
                TlvError::BufferTooSmall,
            ),
            (
                "extended value truncated",
                vec![1, EXTENDED_TLV_MARKER, 0, 2, 0xaa],
                TlvError::BufferTooSmall,
            ),
        ];

        for (name, bytes, expected) in cases {
            assert_eq!(TlvSet::parse(&bytes).unwrap_err(), expected, "{name}");
        }
    }

    #[test]
    fn rejects_values_too_large_to_encode() {
        let mut out = Vec::new();
        assert_eq!(
            encode_header(1, MAX_EXTENDED_TLV_LENGTH + 1, &mut out).unwrap_err(),
            TlvError::ValueTooLarge(MAX_EXTENDED_TLV_LENGTH + 1)
        );
    }
}
