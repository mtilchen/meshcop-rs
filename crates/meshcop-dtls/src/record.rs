//! DTLS record framing.

use alloc::{string::ToString, vec::Vec};

use crate::{Result, error::Error};

use super::constants::DTLS_1_2_VERSION;

/// DTLS record content type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentType {
    /// ChangeCipherSpec.
    ChangeCipherSpec = 20,
    /// Alert.
    Alert = 21,
    /// Handshake.
    Handshake = 22,
    /// Application data.
    ApplicationData = 23,
}

impl TryFrom<u8> for ContentType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            20 => Ok(Self::ChangeCipherSpec),
            21 => Ok(Self::Alert),
            22 => Ok(Self::Handshake),
            23 => Ok(Self::ApplicationData),
            _ => Err(Error::Crypto("unknown DTLS content type".to_string())),
        }
    }
}
/// Parsed DTLS record header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    /// Record content type.
    pub content_type: ContentType,
    /// Wire DTLS version.
    pub version: u16,
    /// Record epoch.
    pub epoch: u16,
    /// 48-bit record sequence number.
    pub sequence_number: u64,
    /// Fragment length.
    pub length: u16,
}

impl RecordHeader {
    /// DTLS record header length.
    pub const LEN: usize = 13;

    /// Parses a DTLS record header.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::LEN {
            return Err(Error::Crypto("DTLS record header is truncated".to_string()));
        }
        let sequence_number = ((bytes[5] as u64) << 40)
            | ((bytes[6] as u64) << 32)
            | ((bytes[7] as u64) << 24)
            | ((bytes[8] as u64) << 16)
            | ((bytes[9] as u64) << 8)
            | bytes[10] as u64;
        Ok(Self {
            content_type: ContentType::try_from(bytes[0])?,
            version: u16::from_be_bytes([bytes[1], bytes[2]]),
            epoch: u16::from_be_bytes([bytes[3], bytes[4]]),
            sequence_number,
            length: u16::from_be_bytes([bytes[11], bytes[12]]),
        })
    }

    /// Encodes this header.
    pub fn encode(self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[0] = self.content_type as u8;
        out[1..3].copy_from_slice(&self.version.to_be_bytes());
        out[3..5].copy_from_slice(&self.epoch.to_be_bytes());
        out[5] = (self.sequence_number >> 40) as u8;
        out[6] = (self.sequence_number >> 32) as u8;
        out[7] = (self.sequence_number >> 24) as u8;
        out[8] = (self.sequence_number >> 16) as u8;
        out[9] = (self.sequence_number >> 8) as u8;
        out[10] = self.sequence_number as u8;
        out[11..13].copy_from_slice(&self.length.to_be_bytes());
        out
    }

    /// Builds the associated-data bytes used by TLS 1.2 AEAD record ciphers.
    pub fn aead_additional_data(self, plaintext_len: u16) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[0..2].copy_from_slice(&self.epoch.to_be_bytes());
        out[2] = (self.sequence_number >> 40) as u8;
        out[3] = (self.sequence_number >> 32) as u8;
        out[4] = (self.sequence_number >> 24) as u8;
        out[5] = (self.sequence_number >> 16) as u8;
        out[6] = (self.sequence_number >> 8) as u8;
        out[7] = self.sequence_number as u8;
        out[8] = self.content_type as u8;
        out[9..11].copy_from_slice(&self.version.to_be_bytes());
        out[11..13].copy_from_slice(&plaintext_len.to_be_bytes());
        out
    }
}

/// One complete DTLS record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DtlsRecord {
    /// Parsed record header.
    pub header: RecordHeader,
    /// Record payload bytes.
    pub payload: Vec<u8>,
}

impl DtlsRecord {
    /// Builds a DTLS record from header metadata and payload.
    pub fn new(
        content_type: ContentType,
        epoch: u16,
        sequence_number: u64,
        payload: Vec<u8>,
    ) -> Result<Self> {
        let length = u16::try_from(payload.len())
            .map_err(|_| Error::Crypto("DTLS record payload is too long".to_string()))?;
        Ok(Self {
            header: RecordHeader {
                content_type,
                version: DTLS_1_2_VERSION,
                epoch,
                sequence_number,
                length,
            },
            payload,
        })
    }

    /// Encodes this record.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.payload.len() != self.header.length as usize {
            return Err(Error::Crypto(
                "DTLS record header length does not match payload".to_string(),
            ));
        }
        let mut out = Vec::with_capacity(RecordHeader::LEN + self.payload.len());
        out.extend_from_slice(&self.header.encode());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Parses all DTLS records contained in one datagram.
    pub fn parse_datagram(mut bytes: &[u8]) -> Result<Vec<Self>> {
        let mut records = Vec::new();
        while !bytes.is_empty() {
            let header = RecordHeader::parse(bytes)?;
            let end = RecordHeader::LEN
                .checked_add(header.length as usize)
                .ok_or_else(|| Error::Crypto("DTLS record length overflow".to_string()))?;
            if bytes.len() < end {
                return Err(Error::Crypto(
                    "DTLS record payload is truncated".to_string(),
                ));
            }
            records.push(Self {
                header,
                payload: bytes[RecordHeader::LEN..end].to_vec(),
            });
            bytes = &bytes[end..];
        }
        Ok(records)
    }
}
