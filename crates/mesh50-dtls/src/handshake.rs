//! DTLS handshake message framing and transcript helpers.

use alloc::{format, string::ToString, vec, vec::Vec};

use sha2::Digest;

use crate::{Result, error::Error};

use super::{
    key_schedule::finished_verify_data,
    record::{ContentType, DtlsRecord},
    util::{MAX_U24, read_u24, write_u24},
};

/// DTLS handshake message type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HandshakeType {
    /// hello_request.
    HelloRequest = 0,
    /// client_hello.
    ClientHello = 1,
    /// server_hello.
    ServerHello = 2,
    /// hello_verify_request.
    HelloVerifyRequest = 3,
    /// certificate.
    Certificate = 11,
    /// server_key_exchange.
    ServerKeyExchange = 12,
    /// certificate_request.
    CertificateRequest = 13,
    /// server_hello_done.
    ServerHelloDone = 14,
    /// certificate_verify.
    CertificateVerify = 15,
    /// client_key_exchange.
    ClientKeyExchange = 16,
    /// finished.
    Finished = 20,
}

impl TryFrom<u8> for HandshakeType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::HelloRequest),
            1 => Ok(Self::ClientHello),
            2 => Ok(Self::ServerHello),
            3 => Ok(Self::HelloVerifyRequest),
            11 => Ok(Self::Certificate),
            12 => Ok(Self::ServerKeyExchange),
            13 => Ok(Self::CertificateRequest),
            14 => Ok(Self::ServerHelloDone),
            15 => Ok(Self::CertificateVerify),
            16 => Ok(Self::ClientKeyExchange),
            20 => Ok(Self::Finished),
            _ => Err(Error::Crypto("unknown DTLS handshake type".to_string())),
        }
    }
}
/// DTLS handshake fragment header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeHeader {
    /// Handshake message type.
    pub message_type: HandshakeType,
    /// Complete message length.
    pub length: u32,
    /// DTLS handshake sequence number.
    pub message_seq: u16,
    /// Fragment offset.
    pub fragment_offset: u32,
    /// Fragment length.
    pub fragment_length: u32,
}

impl HandshakeHeader {
    /// DTLS handshake header length.
    pub const LEN: usize = 12;

    /// Parses a DTLS handshake fragment header.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < Self::LEN {
            return Err(Error::Crypto(
                "DTLS handshake header is truncated".to_string(),
            ));
        }
        let header = Self {
            message_type: HandshakeType::try_from(bytes[0])?,
            length: read_u24(&bytes[1..4]),
            message_seq: u16::from_be_bytes([bytes[4], bytes[5]]),
            fragment_offset: read_u24(&bytes[6..9]),
            fragment_length: read_u24(&bytes[9..12]),
        };
        header.validate()?;
        Ok(header)
    }

    /// Encodes this header.
    pub fn encode(self) -> Result<[u8; Self::LEN]> {
        self.validate()?;
        let mut out = [0u8; Self::LEN];
        out[0] = self.message_type as u8;
        write_u24(self.length, &mut out[1..4])?;
        out[4..6].copy_from_slice(&self.message_seq.to_be_bytes());
        write_u24(self.fragment_offset, &mut out[6..9])?;
        write_u24(self.fragment_length, &mut out[9..12])?;
        Ok(out)
    }

    pub(crate) fn validate(self) -> Result<()> {
        if self.length > MAX_U24 || self.fragment_offset > MAX_U24 || self.fragment_length > MAX_U24
        {
            return Err(Error::Crypto(
                "DTLS handshake length exceeds 24-bit field".to_string(),
            ));
        }
        if self.fragment_offset + self.fragment_length > self.length {
            return Err(Error::Crypto(
                "DTLS handshake fragment exceeds message length".to_string(),
            ));
        }
        Ok(())
    }
}

/// One DTLS handshake fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeFragment {
    /// Fragment header.
    pub header: HandshakeHeader,
    /// Fragment bytes.
    pub fragment: Vec<u8>,
}

impl HandshakeFragment {
    /// Parses one DTLS handshake fragment.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let header = HandshakeHeader::parse(bytes)?;
        let end = HandshakeHeader::LEN
            .checked_add(header.fragment_length as usize)
            .ok_or_else(|| Error::Crypto("DTLS handshake fragment length overflow".to_string()))?;
        if bytes.len() < end {
            return Err(Error::Crypto(
                "DTLS handshake fragment is truncated".to_string(),
            ));
        }
        Ok(Self {
            header,
            fragment: bytes[HandshakeHeader::LEN..end].to_vec(),
        })
    }

    /// Encodes this fragment.
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.fragment.len() != self.header.fragment_length as usize {
            return Err(Error::Crypto(
                "DTLS handshake fragment header length does not match payload".to_string(),
            ));
        }
        let mut out = Vec::with_capacity(HandshakeHeader::LEN + self.fragment.len());
        out.extend_from_slice(&self.header.encode()?);
        out.extend_from_slice(&self.fragment);
        Ok(out)
    }
}

/// One complete DTLS handshake message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeMessage {
    /// Handshake message type.
    pub message_type: HandshakeType,
    /// DTLS handshake sequence number.
    pub message_seq: u16,
    /// Complete handshake body.
    pub payload: Vec<u8>,
}

impl HandshakeMessage {
    /// Encodes this message as one unfragmented DTLS handshake message.
    pub fn encode(&self) -> Result<Vec<u8>> {
        // Empty-bodied messages such as ServerHelloDone still produce one
        // zero-length fragment.
        self.fragment(self.payload.len().max(1))?
            .into_iter()
            .next()
            .ok_or_else(|| Error::Crypto("missing handshake fragment".to_string()))?
            .encode()
    }

    /// Encodes this message in the canonical form used by DTLS Finished hashes.
    ///
    /// RFC 6347 requires the hash to include DTLS-specific handshake fields
    /// while treating every message as a single fragment. Callers decide which
    /// messages enter the transcript, including excluding the initial
    /// ClientHello/HelloVerifyRequest cookie exchange when present.
    pub fn transcript_bytes(&self) -> Result<Vec<u8>> {
        let header = HandshakeHeader {
            message_type: self.message_type,
            length: u32::try_from(self.payload.len()).map_err(|_| {
                Error::Crypto("DTLS handshake message exceeds 24-bit length".to_string())
            })?,
            message_seq: self.message_seq,
            fragment_offset: 0,
            fragment_length: u32::try_from(self.payload.len()).map_err(|_| {
                Error::Crypto("DTLS handshake message exceeds 24-bit length".to_string())
            })?,
        };
        let mut out = Vec::with_capacity(HandshakeHeader::LEN + self.payload.len());
        out.extend_from_slice(&header.encode()?);
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Splits this message into DTLS handshake fragments.
    pub fn fragment(&self, max_fragment_len: usize) -> Result<Vec<HandshakeFragment>> {
        if max_fragment_len == 0 {
            return Err(Error::Crypto(
                "maximum handshake fragment length must be nonzero".to_string(),
            ));
        }
        if self.payload.len() > MAX_U24 as usize {
            return Err(Error::Crypto(
                "DTLS handshake message exceeds 24-bit length".to_string(),
            ));
        }
        let total_len = self.payload.len() as u32;
        let mut fragments = Vec::new();
        for (idx, fragment) in self.payload.chunks(max_fragment_len).enumerate() {
            let offset = idx
                .checked_mul(max_fragment_len)
                .ok_or_else(|| Error::Crypto("fragment offset overflow".to_string()))?
                as u32;
            fragments.push(HandshakeFragment {
                header: HandshakeHeader {
                    message_type: self.message_type,
                    length: total_len,
                    message_seq: self.message_seq,
                    fragment_offset: offset,
                    fragment_length: fragment.len() as u32,
                },
                fragment: fragment.to_vec(),
            });
        }
        if fragments.is_empty() {
            fragments.push(HandshakeFragment {
                header: HandshakeHeader {
                    message_type: self.message_type,
                    length: 0,
                    message_seq: self.message_seq,
                    fragment_offset: 0,
                    fragment_length: 0,
                },
                fragment: Vec::new(),
            });
        }
        Ok(fragments)
    }
}

/// DTLS/TLS Finished message sender role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinishedRole {
    /// Client Finished.
    Client,
    /// Server Finished.
    Server,
}

/// DTLS handshake transcript for Finished verification.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HandshakeTranscript {
    bytes: Vec<u8>,
}

impl HandshakeTranscript {
    /// Creates an empty transcript.
    pub const fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Appends one complete handshake message in canonical transcript form.
    pub fn push(&mut self, message: &HandshakeMessage) -> Result<()> {
        self.bytes.extend_from_slice(&message.transcript_bytes()?);
        Ok(())
    }

    /// Returns the raw transcript bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Computes SHA-256 over the transcript bytes.
    pub fn sha256(&self) -> [u8; 32] {
        let digest = sha2::Sha256::digest(&self.bytes);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    /// Computes the TLS 1.2 Finished verify_data for this transcript.
    pub fn finished_verify_data(
        &self,
        master_secret: &[u8; 48],
        role: FinishedRole,
    ) -> Result<[u8; 12]> {
        finished_verify_data(master_secret, role, &self.sha256())
    }
}

/// Parses one unfragmented handshake message from a DTLS handshake record.
pub fn parse_unfragmented_handshake_record(
    record: &DtlsRecord,
    expected_type: HandshakeType,
) -> Result<HandshakeMessage> {
    if record.header.content_type != ContentType::Handshake {
        return Err(Error::Crypto(
            "DTLS record is not a handshake record".to_string(),
        ));
    }
    let fragment = HandshakeFragment::parse(&record.payload)?;
    let consumed = HandshakeHeader::LEN + fragment.fragment.len();
    if consumed != record.payload.len() {
        return Err(Error::Crypto(
            "DTLS record contains trailing handshake bytes".to_string(),
        ));
    }
    if fragment.header.message_type != expected_type {
        return Err(Error::Crypto("unexpected DTLS handshake type".to_string()));
    }
    if fragment.header.fragment_offset != 0
        || fragment.header.fragment_length != fragment.header.length
    {
        return Err(Error::Crypto(
            "DTLS handshake message is fragmented".to_string(),
        ));
    }
    Ok(HandshakeMessage {
        message_type: fragment.header.message_type,
        message_seq: fragment.header.message_seq,
        payload: fragment.fragment,
    })
}

/// Parses all unfragmented handshake messages packed into a DTLS handshake record.
pub fn parse_unfragmented_handshake_messages(record: &DtlsRecord) -> Result<Vec<HandshakeMessage>> {
    if record.header.content_type != ContentType::Handshake {
        return Err(Error::Crypto(
            "DTLS record is not a handshake record".to_string(),
        ));
    }

    let mut bytes = record.payload.as_slice();
    let mut messages = Vec::new();
    while !bytes.is_empty() {
        let fragment = HandshakeFragment::parse(bytes)?;
        if fragment.header.fragment_offset != 0
            || fragment.header.fragment_length != fragment.header.length
        {
            return Err(Error::Crypto(
                "DTLS handshake message is fragmented".to_string(),
            ));
        }
        let consumed = HandshakeHeader::LEN + fragment.fragment.len();
        messages.push(HandshakeMessage {
            message_type: fragment.header.message_type,
            message_seq: fragment.header.message_seq,
            payload: fragment.fragment,
        });
        bytes = &bytes[consumed..];
    }
    Ok(messages)
}

/// Upper bound on a reassembled DTLS handshake message.
///
/// The 24-bit length field admits up to ~16 MiB; the Thread (non-CCM) profile's
/// handshake messages are at most a few hundred bytes, so this generous 64 KiB
/// cap bounds the buffer a peer can make the reassembler allocate from a single
/// fragment header.
pub(super) const MAX_HANDSHAKE_MESSAGE_LEN: u32 = 64 * 1024;

/// Reassembles DTLS handshake fragments for one message.
#[derive(Debug, Default, Clone)]
pub struct HandshakeReassembler {
    message_type: Option<HandshakeType>,
    message_seq: Option<u16>,
    bytes: Vec<u8>,
    filled: Vec<bool>,
}

impl HandshakeReassembler {
    /// Adds a fragment and returns the complete message once all bytes arrive.
    pub fn push(&mut self, fragment: HandshakeFragment) -> Result<Option<HandshakeMessage>> {
        self.initialize_or_validate(&fragment.header)?;
        let start = fragment.header.fragment_offset as usize;
        let end = start + fragment.fragment.len();
        if end > self.bytes.len() {
            return Err(Error::Crypto(
                "DTLS handshake fragment exceeds message length".to_string(),
            ));
        }

        for (idx, byte) in fragment.fragment.iter().enumerate() {
            let position = start + idx;
            if self.filled[position] && self.bytes[position] != *byte {
                return Err(Error::Crypto(
                    "DTLS handshake fragment overlaps with different data".to_string(),
                ));
            }
            self.bytes[position] = *byte;
            self.filled[position] = true;
        }

        if self.filled.iter().all(|filled| *filled) {
            Ok(Some(HandshakeMessage {
                message_type: self
                    .message_type
                    .ok_or_else(|| Error::Crypto("missing handshake type".to_string()))?,
                message_seq: self
                    .message_seq
                    .ok_or_else(|| Error::Crypto("missing handshake sequence".to_string()))?,
                payload: self.bytes.clone(),
            }))
        } else {
            Ok(None)
        }
    }

    fn initialize_or_validate(&mut self, header: &HandshakeHeader) -> Result<()> {
        match (self.message_type, self.message_seq) {
            (None, None) => {
                if header.length > MAX_HANDSHAKE_MESSAGE_LEN {
                    return Err(Error::Crypto(format!(
                        "DTLS handshake message length {} exceeds the {MAX_HANDSHAKE_MESSAGE_LEN}-byte limit",
                        header.length
                    )));
                }
                self.message_type = Some(header.message_type);
                self.message_seq = Some(header.message_seq);
                self.bytes = vec![0; header.length as usize];
                self.filled = vec![false; header.length as usize];
                Ok(())
            }
            (Some(message_type), Some(message_seq))
                if message_type == header.message_type
                    && message_seq == header.message_seq
                    && self.bytes.len() == header.length as usize =>
            {
                Ok(())
            }
            _ => Err(Error::Crypto(
                "DTLS handshake fragment metadata mismatch".to_string(),
            )),
        }
    }
}
