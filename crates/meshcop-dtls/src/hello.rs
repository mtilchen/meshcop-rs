//! DTLS hello-message codecs and cookie-retry state.

use alloc::{format, string::ToString, vec, vec::Vec};

use crate::{Result, error::Error};

use super::{
    constants::*,
    handshake::{HandshakeMessage, HandshakeType, parse_unfragmented_handshake_record},
    record::{ContentType, DtlsRecord},
};

/// Small client-side DTLS hello flight state.
#[derive(Debug, Clone)]
pub struct DtlsClientHelloState {
    random: [u8; 32],
    cookie: Vec<u8>,
    ecjpake_kkpp: Option<Vec<u8>>,
    next_record_sequence: u64,
    next_message_sequence: u16,
    last_client_hello_sequence: Option<u16>,
}

impl DtlsClientHelloState {
    /// Creates a client hello state with the supplied ClientHello random.
    pub const fn new(random: [u8; 32]) -> Self {
        Self {
            random,
            cookie: Vec::new(),
            ecjpake_kkpp: None,
            next_record_sequence: 0,
            next_message_sequence: 0,
            last_client_hello_sequence: None,
        }
    }

    /// Creates a client hello state with cached ECJPAKE round-one parameters.
    pub fn with_ecjpake_kkpp(random: [u8; 32], ecjpake_kkpp: Vec<u8>) -> Self {
        let mut out = Self::new(random);
        out.ecjpake_kkpp = Some(ecjpake_kkpp);
        out
    }

    /// Returns the cookie to be included in the next ClientHello.
    pub fn cookie(&self) -> &[u8] {
        &self.cookie
    }

    /// Returns the cached ECJPAKE KKPP extension body.
    pub fn ecjpake_kkpp(&self) -> Option<&[u8]> {
        self.ecjpake_kkpp.as_deref()
    }

    /// Returns the next epoch-0 record sequence number.
    pub const fn next_record_sequence(&self) -> u64 {
        self.next_record_sequence
    }

    /// Returns the next handshake message sequence number for this client.
    pub const fn next_message_sequence(&self) -> u16 {
        self.next_message_sequence
    }

    /// Replaces the cached ECJPAKE KKPP extension body.
    pub fn set_ecjpake_kkpp(&mut self, ecjpake_kkpp: Vec<u8>) {
        self.ecjpake_kkpp = Some(ecjpake_kkpp);
    }

    /// Builds the next ClientHello handshake record.
    pub fn next_client_hello_record(&mut self) -> Result<DtlsRecord> {
        let client_hello = match &self.ecjpake_kkpp {
            Some(kkpp) => ClientHello::thread_profile_with_ecjpake(
                self.random,
                self.cookie.clone(),
                kkpp.clone(),
            ),
            None => ClientHello::thread_profile(self.random, self.cookie.clone()),
        };
        let message_seq = self.next_message_sequence;
        self.next_message_sequence = self.next_message_sequence.wrapping_add(1);
        self.last_client_hello_sequence = Some(message_seq);

        let handshake = HandshakeMessage {
            message_type: HandshakeType::ClientHello,
            message_seq,
            payload: client_hello.encode()?,
        };
        let record = DtlsRecord::new(
            ContentType::Handshake,
            0,
            self.next_record_sequence,
            handshake.encode()?,
        )?;
        self.next_record_sequence = self.next_record_sequence.wrapping_add(1);
        Ok(record)
    }

    /// Consumes a HelloVerifyRequest and stores its cookie for the next ClientHello.
    pub fn handle_hello_verify_request(
        &mut self,
        record: &DtlsRecord,
    ) -> Result<HelloVerifyRequest> {
        let handshake =
            parse_unfragmented_handshake_record(record, HandshakeType::HelloVerifyRequest)?;
        if Some(handshake.message_seq) != self.last_client_hello_sequence {
            return Err(Error::Crypto(
                "HelloVerifyRequest sequence does not match ClientHello".to_string(),
            ));
        }
        let hello_verify = HelloVerifyRequest::decode(&handshake.payload)?;
        if hello_verify.server_version != DTLS_1_2_VERSION {
            return Err(Error::Crypto(
                "HelloVerifyRequest version is not DTLS 1.2".to_string(),
            ));
        }
        self.cookie = hello_verify.cookie.clone();
        Ok(hello_verify)
    }
}

/// TLS extension carried by hello messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsExtension {
    /// Extension type code.
    pub extension_type: u16,
    /// Raw extension data.
    pub data: Vec<u8>,
}

/// DTLS ClientHello body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// Client random.
    pub random: [u8; 32],
    /// Session ID.
    pub session_id: Vec<u8>,
    /// DTLS cookie.
    pub cookie: Vec<u8>,
    /// Offered cipher suites.
    pub cipher_suites: Vec<u16>,
    /// Offered compression methods.
    pub compression_methods: Vec<u8>,
    /// TLS extensions.
    pub extensions: Vec<TlsExtension>,
}

impl ClientHello {
    /// Builds a Thread commissioner ClientHello body.
    pub fn thread_profile(random: [u8; 32], cookie: Vec<u8>) -> Self {
        Self {
            random,
            session_id: Vec::new(),
            cookie,
            cipher_suites: vec![
                TLS_ECJPAKE_WITH_AES_128_CCM_8,
                TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
            ],
            compression_methods: vec![TLS_COMPRESSION_NULL],
            extensions: vec![
                supported_groups_extension(),
                signature_algorithms_extension(),
                ec_point_formats_extension(),
            ],
        }
    }

    /// Builds a Thread commissioner ClientHello with the ECJPAKE KKPP extension.
    pub fn thread_profile_with_ecjpake(random: [u8; 32], cookie: Vec<u8>, kkpp: Vec<u8>) -> Self {
        let mut hello = Self::thread_profile(random, cookie);
        hello.set_ecjpake_kkpp(kkpp);
        hello
    }

    /// Replaces or appends the ECJPAKE KKPP extension.
    pub fn set_ecjpake_kkpp(&mut self, kkpp: Vec<u8>) {
        self.extensions.retain(|extension| {
            !matches!(
                extension.extension_type,
                EXTENSION_ECJPAKE_KKPP | EXTENSION_MAX_FRAGMENT_LENGTH
            )
        });
        self.extensions.push(TlsExtension {
            extension_type: EXTENSION_ECJPAKE_KKPP,
            data: kkpp,
        });
        self.extensions.push(max_fragment_length_extension());
    }

    /// Returns the ECJPAKE KKPP extension body if present.
    pub fn ecjpake_kkpp(&self) -> Option<&[u8]> {
        find_extension(&self.extensions, EXTENSION_ECJPAKE_KKPP)
    }

    /// Encodes this ClientHello body.
    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_u8_len(self.session_id.len(), "ClientHello session_id")?;
        validate_u8_len(self.cookie.len(), "ClientHello cookie")?;
        validate_u8_len(
            self.compression_methods.len(),
            "ClientHello compression methods",
        )?;
        let cipher_len =
            self.cipher_suites.len().checked_mul(2).ok_or_else(|| {
                Error::Crypto("ClientHello cipher-suite length overflow".to_string())
            })?;
        validate_u16_len(cipher_len, "ClientHello cipher suites")?;

        let mut out = Vec::new();
        out.extend_from_slice(&DTLS_1_2_VERSION.to_be_bytes());
        out.extend_from_slice(&self.random);
        out.push(self.session_id.len() as u8);
        out.extend_from_slice(&self.session_id);
        out.push(self.cookie.len() as u8);
        out.extend_from_slice(&self.cookie);
        out.extend_from_slice(&(cipher_len as u16).to_be_bytes());
        for suite in &self.cipher_suites {
            out.extend_from_slice(&suite.to_be_bytes());
        }
        out.push(self.compression_methods.len() as u8);
        out.extend_from_slice(&self.compression_methods);
        append_extensions(&mut out, &self.extensions)?;
        Ok(out)
    }

    /// Decodes a ClientHello body.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let version = cursor.read_u16()?;
        if version != DTLS_1_2_VERSION {
            return Err(Error::Crypto(
                "ClientHello version is not DTLS 1.2".to_string(),
            ));
        }
        let random = cursor.read_array_32()?;
        let session_id = cursor.read_vec_u8()?;
        let cookie = cursor.read_vec_u8()?;
        let cipher_bytes = cursor.read_vec_u16()?;
        if cipher_bytes.len() % 2 != 0 {
            return Err(Error::Crypto(
                "ClientHello cipher-suite vector has odd length".to_string(),
            ));
        }
        let cipher_suites = cipher_bytes
            .chunks_exact(2)
            .map(|suite| u16::from_be_bytes([suite[0], suite[1]]))
            .collect();
        let compression_methods = cursor.read_vec_u8()?;
        let extensions = cursor.read_extensions()?;
        cursor.finish()?;
        Ok(Self {
            random,
            session_id,
            cookie,
            cipher_suites,
            compression_methods,
            extensions,
        })
    }
}

/// DTLS HelloVerifyRequest body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloVerifyRequest {
    /// DTLS server version.
    pub server_version: u16,
    /// Stateless verification cookie.
    pub cookie: Vec<u8>,
}

impl HelloVerifyRequest {
    /// Encodes this HelloVerifyRequest body.
    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_u8_len(self.cookie.len(), "HelloVerifyRequest cookie")?;
        let mut out = Vec::with_capacity(3 + self.cookie.len());
        out.extend_from_slice(&self.server_version.to_be_bytes());
        out.push(self.cookie.len() as u8);
        out.extend_from_slice(&self.cookie);
        Ok(out)
    }

    /// Decodes a HelloVerifyRequest body.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let server_version = cursor.read_u16()?;
        let cookie = cursor.read_vec_u8()?;
        cursor.finish()?;
        Ok(Self {
            server_version,
            cookie,
        })
    }
}

/// DTLS ServerHello body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    /// Server random.
    pub random: [u8; 32],
    /// Session ID.
    pub session_id: Vec<u8>,
    /// Selected cipher suite.
    pub cipher_suite: u16,
    /// Selected compression method.
    pub compression_method: u8,
    /// TLS extensions.
    pub extensions: Vec<TlsExtension>,
}

impl ServerHello {
    /// Validates that this ServerHello selected the Thread commissioner profile.
    pub fn validate_thread_profile(&self) -> Result<()> {
        if self.cipher_suite != TLS_ECJPAKE_WITH_AES_128_CCM_8 {
            return Err(Error::Crypto(
                "ServerHello selected an unsupported cipher suite".to_string(),
            ));
        }
        if self.compression_method != TLS_COMPRESSION_NULL {
            return Err(Error::Crypto(
                "ServerHello selected an unsupported compression method".to_string(),
            ));
        }
        Ok(())
    }

    /// Returns the ECJPAKE KKPP extension body if present.
    pub fn ecjpake_kkpp(&self) -> Option<&[u8]> {
        find_extension(&self.extensions, EXTENSION_ECJPAKE_KKPP)
    }

    /// Encodes this ServerHello body.
    pub fn encode(&self) -> Result<Vec<u8>> {
        validate_u8_len(self.session_id.len(), "ServerHello session_id")?;
        let mut out = Vec::new();
        out.extend_from_slice(&DTLS_1_2_VERSION.to_be_bytes());
        out.extend_from_slice(&self.random);
        out.push(self.session_id.len() as u8);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.cipher_suite.to_be_bytes());
        out.push(self.compression_method);
        append_extensions(&mut out, &self.extensions)?;
        Ok(out)
    }

    /// Decodes a ServerHello body.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let version = cursor.read_u16()?;
        if version != DTLS_1_2_VERSION {
            return Err(Error::Crypto(
                "ServerHello version is not DTLS 1.2".to_string(),
            ));
        }
        let random = cursor.read_array_32()?;
        let session_id = cursor.read_vec_u8()?;
        let cipher_suite = cursor.read_u16()?;
        let compression_method = cursor.read_u8()?;
        let extensions = cursor.read_extensions()?;
        cursor.finish()?;
        Ok(Self {
            random,
            session_id,
            cipher_suite,
            compression_method,
            extensions,
        })
    }
}
fn supported_groups_extension() -> TlsExtension {
    TlsExtension {
        extension_type: EXTENSION_SUPPORTED_GROUPS,
        data: vec![
            0x00,
            0x02,
            (NAMED_GROUP_SECP256R1 >> 8) as u8,
            NAMED_GROUP_SECP256R1 as u8,
        ],
    }
}

fn signature_algorithms_extension() -> TlsExtension {
    TlsExtension {
        extension_type: EXTENSION_SIGNATURE_ALGORITHMS,
        data: vec![0x00, 0x02, 0x04, 0x03],
    }
}

pub(crate) fn ec_point_formats_extension() -> TlsExtension {
    TlsExtension {
        extension_type: EXTENSION_EC_POINT_FORMATS,
        data: vec![0x01, EC_POINT_FORMAT_UNCOMPRESSED],
    }
}

fn max_fragment_length_extension() -> TlsExtension {
    TlsExtension {
        extension_type: EXTENSION_MAX_FRAGMENT_LENGTH,
        data: vec![0x02],
    }
}

fn find_extension(extensions: &[TlsExtension], extension_type: u16) -> Option<&[u8]> {
    extensions
        .iter()
        .find(|extension| extension.extension_type == extension_type)
        .map(|extension| extension.data.as_slice())
}

fn append_extensions(out: &mut Vec<u8>, extensions: &[TlsExtension]) -> Result<()> {
    let mut encoded = Vec::new();
    for extension in extensions {
        validate_u16_len(extension.data.len(), "TLS extension")?;
        encoded.extend_from_slice(&extension.extension_type.to_be_bytes());
        encoded.extend_from_slice(&(extension.data.len() as u16).to_be_bytes());
        encoded.extend_from_slice(&extension.data);
    }
    validate_u16_len(encoded.len(), "TLS extensions")?;
    out.extend_from_slice(&(encoded.len() as u16).to_be_bytes());
    out.extend_from_slice(&encoded);
    Ok(())
}
fn validate_u8_len(len: usize, field: &str) -> Result<()> {
    if len > u8::MAX as usize {
        return Err(Error::Crypto(format!("{field} exceeds 255 bytes")));
    }
    Ok(())
}

fn validate_u16_len(len: usize, field: &str) -> Result<()> {
    if len > u16::MAX as usize {
        return Err(Error::Crypto(format!("{field} exceeds 65535 bytes")));
    }
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u8(&mut self) -> Result<u8> {
        let bytes = self.read_exact(1)?;
        Ok(bytes[0])
    }

    fn read_u16(&mut self) -> Result<u16> {
        let bytes = self.read_exact(2)?;
        Ok(crate::util::read_u16(bytes))
    }

    fn read_array_32(&mut self) -> Result<[u8; 32]> {
        let bytes = self.read_exact(32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    fn read_vec_u8(&mut self) -> Result<Vec<u8>> {
        let len = self.read_u8()? as usize;
        Ok(self.read_exact(len)?.to_vec())
    }

    fn read_vec_u16(&mut self) -> Result<Vec<u8>> {
        let len = self.read_u16()? as usize;
        Ok(self.read_exact(len)?.to_vec())
    }

    fn read_extensions(&mut self) -> Result<Vec<TlsExtension>> {
        if self.remaining() == 0 {
            return Ok(Vec::new());
        }
        let extension_bytes = self.read_vec_u16()?;
        let mut cursor = Cursor::new(&extension_bytes);
        let mut extensions = Vec::new();
        while cursor.remaining() > 0 {
            let extension_type = cursor.read_u16()?;
            let data = cursor.read_vec_u16()?;
            extensions.push(TlsExtension {
                extension_type,
                data,
            });
        }
        Ok(extensions)
    }

    fn finish(&self) -> Result<()> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(Error::Crypto(
                "trailing bytes after DTLS structure".to_string(),
            ))
        }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| Error::Crypto("DTLS cursor offset overflow".to_string()))?;
        if self.bytes.len() < end {
            return Err(Error::Crypto("DTLS structure is truncated".to_string()));
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }
}
