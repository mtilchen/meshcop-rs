//! TLS AES-128-CCM-8 record protection for DTLS records.

use alloc::{string::ToString, vec::Vec};

use crate::{
    Result,
    ccm::{
        AesCcm8, RecordProtectionKey, TLS_CCM_8_TAG_LEN, TLS_CCM_EXPLICIT_NONCE_LEN,
        TLS_CCM_FIXED_IV_LEN, dtls_ccm_nonce,
    },
    error::Error,
};

use super::{
    constants::DTLS_1_2_VERSION,
    record::{ContentType, DtlsRecord, RecordHeader},
    util::dtls_trace_secret,
};

/// Encrypts and authenticates a DTLS record payload with AES-128-CCM-8,
/// returning the explicit-nonce-prefixed ciphertext (RFC 6655).
pub fn protect_aes_128_ccm_8_record(
    content_type: ContentType,
    epoch: u16,
    sequence_number: u64,
    key: RecordProtectionKey,
    fixed_iv: &[u8; TLS_CCM_FIXED_IV_LEN],
    plaintext: &[u8],
) -> Result<DtlsRecord> {
    let plaintext_len = u16::try_from(plaintext.len())
        .map_err(|_| Error::Crypto("DTLS plaintext is too long".to_string()))?;
    let nonce = dtls_ccm_nonce(fixed_iv, epoch, sequence_number)?;
    let header = RecordHeader {
        content_type,
        version: DTLS_1_2_VERSION,
        epoch,
        sequence_number,
        length: 0,
    };
    let aad = header.aead_additional_data(plaintext_len);
    if content_type == ContentType::Handshake && epoch == 1 {
        dtls_trace_secret("protect_handshake_nonce", &nonce);
        dtls_trace_secret("protect_handshake_aad", &aad);
        dtls_trace_secret("protect_handshake_plaintext", plaintext);
    }
    let ciphertext = AesCcm8::new(key).encrypt(&nonce, &aad, plaintext)?;
    if content_type == ContentType::Handshake && epoch == 1 {
        dtls_trace_secret("protect_handshake_ciphertext", &ciphertext);
    }
    let mut payload = Vec::with_capacity(TLS_CCM_EXPLICIT_NONCE_LEN + ciphertext.len());
    payload.extend_from_slice(&nonce[TLS_CCM_FIXED_IV_LEN..]);
    payload.extend_from_slice(&ciphertext);
    DtlsRecord::new(content_type, epoch, sequence_number, payload)
}

/// Opens a DTLS record protected with TLS AES-128-CCM-8.
pub fn open_aes_128_ccm_8_record(
    record: &DtlsRecord,
    key: RecordProtectionKey,
    fixed_iv: &[u8; TLS_CCM_FIXED_IV_LEN],
) -> Result<Vec<u8>> {
    if record.payload.len() < TLS_CCM_EXPLICIT_NONCE_LEN + TLS_CCM_8_TAG_LEN {
        return Err(Error::Crypto(
            "DTLS AES-CCM record payload is too short".to_string(),
        ));
    }
    let encrypted = &record.payload[TLS_CCM_EXPLICIT_NONCE_LEN..];
    let plaintext_len = encrypted
        .len()
        .checked_sub(TLS_CCM_8_TAG_LEN)
        .ok_or_else(|| Error::Crypto("DTLS AES-CCM tag is missing".to_string()))?;
    let plaintext_len = u16::try_from(plaintext_len)
        .map_err(|_| Error::Crypto("DTLS plaintext length exceeds 16 bits".to_string()))?;

    let mut nonce = [0u8; TLS_CCM_FIXED_IV_LEN + TLS_CCM_EXPLICIT_NONCE_LEN];
    nonce[..TLS_CCM_FIXED_IV_LEN].copy_from_slice(fixed_iv);
    nonce[TLS_CCM_FIXED_IV_LEN..].copy_from_slice(&record.payload[..TLS_CCM_EXPLICIT_NONCE_LEN]);
    let aad = record.header.aead_additional_data(plaintext_len);
    AesCcm8::new(key).decrypt(&nonce, &aad, encrypted)
}
