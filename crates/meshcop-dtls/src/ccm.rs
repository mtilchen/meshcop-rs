//! AES-CCM-8 record protection helpers.

use alloc::{string::ToString, vec::Vec};

use aes::Aes128;
use ccm::{
    Ccm, Nonce,
    aead::{Aead, KeyInit, Payload},
    consts::{U8, U12},
};
use zeroize::Zeroize;

use crate::{Result, error::Error};

type Aes128Ccm8 = Ccm<Aes128, U8, U12>;

/// TLS AES-CCM fixed IV length.
pub const TLS_CCM_FIXED_IV_LEN: usize = 4;

/// TLS AES-CCM explicit nonce length.
pub const TLS_CCM_EXPLICIT_NONCE_LEN: usize = 8;

/// TLS AES-CCM AEAD nonce length.
pub const TLS_CCM_NONCE_LEN: usize = TLS_CCM_FIXED_IV_LEN + TLS_CCM_EXPLICIT_NONCE_LEN;

/// TLS AES-CCM-8 authentication tag length.
pub const TLS_CCM_8_TAG_LEN: usize = 8;

/// AES-128-CCM-8 record-protection key.
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct RecordProtectionKey([u8; 16]);

impl core::fmt::Debug for RecordProtectionKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("RecordProtectionKey")
            .field(&"<redacted>")
            .finish()
    }
}

impl RecordProtectionKey {
    /// Creates a record-protection key.
    pub const fn new(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Returns the raw key bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// AES-CCM-8 helper with the 12-byte nonce used by TLS/DTLS AES-CCM.
#[derive(Debug, Clone)]
pub struct AesCcm8 {
    key: RecordProtectionKey,
}

impl AesCcm8 {
    /// Creates a new AES-CCM-8 helper.
    pub const fn new(key: RecordProtectionKey) -> Self {
        Self { key }
    }

    /// Encrypts `plaintext` with associated data `aad` and a 12-byte nonce.
    pub fn encrypt(
        &self,
        nonce: &[u8; TLS_CCM_NONCE_LEN],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let cipher = Aes128Ccm8::new_from_slice(&self.key.0)
            .map_err(|_| Error::Crypto("invalid AES-CCM key".to_string()))?;
        cipher
            .encrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| Error::Crypto("AES-CCM encryption failed".to_string()))
    }

    /// Decrypts `ciphertext` with associated data `aad` and a 12-byte nonce.
    pub fn decrypt(
        &self,
        nonce: &[u8; TLS_CCM_NONCE_LEN],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        let cipher = Aes128Ccm8::new_from_slice(&self.key.0)
            .map_err(|_| Error::Crypto("invalid AES-CCM key".to_string()))?;
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| Error::Crypto("AES-CCM authentication failed".to_string()))
    }
}

/// Builds the TLS/DTLS AES-CCM nonce from the fixed IV and 64-bit record sequence.
pub fn dtls_ccm_nonce(
    fixed_iv: &[u8; TLS_CCM_FIXED_IV_LEN],
    epoch: u16,
    sequence_number: u64,
) -> Result<[u8; TLS_CCM_NONCE_LEN]> {
    if sequence_number > 0x0000_ffff_ffff_ffff {
        return Err(Error::Crypto(
            "DTLS record sequence number exceeds 48 bits".to_string(),
        ));
    }

    let mut nonce = [0u8; TLS_CCM_NONCE_LEN];
    nonce[..TLS_CCM_FIXED_IV_LEN].copy_from_slice(fixed_iv);
    nonce[4..6].copy_from_slice(&epoch.to_be_bytes());
    nonce[6] = (sequence_number >> 40) as u8;
    nonce[7] = (sequence_number >> 32) as u8;
    nonce[8] = (sequence_number >> 24) as u8;
    nonce[9] = (sequence_number >> 16) as u8;
    nonce[10] = (sequence_number >> 8) as u8;
    nonce[11] = sequence_number as u8;
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ccm8_round_trip_and_auth_failure() {
        let key = RecordProtectionKey::new([0x11; 16]);
        let ccm = AesCcm8::new(key);
        let nonce = [0x22; TLS_CCM_NONCE_LEN];
        let aad = b"record header";
        let plaintext = b"meshcop payload";

        let mut ciphertext = ccm.encrypt(&nonce, aad, plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);
        assert_eq!(ccm.decrypt(&nonce, aad, &ciphertext).unwrap(), plaintext);

        ciphertext[0] ^= 0x01;
        assert!(ccm.decrypt(&nonce, aad, &ciphertext).is_err());
    }

    #[test]
    fn builds_dtls_ccm_nonce_from_fixed_iv_epoch_and_sequence() {
        assert_eq!(
            dtls_ccm_nonce(&[0xaa, 0xbb, 0xcc, 0xdd], 0x0102, 0x0304_0506_0708).unwrap(),
            [
                0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            ]
        );
        // The largest 48-bit sequence number is accepted; one more is rejected.
        assert!(dtls_ccm_nonce(&[0; 4], 0, 0x0000_ffff_ffff_ffff).is_ok());
        assert!(dtls_ccm_nonce(&[0; 4], 0, 0x0001_0000_0000_0000).is_err());
    }

    #[test]
    fn record_protection_key_debug_is_redacted() {
        let rendered = format!("{:?}", RecordProtectionKey::new([0xab; 16]));
        assert!(rendered.contains("RecordProtectionKey"));
        assert!(rendered.contains("<redacted>"));
        assert!(!rendered.contains("ab"));
    }
}
