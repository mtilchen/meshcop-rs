//! TLS 1.2 key schedule helpers for the Thread DTLS profile.

use alloc::{string::ToString, vec::Vec};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

use crate::{Result, error::Error};

use super::handshake::FinishedRole;

/// TLS 1.2 AES-128-CCM-8 write keys and fixed IVs.
#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct Tls12Aes128Ccm8KeyBlock {
    /// Client write key.
    pub client_write_key: [u8; 16],
    /// Server write key.
    pub server_write_key: [u8; 16],
    /// Client fixed IV.
    pub client_write_iv: [u8; 4],
    /// Server fixed IV.
    pub server_write_iv: [u8; 4],
}

impl core::fmt::Debug for Tls12Aes128Ccm8KeyBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tls12Aes128Ccm8KeyBlock")
            .field("client_write_key", &"<redacted>")
            .field("server_write_key", &"<redacted>")
            .field("client_write_iv", &"<redacted>")
            .field("server_write_iv", &"<redacted>")
            .finish()
    }
}

/// Derived Thread DTLS key material after the ECJPAKE exchange.
#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct ThreadDtlsKeyMaterial {
    /// TLS 1.2 master secret.
    pub master_secret: [u8; 48],
    /// AES-128-CCM-8 traffic keys and fixed IVs.
    pub key_block: Tls12Aes128Ccm8KeyBlock,
}

impl core::fmt::Debug for ThreadDtlsKeyMaterial {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ThreadDtlsKeyMaterial")
            .field("master_secret", &"<redacted>")
            .field("key_block", &self.key_block)
            .finish()
    }
}

/// TLS 1.2 pseudo-random function (P_SHA-256), producing `out_len` bytes from
/// `secret`, an ASCII `label`, and a `seed` (RFC 5246 §5).
pub fn tls12_prf(secret: &[u8], label: &[u8], seed: &[u8], out_len: usize) -> Result<Vec<u8>> {
    let mut label_seed = Vec::with_capacity(label.len() + seed.len());
    label_seed.extend_from_slice(label);
    label_seed.extend_from_slice(seed);

    let mut out = Vec::with_capacity(out_len);
    // `a` and `block_seed` are HMACs of the secret, so they are sensitive;
    // scrub them as the P_hash chain advances. Callers wrap the returned key
    // material in `Zeroizing`.
    let mut a = hmac_sha256(secret, &label_seed)?;
    while out.len() < out_len {
        let mut block_seed = Vec::with_capacity(a.len() + label_seed.len());
        block_seed.extend_from_slice(&a);
        block_seed.extend_from_slice(&label_seed);
        out.extend_from_slice(&hmac_sha256(secret, &block_seed)?);
        block_seed.zeroize();
        let next = hmac_sha256(secret, &a)?;
        a.zeroize();
        a = next;
    }
    a.zeroize();
    out.truncate(out_len);
    Ok(out)
}

/// Derives the TLS 1.2 master secret from the ECJPAKE premaster secret.
pub fn derive_master_secret(
    pre_master_secret: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> Result<[u8; 48]> {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);
    let bytes = Zeroizing::new(tls12_prf(pre_master_secret, b"master secret", &seed, 48)?);
    let mut out = [0u8; 48];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Derives AES-128-CCM-8 keys and fixed IVs for the Thread DTLS profile.
pub fn derive_aes_128_ccm_8_key_block(
    master_secret: &[u8; 48],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> Result<Tls12Aes128Ccm8KeyBlock> {
    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);
    let bytes = Zeroizing::new(tls12_prf(master_secret, b"key expansion", &seed, 40)?);
    let mut client_write_key = [0u8; 16];
    let mut server_write_key = [0u8; 16];
    let mut client_write_iv = [0u8; 4];
    let mut server_write_iv = [0u8; 4];
    client_write_key.copy_from_slice(&bytes[0..16]);
    server_write_key.copy_from_slice(&bytes[16..32]);
    client_write_iv.copy_from_slice(&bytes[32..36]);
    server_write_iv.copy_from_slice(&bytes[36..40]);
    Ok(Tls12Aes128Ccm8KeyBlock {
        client_write_key,
        server_write_key,
        client_write_iv,
        server_write_iv,
    })
}

/// Derives the Thread Joiner Router KEK from an established DTLS session.
///
/// The KEK is `SHA-256(key_block)[0..16]` where `key_block` is the 40-byte
/// AES-128-CCM-8 expansion, matching mbedTLS key-export behavior in both
/// OpenThread joiners and the C++ commissioner.
pub fn derive_joiner_router_kek(
    master_secret: &[u8; 48],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> Result<[u8; 16]> {
    use sha2::Digest;

    let mut seed = Vec::with_capacity(64);
    seed.extend_from_slice(server_random);
    seed.extend_from_slice(client_random);
    let key_block = Zeroizing::new(tls12_prf(master_secret, b"key expansion", &seed, 40)?);
    let digest = Sha256::digest(&*key_block);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    Ok(out)
}

/// Computes the 12-byte Finished `verify_data` for `role` over the handshake
/// transcript hash (RFC 5246 §7.4.9).
pub fn finished_verify_data(
    master_secret: &[u8; 48],
    role: FinishedRole,
    handshake_hash: &[u8; 32],
) -> Result<[u8; 12]> {
    let label = match role {
        FinishedRole::Client => b"client finished".as_slice(),
        FinishedRole::Server => b"server finished".as_slice(),
    };
    let bytes = Zeroizing::new(tls12_prf(master_secret, label, handshake_hash, 12)?);
    let mut out = [0u8; 12];
    out.copy_from_slice(&bytes);
    Ok(out)
}
fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<[u8; 32]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key)
        .map_err(|_| Error::Crypto("invalid HMAC key".to_string()))?;
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
