//! PSKc, joiner ID, and steering-data helpers.

use aes::Aes128;
use cmac::{Cmac, Mac};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{Result, dataset::Dataset, error::Error};

/// Maximum PSKc length in bytes.
pub const MAX_PSKC_LEN: usize = 16;
const MIN_COMMISSIONER_CREDENTIAL_LEN: usize = 6;
const MAX_COMMISSIONER_CREDENTIAL_LEN: usize = 255;
const MAX_NETWORK_NAME_LEN: usize = 16;
const EXTENDED_PAN_ID_LEN: usize = 8;
const JOINER_ID_LEN: usize = 8;
const LOCAL_EXTERNAL_ADDR_MASK: u8 = 1 << 1;
const MAX_STEERING_DATA_LEN: usize = 16;

type Aes128Cmac = Cmac<Aes128>;

/// The 128-bit pre-shared key for the Thread commissioner.
///
/// A PSKc is the EC J-PAKE password used to authenticate a commissioner to a
/// border agent. Its contents are redacted from debug output and zeroized when
/// dropped.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Pskc([u8; MAX_PSKC_LEN]);

impl core::fmt::Debug for Pskc {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Pskc").field(&"<redacted>").finish()
    }
}

impl Pskc {
    /// Creates a PSKc from its 16-byte representation.
    pub const fn new(bytes: [u8; MAX_PSKC_LEN]) -> Self {
        Self(bytes)
    }

    /// Parses a PSKc from exactly 32 hexadecimal digits.
    pub fn from_hex(value: &str) -> Result<Self> {
        let bytes = Zeroizing::new(hex::decode(value)?);
        let bytes = bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::Dataset("PSKc must be exactly 16 bytes".to_string()))?;
        Ok(Self::new(bytes))
    }

    /// Returns the raw PSKc bytes.
    pub const fn as_bytes(&self) -> &[u8; MAX_PSKC_LEN] {
        &self.0
    }
}

impl From<[u8; MAX_PSKC_LEN]> for Pskc {
    fn from(bytes: [u8; MAX_PSKC_LEN]) -> Self {
        Self::new(bytes)
    }
}

/// Extracts the PSKc TLV from an active dataset.
pub fn pskc_from_active_dataset(dataset: &Dataset) -> Result<Pskc> {
    let bytes = dataset
        .pskc()
        .ok_or_else(|| Error::Dataset("dataset does not contain PSKc".to_string()))?
        .try_into()
        .map_err(|_| Error::Dataset("PSKc TLV must be 16 bytes".to_string()))?;
    Ok(Pskc::new(bytes))
}

/// Generates PSKc using Thread's PBKDF2-AES-CMAC-PRF-128 construction.
///
/// Pinned to the worked example in Thread 1.4.0 §8.4.1.2.1 "Derivation of
/// PSKc" (carried unchanged from Thread 1.2; also exercised by OpenThread).
/// See `docs/VECTORS.md`.
pub fn generate_pskc(
    passphrase: &str,
    network_name: &str,
    extended_pan_id: &[u8; EXTENDED_PAN_ID_LEN],
) -> Result<Pskc> {
    let passphrase_bytes = passphrase.as_bytes();
    if !(MIN_COMMISSIONER_CREDENTIAL_LEN..=MAX_COMMISSIONER_CREDENTIAL_LEN)
        .contains(&passphrase_bytes.len())
    {
        return Err(Error::Dataset(format!(
            "passphrase length must be in [{MIN_COMMISSIONER_CREDENTIAL_LEN}, {MAX_COMMISSIONER_CREDENTIAL_LEN}]"
        )));
    }
    if network_name.len() > MAX_NETWORK_NAME_LEN {
        return Err(Error::Dataset(format!(
            "network name is longer than {MAX_NETWORK_NAME_LEN} bytes"
        )));
    }

    let mut salt = Vec::with_capacity(6 + EXTENDED_PAN_ID_LEN + network_name.len());
    salt.extend_from_slice(b"Thread");
    salt.extend_from_slice(extended_pan_id);
    salt.extend_from_slice(network_name.as_bytes());

    let mut out = [0u8; MAX_PSKC_LEN];
    pbkdf2_aes_cmac_prf_128(passphrase_bytes, &salt, 16_384, &mut out)?;
    Ok(Pskc::new(out))
}

/// Computes the Thread joiner ID from an EUI-64.
pub fn compute_joiner_id(eui64: u64) -> [u8; JOINER_ID_LEN] {
    let digest = Sha256::digest(eui64.to_be_bytes());
    let mut joiner_id = [0u8; JOINER_ID_LEN];
    joiner_id.copy_from_slice(&digest[..JOINER_ID_LEN]);
    joiner_id[0] |= LOCAL_EXTERNAL_ADDR_MASK;
    joiner_id
}

/// Adds a joiner ID to steering data using Thread's two-CRC Bloom filter.
pub fn add_joiner_to_steering_data(steering_data: &mut Vec<u8>, joiner_id: &[u8]) {
    if steering_data.len() != MAX_STEERING_DATA_LEN {
        steering_data.resize(MAX_STEERING_DATA_LEN, 0);
        steering_data.fill(0);
    }
    compute_bloom_filter(steering_data, joiner_id);
}

fn pbkdf2_aes_cmac_prf_128(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out: &mut [u8],
) -> Result<()> {
    if iterations == 0 {
        return Err(Error::Crypto(
            "PBKDF2 iteration count must be nonzero".to_string(),
        ));
    }

    let mut block_counter = 1u32;
    let mut offset = 0usize;
    while offset < out.len() {
        let mut input = Vec::with_capacity(salt.len() + 4);
        input.extend_from_slice(salt);
        input.extend_from_slice(&block_counter.to_be_bytes());

        let mut u = aes_cmac_prf_128(password, &input)?;
        let mut t = u;
        for _ in 1..iterations {
            u = aes_cmac_prf_128(password, &u)?;
            for (dst, src) in t.iter_mut().zip(u) {
                *dst ^= src;
            }
        }
        input.zeroize();

        let len = core::cmp::min(out.len() - offset, t.len());
        out[offset..offset + len].copy_from_slice(&t[..len]);
        // `u`/`t` are PSKc-derived PRF blocks; scrub them once consumed.
        u.zeroize();
        t.zeroize();
        offset += len;
        block_counter = block_counter
            .checked_add(1)
            .ok_or_else(|| Error::Crypto("PBKDF2 block counter overflow".to_string()))?;
    }

    Ok(())
}

fn aes_cmac_prf_128(key: &[u8], message: &[u8]) -> Result<[u8; 16]> {
    let mut prf_key = if key.len() == 16 {
        let mut fixed = [0u8; 16];
        fixed.copy_from_slice(key);
        fixed
    } else {
        aes_cmac(&[0u8; 16], key)?
    };
    let out = aes_cmac(&prf_key, message);
    prf_key.zeroize();
    out
}

fn aes_cmac(key: &[u8; 16], message: &[u8]) -> Result<[u8; 16]> {
    let mut mac = <Aes128Cmac as Mac>::new_from_slice(key)
        .map_err(|_| Error::Crypto("invalid AES-CMAC key".to_string()))?;
    mac.update(message);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn compute_bloom_filter(out: &mut [u8], input: &[u8]) {
    let num_bits = out.len() * 8;
    let ccitt = crc16(0x1021, input) as usize % num_bits;
    let ansi = crc16(0x8005, input) as usize % num_bits;
    set_bit(out, ccitt);
    set_bit(out, ansi);
}

fn set_bit(out: &mut [u8], bit: usize) {
    let idx = out.len() - 1 - (bit / 8);
    out[idx] |= 1 << (bit % 8);
}

fn crc16(poly: u16, bytes: &[u8]) -> u16 {
    let mut crc = 0u16;
    for byte in bytes {
        crc ^= (*byte as u16) << 8;
        for _ in 0..8 {
            crc = if (crc & 0x8000) != 0 {
                (crc << 1) ^ poly
            } else {
                crc << 1
            };
        }
    }
    crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dataset::Dataset;

    /// Golden vector: Thread 1.4.0 §8.4.1.2.1 "Test Vector for Derivation of
    /// PSKc". Provenance and regeneration: docs/VECTORS.md.
    #[test]
    fn generates_thread_pskc_test_vector() {
        let pskc = generate_pskc(
            "12SECRETPASSWORD34",
            "Test Network",
            &[0, 1, 2, 3, 4, 5, 6, 7],
        )
        .unwrap();
        assert_eq!(
            hex::encode(pskc.as_bytes()),
            "c3f59368445a1b6106be420a706d4cc9"
        );
    }

    #[test]
    fn extracts_pskc_from_dataset() {
        let dataset = Dataset::from_hex("0410000102030405060708090a0b0c0d0e0f").unwrap();
        assert_eq!(
            pskc_from_active_dataset(&dataset).unwrap().as_bytes(),
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
    }

    #[test]
    fn pskc_parses_hex_and_rejects_wrong_lengths() {
        let pskc = Pskc::from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        assert_eq!(
            pskc.as_bytes(),
            &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
        assert!(Pskc::from_hex("0001").is_err());
    }

    #[test]
    fn pskc_debug_is_redacted() {
        let rendered = format!("{:?}", Pskc::new([0xab; MAX_PSKC_LEN]));
        assert_eq!(rendered, "Pskc(\"<redacted>\")");
        assert!(!rendered.contains("ab"));
    }

    #[test]
    fn pskc_has_zeroize_on_drop_shape() {
        fn assert_zeroize_on_drop<T: zeroize::ZeroizeOnDrop>() {}

        assert_zeroize_on_drop::<Pskc>();
        let mut pskc = Pskc::new([0xab; MAX_PSKC_LEN]);
        pskc.zeroize();
        assert_eq!(pskc.as_bytes(), &[0; MAX_PSKC_LEN]);
    }

    #[test]
    fn computes_joiner_id_with_local_external_mask() {
        let id = compute_joiner_id(0x0012_4b00_01aa_bbcc);
        assert_eq!(id.len(), JOINER_ID_LEN);
        assert_eq!(id[0] & LOCAL_EXTERNAL_ADDR_MASK, LOCAL_EXTERNAL_ADDR_MASK);
    }

    #[test]
    fn crc16_matches_known_catalog_check_values() {
        // The two polynomials are the non-reflected, zero-init CRC-16 variants
        // used by Thread steering data. Their check values over b"123456789" are
        // the published CRC catalog constants for CRC-16/XMODEM and
        // CRC-16/BUYPASS, which pins the polynomial feedback and shift direction.
        assert_eq!(crc16(0x1021, b"123456789"), 0x31c3);
        assert_eq!(crc16(0x8005, b"123456789"), 0xfee8);
    }

    #[test]
    fn set_bit_indexes_from_most_significant_byte() {
        let mut out = [0u8; MAX_STEERING_DATA_LEN];
        set_bit(&mut out, 0);
        set_bit(&mut out, 8);
        set_bit(&mut out, 127);
        // Bit 0 is the LSB of the last byte; bit 127 is the MSB of the first.
        assert_eq!(out[15], 0x01);
        assert_eq!(out[14], 0x01);
        assert_eq!(out[0], 0x80);
        assert_eq!(out[1..14], [0u8; 13]);
    }

    /// Golden vector: the steering-data Bloom filter follows Thread 1.4.0
    /// §8.4.4.3. Both expected bit positions are derived independently from the
    /// spec algorithm (CRC16-CCITT 0x1021 % 128 = 44, CRC16-ANSI 0x8005 % 128 =
    /// 14, big-endian mask), anchored by the catalog CRC checks in
    /// `crc16_matches_known_catalog_check_values`. Provenance: docs/VECTORS.md.
    #[test]
    fn compute_bloom_filter_sets_two_crc_indexed_bits() {
        let mut out = [0u8; MAX_STEERING_DATA_LEN];
        compute_bloom_filter(&mut out, &[1, 2, 3, 4, 5, 6, 7, 8]);
        // CCITT CRC selects bit 44 (out[10] bit 4); ANSI CRC selects bit 14
        // (out[14] bit 6). The 128-bit modulus (16 bytes * 8) places them here.
        assert_eq!(
            out,
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
                0x40, 0x00,
            ]
        );
    }

    /// Golden vector: steering data for the OpenThread joiner ID
    /// d65e64fa83f81cf7 per Thread 1.4.0 §8.4.4.3. Independently derived bits
    /// (CRC16-CCITT % 128 = 1, CRC16-ANSI % 128 = 4) set bits 1 and 4 of the
    /// final byte (0x12), tying steering data to the same joiner used in
    /// `compute_joiner_id_matches_openthread`. Provenance: docs/VECTORS.md.
    #[test]
    fn compute_bloom_filter_matches_spec_for_openthread_joiner() {
        let mut out = [0u8; MAX_STEERING_DATA_LEN];
        compute_bloom_filter(&mut out, &[0xd6, 0x5e, 0x64, 0xfa, 0x83, 0xf8, 0x1c, 0xf7]);
        assert_eq!(
            out,
            [
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x12,
            ]
        );
    }

    #[test]
    fn generate_pskc_enforces_network_name_length() {
        let xpan = [0, 1, 2, 3, 4, 5, 6, 7];
        // A 16-byte network name is the maximum and must be accepted.
        assert!(generate_pskc("12SECRETPASSWORD34", "0123456789abcdef", &xpan).is_ok());
        // 17 bytes is one over the limit and must be rejected.
        assert!(generate_pskc("12SECRETPASSWORD34", "0123456789abcdefg", &xpan).is_err());
    }

    #[test]
    fn compute_joiner_id_sets_local_external_bit_without_clearing_others() {
        // SHA-256(eui)[0] for this EUI is 0xd1 (bit 1 clear), so ORing in the
        // local/external mask must yield 0xd3 — proving the mask value (2) and
        // the OR semantics, not an AND that would zero the other digest bits.
        let id = compute_joiner_id(0x0011_2233_4455_6677);
        assert_eq!(id, [0xd3, 0xa5, 0xf9, 0x98, 0xfa, 0x6e, 0xd8, 0x2d]);
    }

    /// Golden vector: joiner ID derivation matches OpenThread. The simulation
    /// node `ot-cli-ftd 2` (factory EUI-64 18b4300000000002) reports joiner ID
    /// d65e64fa83f81cf7 via its `joiner id` command, which this crate must
    /// reproduce. Provenance: docs/VECTORS.md.
    #[test]
    fn compute_joiner_id_matches_openthread() {
        let id = compute_joiner_id(0x18b4_3000_0000_0002);
        assert_eq!(id, [0xd6, 0x5e, 0x64, 0xfa, 0x83, 0xf8, 0x1c, 0xf7]);
    }

    #[test]
    fn pbkdf2_concatenates_blocks_across_a_partial_final_block() {
        // A 20-byte output spans two CMAC blocks with a 4-byte final block, so
        // the per-block `out.len() - offset` length must shrink on the second
        // pass. Block 1 of the longer output equals the standalone 16-byte run.
        let mut sixteen = [0u8; 16];
        pbkdf2_aes_cmac_prf_128(b"password", b"salt", 8, &mut sixteen).unwrap();
        let mut twenty = [0u8; 20];
        pbkdf2_aes_cmac_prf_128(b"password", b"salt", 8, &mut twenty).unwrap();
        assert_eq!(&twenty[..16], &sixteen);
        assert!(twenty[16..].iter().any(|b| *b != 0));
    }

    #[test]
    fn adds_joiner_to_steering_data() {
        let joiner_id = compute_joiner_id(0x0012_4b00_01aa_bbcc);
        let mut steering = Vec::new();
        add_joiner_to_steering_data(&mut steering, &joiner_id);
        assert_eq!(steering.len(), MAX_STEERING_DATA_LEN);
        assert!(steering.iter().any(|byte| *byte != 0));
    }
}
