//! TLS EC J-PAKE wire codecs: the `ECSchnorrZKP` proof structure, the
//! `ECJPAKEKeyKPPairList` (round one), and the key-exchange parameters
//! (round two), with a small cursor that length-checks every field.

use alloc::{format, string::ToString, vec::Vec};

use p256::ProjectivePoint;

use crate::{Result, error::Error};

use super::{RoundOne, RoundTwo, SchnorrProof, point_from_bytes, point_to_bytes, scalar_from_repr};

impl SchnorrProof {
    /// Encodes this proof as the TLS `ECSchnorrZKP` structure used by EC J-PAKE.
    pub fn encode_tls(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        write_tls_point(&mut out, &self.v)?;
        let r = trim_scalar_bytes(&self.r);
        validate_tls_u8_len(r.len(), "Schnorr scalar")?;
        if r.is_empty() {
            return Err(Error::Crypto(
                "Schnorr scalar must not be empty".to_string(),
            ));
        }
        out.push(r.len() as u8);
        out.extend_from_slice(r);
        Ok(out)
    }
}

impl RoundOne {
    /// Encodes this message as a TLS `ECJPAKEKeyKPPairList`.
    pub fn encode_tls_kkpp(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        write_key_kp(&mut out, &self.g1, &self.proof1)?;
        write_key_kp(&mut out, &self.g2, &self.proof2)?;
        Ok(out)
    }

    /// Decodes and verifies a TLS `ECJPAKEKeyKPPairList`.
    pub fn decode_tls_kkpp(bytes: &[u8], participant_id: impl Into<Vec<u8>>) -> Result<Self> {
        let participant_id = participant_id.into();
        let mut cursor = TlsEcJpakeCursor::new(bytes);
        let (g1, proof1) = cursor.read_key_kp(&participant_id)?;
        let (g2, proof2) = cursor.read_key_kp(&participant_id)?;
        cursor.finish()?;

        let out = Self {
            g1,
            g2,
            proof1,
            proof2,
            participant_id,
        };
        let base = ProjectivePoint::GENERATOR;
        let g1 = point_from_bytes(&out.g1)?;
        let g2 = point_from_bytes(&out.g2)?;
        out.proof1.verify(&base, &g1, &out.participant_id, b"")?;
        out.proof2.verify(&base, &g2, &out.participant_id, b"")?;
        Ok(out)
    }
}

impl RoundTwo {
    /// Encodes this message as TLS EC J-PAKE key-exchange parameters.
    ///
    /// ServerKeyExchange carries the named-curve parameters before the key
    /// proof, while ClientKeyExchange carries only the key proof.
    pub fn encode_tls_key_exchange(&self, include_curve_params: bool) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        if include_curve_params {
            write_secp256r1_curve_params(&mut out);
        }
        write_key_kp(&mut out, &self.point, &self.proof)?;
        Ok(out)
    }

    /// Decodes TLS EC J-PAKE key-exchange parameters.
    pub fn decode_tls_key_exchange(
        bytes: &[u8],
        participant_id: impl Into<Vec<u8>>,
        expect_curve_params: bool,
    ) -> Result<Self> {
        let participant_id = participant_id.into();
        let mut cursor = TlsEcJpakeCursor::new(bytes);
        if expect_curve_params {
            cursor.read_secp256r1_curve_params()?;
        }
        let (point, proof) = cursor.read_key_kp(&participant_id)?;
        cursor.finish()?;
        Ok(Self { point, proof })
    }
}

fn write_key_kp(out: &mut Vec<u8>, point: &[u8], proof: &SchnorrProof) -> Result<()> {
    write_tls_point(out, point)?;
    out.extend_from_slice(&proof.encode_tls()?);
    Ok(())
}

fn write_tls_point(out: &mut Vec<u8>, point: &[u8]) -> Result<()> {
    let parsed = point_from_bytes(point)?;
    let canonical = point_to_bytes(&parsed);
    validate_tls_u8_len(canonical.len(), "EC point")?;
    out.push(canonical.len() as u8);
    out.extend_from_slice(&canonical);
    Ok(())
}

/// Rejects a length that would not fit in the TLS one-byte length prefix.
pub(super) fn validate_tls_u8_len(len: usize, name: &str) -> Result<()> {
    if len > u8::MAX as usize {
        return Err(Error::Crypto(format!("{name} exceeds 255 bytes")));
    }
    Ok(())
}

/// Trims leading zero bytes from a 32-byte scalar, keeping at least one byte.
pub(super) fn trim_scalar_bytes(bytes: &[u8; 32]) -> &[u8] {
    let first_nonzero = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len() - 1);
    &bytes[first_nonzero..]
}

fn write_secp256r1_curve_params(out: &mut Vec<u8>) {
    out.extend_from_slice(&[0x03, 0x00, 0x17]);
}

/// Cursor over a TLS EC J-PAKE structure, length-checking each field.
pub(super) struct TlsEcJpakeCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> TlsEcJpakeCursor<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_key_kp(&mut self, participant_id: &[u8]) -> Result<(Vec<u8>, SchnorrProof)> {
        let point = self.read_tls_point()?;
        let proof = self.read_proof(participant_id)?;
        Ok((point, proof))
    }

    pub(super) fn read_proof(&mut self, participant_id: &[u8]) -> Result<SchnorrProof> {
        let v = self.read_tls_point()?;
        let r_bytes = self.read_opaque_u8("Schnorr scalar")?;
        if r_bytes.is_empty() {
            return Err(Error::Crypto(
                "Schnorr scalar must not be empty".to_string(),
            ));
        }
        if r_bytes.len() > 32 {
            return Err(Error::Crypto("Schnorr scalar exceeds 32 bytes".to_string()));
        }
        let mut r = [0u8; 32];
        let start = r.len() - r_bytes.len();
        r[start..].copy_from_slice(r_bytes);
        scalar_from_repr(r)?;
        Ok(SchnorrProof {
            v,
            r,
            prover_id: participant_id.to_vec(),
        })
    }

    fn read_tls_point(&mut self) -> Result<Vec<u8>> {
        let point = self.read_opaque_u8("EC point")?.to_vec();
        let parsed = point_from_bytes(&point)?;
        Ok(point_to_bytes(&parsed))
    }

    fn read_secp256r1_curve_params(&mut self) -> Result<()> {
        let curve_type = self.read_u8()?;
        let named_curve = self.read_u16()?;
        if curve_type != 0x03 || named_curve != 0x0017 {
            return Err(Error::Crypto(
                "ECJPAKE key exchange does not use secp256r1".to_string(),
            ));
        }
        Ok(())
    }

    fn read_opaque_u8(&mut self, name: &str) -> Result<&'a [u8]> {
        let len = self.read_u8()? as usize;
        if len == 0 {
            return Err(Error::Crypto(format!("{name} is empty")));
        }
        self.read_exact(len)
    }

    fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16> {
        let bytes = self.read_exact(2)?;
        Ok(crate::util::read_u16(bytes))
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| Error::Crypto("ECJPAKE cursor offset overflow".to_string()))?;
        if self.bytes.len() < end {
            return Err(Error::Crypto("ECJPAKE structure is truncated".to_string()));
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }

    fn finish(&self) -> Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::Crypto(
                "trailing bytes after ECJPAKE structure".to_string(),
            ))
        }
    }
}
