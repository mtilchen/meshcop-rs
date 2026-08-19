//! Schnorr NIZK proof generation and verification (RFC 8235).

use alloc::string::ToString;

use p256::{
    ProjectivePoint, Scalar, U256,
    elliptic_curve::{group::Group, ops::Reduce},
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use crate::{Result, error::Error};

use super::{SchnorrProof, point_from_bytes, point_to_bytes, random_scalar, scalar_from_repr};

impl SchnorrProof {
    /// Generates a Schnorr NIZK proof of knowledge of `private` such that
    /// `public = base * private`, bound to `prover_id` via Fiat-Shamir.
    pub fn generate(
        base: &ProjectivePoint,
        private: &Scalar,
        public: &ProjectivePoint,
        prover_id: &[u8],
        other_info: &[u8],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Self {
        let v_scalar = random_scalar(rng, false);
        let v_point = *base * v_scalar;
        let challenge = challenge_scalar(base, &v_point, public, prover_id, other_info);
        let r = v_scalar - (*private * challenge);
        let mut r_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&r.to_bytes());
        Self {
            v: point_to_bytes(&v_point),
            r: r_bytes,
            prover_id: prover_id.to_vec(),
        }
    }

    /// Verifies this proof against the given base and public point.
    pub fn verify(
        &self,
        base: &ProjectivePoint,
        public: &ProjectivePoint,
        expected_prover_id: &[u8],
        other_info: &[u8],
    ) -> Result<()> {
        if self.prover_id != expected_prover_id {
            return Err(Error::Crypto("Schnorr proof identity mismatch".to_string()));
        }
        if bool::from(public.is_identity()) {
            return Err(Error::Crypto(
                "Schnorr public point is identity".to_string(),
            ));
        }
        let v_point = point_from_bytes(&self.v)?;
        let r = scalar_from_repr(self.r)?;
        let challenge = challenge_scalar(base, &v_point, public, expected_prover_id, other_info);
        let expected = (*base * r) + (*public * challenge);
        if point_to_bytes(&expected) != self.v {
            return Err(Error::Crypto(
                "Schnorr proof verification failed".to_string(),
            ));
        }
        Ok(())
    }
}

/// Computes the Fiat-Shamir challenge scalar over the proof transcript.
fn challenge_scalar(
    base: &ProjectivePoint,
    v: &ProjectivePoint,
    public: &ProjectivePoint,
    prover_id: &[u8],
    other_info: &[u8],
) -> Scalar {
    let mut hasher = Sha256::new();
    hash_item(&mut hasher, &point_to_bytes(base));
    hash_item(&mut hasher, &point_to_bytes(v));
    hash_item(&mut hasher, &point_to_bytes(public));
    hash_item(&mut hasher, prover_id);
    if !other_info.is_empty() {
        hash_item(&mut hasher, other_info);
    }
    let digest = hasher.finalize();
    <Scalar as Reduce<U256>>::reduce_bytes(&digest)
}

/// Hashes one length-prefixed item into the challenge transcript.
fn hash_item(hasher: &mut Sha256, item: &[u8]) {
    hasher.update((item.len() as u32).to_be_bytes());
    hasher.update(item);
}
