//! EC J-PAKE and Schnorr NIZK helpers for the Thread DTLS profile.
//!
//! This module follows the EC form in RFC 8236 and the Schnorr NIZK proof in
//! RFC 8235. It deliberately keeps TLS/DTLS handshake framing outside the
//! protocol itself; callers provide the message transcript and transport
//! framing.
//!
//! The protocol state machine ([`EcJpakeParty`]) and the shared P-256 scalar
//! and point helpers live here; the Schnorr proof generation/verification is in
//! the private `schnorr` module, and the TLS `ECJPAKEKeyKPPairList` /
//! key-exchange codecs are in the private `codec` module.

use alloc::{string::ToString, vec::Vec};

use p256::{
    AffinePoint, EncodedPoint, ProjectivePoint, Scalar, U256,
    elliptic_curve::{
        ff::Field,
        group::Group,
        ops::Reduce,
        sec1::{FromEncodedPoint, ToEncodedPoint},
    },
};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::{Result, error::Error};

mod codec;
mod schnorr;
#[cfg(test)]
mod tests;

/// Thread/TLS EC J-PAKE client proof identity.
pub const THREAD_CLIENT_ID: &[u8] = b"client";

/// Thread/TLS EC J-PAKE server proof identity.
pub const THREAD_SERVER_ID: &[u8] = b"server";

/// Participant role used to derive a stable transcript order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcJpakeRole {
    /// Alice/client side of RFC 8236.
    Client,
    /// Bob/server side of RFC 8236.
    Server,
}

/// Schnorr NIZK proof over P-256.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchnorrProof {
    /// SEC1-encoded commitment point V.
    pub v: Vec<u8>,
    /// Scalar response r in 32-byte big-endian form.
    pub r: [u8; 32],
    /// Prover identity used in the Fiat-Shamir challenge.
    pub prover_id: Vec<u8>,
}

/// First-round J-PAKE message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundOne {
    /// SEC1-encoded G*x1 or G*x3.
    pub g1: Vec<u8>,
    /// SEC1-encoded G*x2 or G*x4.
    pub g2: Vec<u8>,
    /// Proof for x1/x3.
    pub proof1: SchnorrProof,
    /// Proof for x2/x4.
    pub proof2: SchnorrProof,
    /// Sender identity.
    pub participant_id: Vec<u8>,
}

/// Second-round J-PAKE message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundTwo {
    /// SEC1-encoded A or B point.
    pub point: Vec<u8>,
    /// Proof for x2*s or x4*s.
    pub proof: SchnorrProof,
}

/// One EC J-PAKE participant.
pub struct EcJpakeParty {
    role: EcJpakeRole,
    participant_id: Vec<u8>,
    secret: Scalar,
    x1: Scalar,
    x2: Scalar,
}

impl core::fmt::Debug for EcJpakeParty {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EcJpakeParty")
            .field("role", &self.role)
            .field("participant_id", &self.participant_id)
            .field("secret", &"<redacted>")
            .field("x1", &"<redacted>")
            .field("x2", &"<redacted>")
            .finish()
    }
}

impl Drop for EcJpakeParty {
    fn drop(&mut self) {
        self.secret.zeroize();
        self.x1.zeroize();
        self.x2.zeroize();
        self.participant_id.zeroize();
    }
}

impl EcJpakeParty {
    /// Creates a Thread-profile party using the role's fixed TLS EC J-PAKE identity.
    pub fn new_thread(
        role: EcJpakeRole,
        shared_secret: &[u8],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Self {
        Self::new_thread_with_rng(rng, role, shared_secret)
    }

    /// Creates a Thread-profile party with randomness supplied by the caller.
    pub fn new_thread_with_rng(
        rng: &mut (impl RngCore + CryptoRng),
        role: EcJpakeRole,
        shared_secret: &[u8],
    ) -> Self {
        Self::new_with_rng(rng, role, role.thread_participant_id(), shared_secret)
    }

    /// Creates a party with random ephemeral scalars.
    pub fn new(
        role: EcJpakeRole,
        participant_id: impl Into<Vec<u8>>,
        shared_secret: &[u8],
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Self {
        Self::new_with_rng(rng, role, participant_id, shared_secret)
    }

    /// Creates a party with caller-supplied randomness for its ephemeral scalars.
    pub fn new_with_rng(
        rng: &mut (impl RngCore + CryptoRng),
        role: EcJpakeRole,
        participant_id: impl Into<Vec<u8>>,
        shared_secret: &[u8],
    ) -> Self {
        Self {
            role,
            participant_id: participant_id.into(),
            secret: scalar_from_secret(shared_secret),
            x1: random_scalar(rng, false),
            x2: random_scalar(rng, false),
        }
    }

    /// Creates a deterministic party for tests and reproducible vectors.
    ///
    /// This constructor uses the role's fixed Thread/TLS identity:
    /// `client` for the commissioner and `server` for the border agent.
    pub fn new_thread_with_scalars(
        role: EcJpakeRole,
        shared_secret: &[u8],
        x1: [u8; 32],
        x2: [u8; 32],
    ) -> Result<Self> {
        Self::new_with_scalars(role, role.thread_participant_id(), shared_secret, x1, x2)
    }

    /// Creates a deterministic party for tests and reproducible vectors.
    pub fn new_with_scalars(
        role: EcJpakeRole,
        participant_id: impl Into<Vec<u8>>,
        shared_secret: &[u8],
        x1: [u8; 32],
        x2: [u8; 32],
    ) -> Result<Self> {
        let x1 = scalar_from_repr(x1)?;
        let x2 = scalar_from_repr(x2)?;
        if bool::from(x1.is_zero()) {
            return Err(Error::Crypto("x1/x3 must be nonzero".to_string()));
        }
        if bool::from(x2.is_zero()) {
            return Err(Error::Crypto("x2/x4 must be nonzero".to_string()));
        }
        Ok(Self {
            role,
            participant_id: participant_id.into(),
            secret: scalar_from_secret(shared_secret),
            x1,
            x2,
        })
    }

    /// Returns this party's role.
    pub const fn role(&self) -> EcJpakeRole {
        self.role
    }

    /// Builds the first round message.
    pub fn round_one(&self, rng: &mut (impl RngCore + CryptoRng)) -> RoundOne {
        let base = ProjectivePoint::GENERATOR;
        let g1 = base * self.x1;
        let g2 = base * self.x2;
        let proof1 = SchnorrProof::generate(&base, &self.x1, &g1, &self.participant_id, b"", rng);
        let proof2 = SchnorrProof::generate(&base, &self.x2, &g2, &self.participant_id, b"", rng);

        RoundOne {
            g1: point_to_bytes(&g1),
            g2: point_to_bytes(&g2),
            proof1,
            proof2,
            participant_id: self.participant_id.clone(),
        }
    }

    /// Verifies a peer's first-round message.
    pub fn verify_round_one(&self, peer: &RoundOne) -> Result<()> {
        let base = ProjectivePoint::GENERATOR;
        let g1 = point_from_bytes(&peer.g1)?;
        let g2 = point_from_bytes(&peer.g2)?;
        if bool::from(g2.is_identity()) {
            return Err(Error::Crypto(
                "peer x2/x4 point must not be identity".to_string(),
            ));
        }
        peer.proof1.verify(&base, &g1, &peer.participant_id, b"")?;
        peer.proof2.verify(&base, &g2, &peer.participant_id, b"")?;
        Ok(())
    }

    /// Builds the second round message.
    pub fn round_two(
        &self,
        own_round_one: &RoundOne,
        peer_round_one: &RoundOne,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<RoundTwo> {
        self.verify_round_one(peer_round_one)?;
        let base = self.second_round_base(own_round_one, peer_round_one, self.role)?;
        if bool::from(base.is_identity()) {
            return Err(Error::Crypto(
                "second-round generator is identity".to_string(),
            ));
        }
        let exponent = self.x2 * self.secret;
        let point = base * exponent;
        let proof =
            SchnorrProof::generate(&base, &exponent, &point, &self.participant_id, b"", rng);
        Ok(RoundTwo {
            point: point_to_bytes(&point),
            proof,
        })
    }

    /// Verifies the peer's second round and derives a 32-byte session key.
    pub fn finish(
        &self,
        own_round_one: &RoundOne,
        peer_round_one: &RoundOne,
        peer_round_two: &RoundTwo,
    ) -> Result<[u8; 32]> {
        self.verify_round_one(peer_round_one)?;
        let peer_base =
            self.second_round_base(own_round_one, peer_round_one, self.role.peer_role())?;
        let peer_point = point_from_bytes(&peer_round_two.point)?;
        peer_round_two.proof.verify(
            &peer_base,
            &peer_point,
            &peer_round_one.participant_id,
            b"",
        )?;

        let peer_x2_point = point_from_bytes(&peer_round_one.g2)?;
        let exponent = self.x2 * self.secret;
        let shared = (peer_point - (peer_x2_point * exponent)) * self.x2;

        if bool::from(shared.is_identity()) {
            return Err(Error::Crypto(
                "derived J-PAKE point is identity".to_string(),
            ));
        }

        derive_session_key(&shared, self.role, own_round_one, peer_round_one)
    }

    fn second_round_base(
        &self,
        own: &RoundOne,
        peer: &RoundOne,
        sender_role: EcJpakeRole,
    ) -> Result<ProjectivePoint> {
        let own_g1 = point_from_bytes(&own.g1)?;
        let own_g2 = point_from_bytes(&own.g2)?;
        let peer_g1 = point_from_bytes(&peer.g1)?;
        let peer_g2 = point_from_bytes(&peer.g2)?;

        Ok(match (self.role, sender_role) {
            (EcJpakeRole::Client, EcJpakeRole::Client) => own_g1 + peer_g1 + peer_g2,
            (EcJpakeRole::Client, EcJpakeRole::Server) => own_g1 + own_g2 + peer_g1,
            (EcJpakeRole::Server, EcJpakeRole::Server) => peer_g1 + peer_g2 + own_g1,
            (EcJpakeRole::Server, EcJpakeRole::Client) => peer_g1 + own_g1 + own_g2,
        })
    }
}

impl EcJpakeRole {
    /// Returns the fixed TLS EC J-PAKE participant identity for this role.
    pub const fn thread_participant_id(self) -> &'static [u8] {
        match self {
            Self::Client => THREAD_CLIENT_ID,
            Self::Server => THREAD_SERVER_ID,
        }
    }

    fn peer_role(self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }
}

/// Returns a random nonzero (or possibly-zero, when `allow_zero`) scalar.
pub(super) fn random_scalar(rng: &mut (impl RngCore + CryptoRng), allow_zero: bool) -> Scalar {
    loop {
        let scalar = Scalar::random(&mut *rng);
        if allow_zero {
            return scalar;
        }
        if bool::from(scalar.is_zero()) {
            continue;
        }
        return scalar;
    }
}

fn scalar_from_secret(secret: &[u8]) -> Scalar {
    let mut bytes = [0u8; 32];
    if secret.len() <= bytes.len() {
        let start = bytes.len() - secret.len();
        bytes[start..].copy_from_slice(secret);
    } else {
        bytes.copy_from_slice(&Sha256::digest(secret));
    }
    let scalar = <Scalar as Reduce<U256>>::reduce_bytes(&bytes.into());
    if bool::from(scalar.is_zero()) {
        Scalar::ONE
    } else {
        scalar
    }
}

/// Parses a 32-byte big-endian scalar, rejecting values outside the field.
pub(super) fn scalar_from_repr(bytes: [u8; 32]) -> Result<Scalar> {
    use p256::elliptic_curve::ff::PrimeField;
    Option::<Scalar>::from(Scalar::from_repr(bytes.into()))
        .ok_or_else(|| Error::Crypto("invalid scalar representation".to_string()))
}

/// Decodes a non-identity SEC1 point that lies on P-256.
pub(super) fn point_from_bytes(bytes: &[u8]) -> Result<ProjectivePoint> {
    let encoded = EncodedPoint::from_bytes(bytes)
        .map_err(|_| Error::Crypto("invalid SEC1 point encoding".to_string()))?;
    let affine = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&encoded))
        .ok_or_else(|| Error::Crypto("point is not on P-256".to_string()))?;
    let point = ProjectivePoint::from(affine);
    if bool::from(point.is_identity()) {
        return Err(Error::Crypto("identity point is not allowed".to_string()));
    }
    Ok(point)
}

/// Encodes a point in uncompressed SEC1 form.
pub(super) fn point_to_bytes(point: &ProjectivePoint) -> Vec<u8> {
    point
        .to_affine()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}

fn derive_session_key(
    shared: &ProjectivePoint,
    role: EcJpakeRole,
    _own: &RoundOne,
    _peer: &RoundOne,
) -> Result<[u8; 32]> {
    let _ = role;
    // The shared point's X coordinate is the raw J-PAKE secret; scrub it once
    // it has been hashed into the session key.
    let shared_x = Zeroizing::new(point_x_bytes(shared)?);
    let digest = Sha256::digest(&*shared_x);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Ok(out)
}

fn point_x_bytes(point: &ProjectivePoint) -> Result<Vec<u8>> {
    let bytes = point_to_bytes(point);
    let encoded = EncodedPoint::from_bytes(&bytes)
        .map_err(|_| Error::Crypto("invalid SEC1 point encoding".to_string()))?;
    let x = encoded
        .x()
        .ok_or_else(|| Error::Crypto("SEC1 point has no X coordinate".to_string()))?;
    Ok(x.to_vec())
}
