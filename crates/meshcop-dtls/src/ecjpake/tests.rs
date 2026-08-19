use super::codec::{TlsEcJpakeCursor, trim_scalar_bytes, validate_tls_u8_len};
use super::*;
use rand_core::{CryptoRng, Error as RandError, OsRng, RngCore};

#[derive(Default)]
struct ZeroThenOneRng {
    fills: usize,
}

impl RngCore for ZeroThenOneRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_be_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_be_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0);
        if self.fills > 0 {
            let last = dest
                .last_mut()
                .expect("scalar generation always requests a nonempty buffer");
            *last = 1;
        }
        self.fills += 1;
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> core::result::Result<(), RandError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for ZeroThenOneRng {}

fn scalar_bytes(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..].copy_from_slice(&v.to_be_bytes());
    out
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    hex::decode(hex).unwrap()
}

fn hex_scalar(hex: &str) -> [u8; 32] {
    let bytes = hex_bytes(hex);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

#[test]
fn ecjpake_success_derives_same_key() {
    let mut rng = OsRng;
    let alice = EcJpakeParty::new_with_scalars(
        EcJpakeRole::Client,
        b"client",
        b"shared pskc",
        scalar_bytes(3),
        scalar_bytes(5),
    )
    .unwrap();
    let bob = EcJpakeParty::new_with_scalars(
        EcJpakeRole::Server,
        b"server",
        b"shared pskc",
        scalar_bytes(7),
        scalar_bytes(11),
    )
    .unwrap();

    let a1 = alice.round_one(&mut rng);
    let b1 = bob.round_one(&mut rng);
    let a2 = alice.round_two(&a1, &b1, &mut rng).unwrap();
    let b2 = bob.round_two(&b1, &a1, &mut rng).unwrap();

    let alice_key = alice.finish(&a1, &b1, &b2).unwrap();
    let bob_key = bob.finish(&b1, &a1, &a2).unwrap();
    assert_eq!(alice_key, bob_key);
}

#[test]
fn ecjpake_mismatched_secret_derives_different_keys() {
    let mut rng = OsRng;
    let alice = EcJpakeParty::new_with_scalars(
        EcJpakeRole::Client,
        b"client",
        b"secret a",
        scalar_bytes(3),
        scalar_bytes(5),
    )
    .unwrap();
    let bob = EcJpakeParty::new_with_scalars(
        EcJpakeRole::Server,
        b"server",
        b"secret b",
        scalar_bytes(7),
        scalar_bytes(11),
    )
    .unwrap();

    let a1 = alice.round_one(&mut rng);
    let b1 = bob.round_one(&mut rng);
    let a2 = alice.round_two(&a1, &b1, &mut rng).unwrap();
    let b2 = bob.round_two(&b1, &a1, &mut rng).unwrap();

    let alice_key = alice.finish(&a1, &b1, &b2).unwrap();
    let bob_key = bob.finish(&b1, &a1, &a2).unwrap();
    assert_ne!(alice_key, bob_key);
}

#[test]
fn corrupted_schnorr_proof_is_rejected() {
    let mut rng = OsRng;
    let alice = EcJpakeParty::new(EcJpakeRole::Client, b"client", b"shared pskc", &mut rng);
    let mut a1 = alice.round_one(&mut rng);
    a1.proof2.r[0] ^= 0x80;
    assert!(alice.verify_round_one(&a1).is_err());
}

#[test]
fn invalid_point_is_rejected() {
    assert!(point_from_bytes(&[0x04, 1, 2, 3]).is_err());
}

#[test]
fn deterministic_parties_reject_zero_ephemeral_scalars() {
    assert!(matches!(
        EcJpakeParty::new_with_scalars(
            EcJpakeRole::Client,
            b"client",
            b"shared pskc",
            scalar_bytes(0),
            scalar_bytes(5),
        ),
        Err(Error::Crypto(message)) if message == "x1/x3 must be nonzero"
    ));
    assert!(matches!(
        EcJpakeParty::new_with_scalars(
            EcJpakeRole::Server,
            b"server",
            b"shared pskc",
            scalar_bytes(7),
            scalar_bytes(0),
        ),
        Err(Error::Crypto(message)) if message == "x2/x4 must be nonzero"
    ));
}

#[test]
fn random_scalar_returns_zero_when_allowed() {
    let mut rng = ZeroThenOneRng::default();

    let scalar = random_scalar(&mut rng, true);

    assert!(bool::from(scalar.is_zero()));
    assert_eq!(rng.fills, 1);
}

#[test]
fn random_scalar_retries_zero_when_disallowed() {
    let mut rng = ZeroThenOneRng::default();

    let scalar = random_scalar(&mut rng, false);

    assert!(!bool::from(scalar.is_zero()));
    assert_eq!(rng.fills, 2);
}

#[test]
fn tls_round_one_and_round_two_codecs_round_trip() {
    let mut rng = OsRng;
    let client = EcJpakeParty::new_thread(EcJpakeRole::Client, b"shared pskc", &mut rng);
    let server = EcJpakeParty::new_thread(EcJpakeRole::Server, b"shared pskc", &mut rng);
    let client_one = client.round_one(&mut rng);
    let server_one = server.round_one(&mut rng);
    let server_two = server
        .round_two(&server_one, &client_one, &mut rng)
        .unwrap();

    let client_one_wire = client_one.encode_tls_kkpp().unwrap();
    assert_eq!(
        RoundOne::decode_tls_kkpp(&client_one_wire, THREAD_CLIENT_ID).unwrap(),
        client_one
    );

    let server_two_wire = server_two.encode_tls_key_exchange(true).unwrap();
    assert_eq!(
        RoundTwo::decode_tls_key_exchange(&server_two_wire, THREAD_SERVER_ID, true).unwrap(),
        server_two
    );
}

#[test]
fn tls_codecs_reject_bad_curve_params_and_trailing_bytes() {
    assert!(RoundTwo::decode_tls_key_exchange(&[0x03, 0x00, 0x18], b"server", true).is_err());

    let mut rng = OsRng;
    let client = EcJpakeParty::new_thread(EcJpakeRole::Client, b"shared pskc", &mut rng);
    let mut encoded = client.round_one(&mut rng).encode_tls_kkpp().unwrap();
    encoded.push(0);
    assert!(RoundOne::decode_tls_kkpp(&encoded, THREAD_CLIENT_ID).is_err());
}

#[test]
fn key_exchange_rejects_wrong_named_curve_even_with_valid_key_kp() {
    // A structurally valid key exchange whose named-curve identifier is
    // corrupted must be rejected. The curve check guards each field
    // independently, so flipping only the named curve still fails.
    let mut rng = OsRng;
    let server = EcJpakeParty::new_thread(EcJpakeRole::Server, b"shared pskc", &mut rng);
    let client = EcJpakeParty::new_thread(EcJpakeRole::Client, b"shared pskc", &mut rng);
    let client_one = client.round_one(&mut rng);
    let server_one = server.round_one(&mut rng);
    let server_two = server
        .round_two(&server_one, &client_one, &mut rng)
        .unwrap();
    let mut wire = server_two.encode_tls_key_exchange(true).unwrap();
    // Curve params are [0x03, 0x00, 0x17]; corrupt the named-curve low byte.
    assert_eq!(&wire[..3], &[0x03, 0x00, 0x17]);
    wire[2] = 0x18;
    assert!(RoundTwo::decode_tls_key_exchange(&wire, THREAD_SERVER_ID, true).is_err());
}

#[test]
fn read_proof_accepts_short_scalar_and_rejects_oversized_scalar() {
    let mut rng = OsRng;
    let client = EcJpakeParty::new_thread(EcJpakeRole::Client, b"shared pskc", &mut rng);
    let proof = client.round_one(&mut rng).proof1;

    // A scalar shorter than 32 bytes is left-padded and accepted.
    let mut wire = vec![proof.v.len() as u8];
    wire.extend_from_slice(&proof.v);
    wire.push(1);
    wire.push(0x01);
    assert!(
        TlsEcJpakeCursor::new(&wire)
            .read_proof(THREAD_CLIENT_ID)
            .is_ok()
    );

    // A scalar longer than 32 bytes is rejected.
    let mut oversized = vec![proof.v.len() as u8];
    oversized.extend_from_slice(&proof.v);
    oversized.push(33);
    oversized.extend_from_slice(&[0x01; 33]);
    assert!(
        TlsEcJpakeCursor::new(&oversized)
            .read_proof(THREAD_CLIENT_ID)
            .is_err()
    );
}

#[test]
fn validate_tls_u8_len_enforces_255_byte_ceiling() {
    assert!(validate_tls_u8_len(255, "x").is_ok());
    assert!(validate_tls_u8_len(256, "x").is_err());
}

#[test]
fn trim_scalar_bytes_keeps_one_byte_for_all_zero_scalar() {
    // With no nonzero byte, the fallback index (len - 1) retains the final
    // byte so the scalar is never trimmed to empty.
    assert_eq!(trim_scalar_bytes(&[0u8; 32]), &[0u8]);
    let mut bytes = [0u8; 32];
    bytes[30] = 0xaa;
    bytes[31] = 0xbb;
    assert_eq!(trim_scalar_bytes(&bytes), &[0xaa, 0xbb]);
}

#[test]
fn ecjpake_party_debug_redacts_secret_scalars() {
    let party = EcJpakeParty::new_with_scalars(
        EcJpakeRole::Client,
        b"client",
        b"shared pskc",
        scalar_bytes(3),
        scalar_bytes(5),
    )
    .unwrap();
    let rendered = format!("{party:?}");
    assert!(rendered.contains("EcJpakeParty"));
    assert!(rendered.contains("<redacted>"));
}

/// Golden vector: a cross-implementation conformance check against mbedTLS
/// (the canonical EC-JPAKE-for-TLS implementation). The deterministic scalars
/// are fed to both implementations; the round messages and expected premaster
/// secret below are what mbedTLS produces for them (via the harnesses in
/// `tools/`). This is not a verbatim entry from mbedTLS's own test suite.
/// Provenance and regeneration: docs/VECTORS.md.
#[test]
fn mbedtls_reference_handshake_derives_expected_premaster_secret() {
    let client = EcJpakeParty::new_thread_with_scalars(
        EcJpakeRole::Client,
        b"threadjpaketest",
        hex_scalar("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f21"),
        hex_scalar("6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f81"),
    )
    .unwrap();
    let server = EcJpakeParty::new_thread_with_scalars(
        EcJpakeRole::Server,
        b"threadjpaketest",
        hex_scalar("6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f81"),
        hex_scalar("c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe1"),
    )
    .unwrap();

    let client_one = RoundOne::decode_tls_kkpp(
        &hex_bytes(concat!(
            "4104accf0106ef858fa2d919331346805a78b58bbad0b844e5c7892879146187",
            "dd2666ada781bb7f111372251a8910621f634df128ac48e381fd6ef9060731f694a4",
            "41041dd0bd5d4566c9bed9ce7de701b5e82e08e84b730466018ab903c79eb9821722",
            "36c0c1728ae4bf73610d34de44246ef3d9c05a2236fb66a6583d7449308babce",
            "2072fe16662992e9235c25002f11b15087b82738e03c945bf7a2995dda1e983458",
            "41047ea6e3a4487037a9e0dbd79262b2cc273e779930fc18409ac5361c5fe669",
            "d702e147790aeb4ce7fd6575ab0f6c7fd1c335939aa863ba37ec91b7e32bb013",
            "bb2b4104a49558d32ed1ebfc1816af4ff09b55fcb4ca47b2a02d1e7caf1179",
            "ea3fe1395b22b861964016fabaf72c975695d93d4df0e5197fe9f040634ed597",
            "64937787be20bc4deebbf9b8d60a335f046ca3aa941e45864c7cadef9cf75b",
            "3d8b010e443ef0",
        )),
        THREAD_CLIENT_ID,
    )
    .unwrap();
    let server_one = RoundOne::decode_tls_kkpp(
        &hex_bytes(concat!(
            "41047ea6e3a4487037a9e0dbd79262b2cc273e779930fc18409ac5361c5fe669",
            "d702e147790aeb4ce7fd6575ab0f6c7fd1c335939aa863ba37ec91b7e32bb013",
            "bb2b410409f85b3d20ebd7885ce464c08d056d6428fe4dd9287aa365f131f436",
            "0ff386d846898bc4b41583c2a5197f65d78742746c12a5ec0a4ffe2f270a75",
            "0a1d8fb51620934d74eb43e54df424fd96306c0117bf131afabf90a9d33d1198",
            "d905193735144104190a07700ffa4be6ae1d79ee0f06aeb544cd5addaabedf70f",
            "8623321332c54f355f0fbfec783ed359e5d0bf7377a0fc4ea7ace473c9c112b",
            "41ccd41ac56a56124104360a1cea33fce641156458e0a4eac219e96831e6aebc",
            "88b3f3752f93a0281d1bf1fb106051db9694a8d6e862a5ef1324a3d9e27894",
            "f1ee4f7c59199965a8dd4a2091847d2d22df3ee55faa2a3fb33fd2d1e055",
            "a07a7c61ecfb8d80ec00c2c9eb12",
        )),
        THREAD_SERVER_ID,
    )
    .unwrap();
    let server_two = RoundTwo::decode_tls_key_exchange(
        &hex_bytes(concat!(
            "03001741040fb22b1d5d1123e0ef9feb9d8a2e590a1f4d7ced2c2b06586e8f",
            "2a16d4eb2fda4328a20b07d8fd667654ca18c54e32a333a0845451e926ee88",
            "04fd7af0aaa7a641045516ea3e54a0d5d8b2ce786b38d383370029a5dbe4459",
            "c9dd601b408a24ae6465c8ac905b9eb03b5d3691c139ef83f1cd4200f6c9c",
            "d4ec392218a59ed243d3c820ff724a9a70b88cb86f20b434c6865aa1cd79",
            "06dd7c9bce3525f508276f26836c",
        )),
        THREAD_SERVER_ID,
        true,
    )
    .unwrap();
    let client_two = RoundTwo::decode_tls_key_exchange(
        &hex_bytes(concat!(
            "410469d54ee85e90ce3f1246742de507e939e81d1dc1c5cb988b58c310c9fd",
            "d9524d93720b45541c83ee8841191da7ced86e3312d43623c1d63e74989aba",
            "4affd1ee4104077e8c31e20e6bedb760c13593e69f15be85c27d68cd09ccb8",
            "c4183608917c5c3d409fac39fefee82f7292d36f0d23e055913f45a52b85dd",
            "8a2052e9e129bb4d200f011f19483535a6e89a580c9b0003baf21462ece9",
            "1a82cc38dbdcae60d9c54c",
        )),
        THREAD_CLIENT_ID,
        false,
    )
    .unwrap();
    let expected_pms =
        hex_scalar("f3d47f599844db92a569bbe7981e39d931fd743bf22e98f9b438f719d3c4f351");
    let generated_client_two = client
        .round_two(&client_one, &server_one, &mut OsRng)
        .unwrap();
    let generated_server_two = server
        .round_two(&server_one, &client_one, &mut OsRng)
        .unwrap();

    assert_eq!(generated_client_two.point, client_two.point);
    assert_eq!(generated_server_two.point, server_two.point);

    assert_eq!(
        client
            .finish(&client_one, &server_one, &server_two)
            .unwrap(),
        expected_pms
    );
    assert_eq!(
        server
            .finish(&server_one, &client_one, &client_two)
            .unwrap(),
        expected_pms
    );
}
