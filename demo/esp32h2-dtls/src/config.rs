//! Canned Thread dataset and application addressing for the desk demo.

#[cfg(feature = "role-client")]
use core::net::{Ipv6Addr, SocketAddrV6};

const TLV_PSKC: u8 = 0x04;
#[cfg(feature = "role-client")]
const TLV_MESH_LOCAL_PREFIX: u8 = 0x07;

/// UDP port used by the DTLS server and client.
pub(crate) const DEMO_PORT: u16 = 49_191;

/// Demo-only Active Operational Dataset, encoded as Thread TLVs.
///
/// Generated with:
/// `cargo run -p meshcop --example generate_esp32h2_demo_dataset`
///
/// The dataset includes the network name `meshcop-dtls-demo`, channel 15,
/// PAN ID `0xd71d`, an extended PAN ID, mesh-local prefix, Network Key, PSKc,
/// Active Timestamp, and Security Policy. Its keys are public demo credentials.
pub(crate) const ACTIVE_DATASET_TLV_HEX: &str = concat!(
    "0e080000000000010001",
    "000300000f",
    "0102d71d",
    "020802240723d715a10c",
    "03107468726561642d64746c732d64656d6f",
    "0410d31964aa08f25c71be439710e62d8b55",
    "05105ac17e3942b86df01193ce2478a50bd6",
    "0708fd240723d7150000",
    "0c0402a0f7f8",
);

/// Returns the PSKc encoded in [`ACTIVE_DATASET_TLV_HEX`].
pub(crate) const fn dataset_pskc() -> [u8; 16] {
    dataset_tlv_value::<16>(TLV_PSKC)
}

/// Returns the deterministic Leader Anycast Locator and demo UDP port.
#[cfg(feature = "role-client")]
pub(crate) fn leader_aloc() -> SocketAddrV6 {
    let prefix = dataset_tlv_value::<8>(TLV_MESH_LOCAL_PREFIX);
    let mut octets = [0; 16];
    let mut index = 0;
    while index < prefix.len() {
        octets[index] = prefix[index];
        index += 1;
    }
    octets[8..].copy_from_slice(&[0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0xfc, 0x00]);

    SocketAddrV6::new(Ipv6Addr::from(octets), DEMO_PORT, 0, 0)
}

const fn dataset_tlv_value<const N: usize>(wanted_type: u8) -> [u8; N] {
    let hex = ACTIVE_DATASET_TLV_HEX.as_bytes();
    let mut cursor = 0;

    while cursor + 4 <= hex.len() {
        let tlv_type = hex_byte(hex, cursor);
        let length = hex_byte(hex, cursor + 2) as usize;
        let value_start = cursor + 4;

        if tlv_type == wanted_type {
            assert!(length == N, "unexpected demo dataset TLV length");
            assert!(
                value_start + (length * 2) <= hex.len(),
                "truncated demo dataset TLV"
            );

            let mut value = [0; N];
            let mut index = 0;
            while index < N {
                value[index] = hex_byte(hex, value_start + (index * 2));
                index += 1;
            }
            return value;
        }

        cursor = value_start + (length * 2);
    }

    panic!("required demo dataset TLV is missing")
}

const fn hex_byte(hex: &[u8], offset: usize) -> u8 {
    (hex_nibble(hex[offset]) << 4) | hex_nibble(hex[offset + 1])
}

const fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid hex in demo dataset"),
    }
}
