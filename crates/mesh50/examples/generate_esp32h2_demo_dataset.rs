//! Generates the canned Active Operational Dataset used by the ESP32-H2 demo.

use mesh50::dataset::{
    Channel, Dataset, SecurityPolicy, SecurityPolicyFlags, TLV_ACTIVE_TIMESTAMP, TLV_CHANNEL,
    TLV_EXTENDED_PAN_ID, TLV_MESH_LOCAL_PREFIX, TLV_NETWORK_KEY, TLV_NETWORK_NAME, TLV_PAN_ID,
    TLV_PSKC, TLV_SECURITY_POLICY, Timestamp,
};

const CHANNEL: u16 = 15;
const PAN_ID: u16 = 0xd71d;
const EXTENDED_PAN_ID: [u8; 8] = [0x02, 0x24, 0x07, 0x23, 0xd7, 0x15, 0xa1, 0x0c];
const MESH_LOCAL_PREFIX: [u8; 8] = [0xfd, 0x24, 0x07, 0x23, 0xd7, 0x15, 0x00, 0x00];
const NETWORK_KEY: [u8; 16] = [
    0x5a, 0xc1, 0x7e, 0x39, 0x42, 0xb8, 0x6d, 0xf0, 0x11, 0x93, 0xce, 0x24, 0x78, 0xa5, 0x0b, 0xd6,
];
const PSKC: [u8; 16] = [
    0xd3, 0x19, 0x64, 0xaa, 0x08, 0xf2, 0x5c, 0x71, 0xbe, 0x43, 0x97, 0x10, 0xe6, 0x2d, 0x8b, 0x55,
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut dataset = Dataset::default();
    dataset.set_raw(
        TLV_ACTIVE_TIMESTAMP,
        Timestamp::from_components(1, 0, true).to_value(),
    );
    dataset.set_raw(
        TLV_CHANNEL,
        Channel {
            page: 0,
            channel: CHANNEL,
        }
        .to_value(),
    );
    dataset.set_raw(TLV_PAN_ID, PAN_ID.to_be_bytes());
    dataset.set_raw(TLV_EXTENDED_PAN_ID, EXTENDED_PAN_ID);
    dataset.set_raw(TLV_NETWORK_NAME, b"mesh50-dtls-demo".to_vec());
    dataset.set_raw(TLV_PSKC, PSKC);
    dataset.set_raw(TLV_NETWORK_KEY, NETWORK_KEY);
    dataset.set_raw(TLV_MESH_LOCAL_PREFIX, MESH_LOCAL_PREFIX);
    dataset.set_raw(
        TLV_SECURITY_POLICY,
        SecurityPolicy {
            rotation_time: 672,
            flags: SecurityPolicyFlags::from_bits_retain(0xf7f8),
        }
        .to_value(),
    );

    println!("{}", dataset.to_hex()?);
    Ok(())
}
