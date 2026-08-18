//! Dataset and diagnostic flag mapping helpers.

use super::constants::*;

/// Converts dataset flags to active dataset TLV types.
pub fn active_dataset_tlv_types(flags: u64) -> Vec<u8> {
    dataset_tlv_types(flags, false)
}

/// Converts dataset flags to pending dataset TLV types.
pub fn pending_dataset_tlv_types(flags: u64) -> Vec<u8> {
    dataset_tlv_types(flags, true)
}

/// Converts commissioner dataset flags to TLV types.
pub fn commissioner_dataset_tlv_types(flags: u64) -> Vec<u8> {
    const TYPES: &[(u64, u8)] = &[
        (1 << 15, TLV_BORDER_AGENT_LOCATOR),
        (1 << 14, TLV_COMMISSIONER_SESSION_ID),
        (1 << 13, TLV_STEERING_DATA),
        (1 << 12, TLV_AE_STEERING_DATA),
        (1 << 11, TLV_NMKP_STEERING_DATA),
        (1 << 10, TLV_JOINER_UDP_PORT),
        (1 << 9, TLV_AE_UDP_PORT),
        (1 << 8, TLV_NMKP_UDP_PORT),
    ];
    flag_types(flags, TYPES)
}

/// Converts diagnostic flags to network-diagnostic TLV types.
pub fn network_diag_tlv_types(flags: u64) -> Vec<u8> {
    const TYPES: &[(u64, u8)] = &[
        (1 << 0, 0),
        (1 << 1, 1),
        (1 << 2, 2),
        (1 << 3, 5),
        (1 << 4, 6),
        (1 << 5, 8),
        (1 << 8, 9),
        (1 << 6, 16),
        (1 << 7, 23),
        (1 << 9, 30),
        (1 << 10, 7),
        (1 << 11, 3),
        (1 << 12, 4),
        (1 << 13, 14),
        (1 << 14, 15),
        (1 << 15, 17),
        (1 << 16, 18),
    ];
    flag_types(flags, TYPES)
}

fn dataset_tlv_types(flags: u64, pending: bool) -> Vec<u8> {
    const ACTIVE_TYPES: &[(u64, u8)] = &[
        (1 << 15, crate::dataset::TLV_ACTIVE_TIMESTAMP),
        (1 << 14, crate::dataset::TLV_CHANNEL),
        (1 << 13, crate::dataset::TLV_CHANNEL_MASK),
        (1 << 12, crate::dataset::TLV_EXTENDED_PAN_ID),
        (1 << 11, crate::dataset::TLV_MESH_LOCAL_PREFIX),
        (1 << 10, crate::dataset::TLV_NETWORK_KEY),
        (1 << 9, crate::dataset::TLV_NETWORK_NAME),
        (1 << 8, crate::dataset::TLV_PAN_ID),
        (1 << 7, crate::dataset::TLV_PSKC),
        (1 << 6, crate::dataset::TLV_SECURITY_POLICY),
    ];
    const PENDING_TYPES: &[(u64, u8)] = &[
        (1 << 5, crate::dataset::TLV_DELAY_TIMER),
        (1 << 4, crate::dataset::TLV_PENDING_TIMESTAMP),
    ];

    let mut types = flag_types(flags, ACTIVE_TYPES);
    if pending {
        types.extend(flag_types(flags, PENDING_TYPES));
    }
    types
}

fn flag_types(flags: u64, mappings: &[(u64, u8)]) -> Vec<u8> {
    mappings
        .iter()
        .filter_map(|(bit, ty)| if flags & bit != 0 { Some(*ty) } else { None })
        .collect()
}
