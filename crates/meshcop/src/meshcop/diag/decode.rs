//! Decoders for network-diagnostic (TMF) TLV payloads.
//!
//! Parsing follows the Thread 1.4 specification (§4.4 MLE TLVs, §5.18 Thread
//! Network Data, §10.11.4 network diagnostic TLVs) and OpenThread's wire
//! behavior where the C++ reference diverges. Every decoder length-checks its
//! input before indexing so malformed wire data yields an [`Error`] rather than
//! a panic.

use std::net::Ipv6Addr;

use crate::{Result, error::Error, tlv::TlvSet};

use super::model::{
    BorderRouterEntry, ChildIpv6AddrInfo, ChildTableEntry, Connectivity, HasRouteEntry, LeaderData,
    MacCounters, ModeData, NetDiagData, NetworkData, PrefixEntry, Route64, RouteDataEntry,
    SixLowPanContext,
};

/// Network-diagnostic TLV types (Thread 1.4 §10.11.4).
mod diag_tlv {
    pub const EXT_MAC_ADDRESS: u8 = 0;
    pub const MAC_ADDRESS: u8 = 1;
    pub const MODE: u8 = 2;
    pub const TIMEOUT: u8 = 3;
    pub const CONNECTIVITY: u8 = 4;
    pub const ROUTE64: u8 = 5;
    pub const LEADER_DATA: u8 = 6;
    pub const NETWORK_DATA: u8 = 7;
    pub const IPV6_ADDRESSES: u8 = 8;
    pub const MAC_COUNTERS: u8 = 9;
    pub const BATTERY_LEVEL: u8 = 14;
    pub const SUPPLY_VOLTAGE: u8 = 15;
    pub const CHILD_TABLE: u8 = 16;
    pub const CHANNEL_PAGES: u8 = 17;
    pub const TYPE_LIST: u8 = 18;
    pub const EUI64: u8 = 23;
    pub const CHILD_IPV6_ADDRESSES: u8 = 30;
}

impl ModeData {
    /// Decodes a one-byte MLE Mode value.
    pub fn decode(value: &[u8]) -> Result<Self> {
        let [mode] = value else {
            return Err(Error::Dataset(format!(
                "Mode value must be 1 byte, got {}",
                value.len()
            )));
        };
        Ok(Self {
            rx_on_when_idle: mode & 0x08 != 0,
            is_mtd: mode & 0x02 == 0,
            requires_full_network_data: mode & 0x01 != 0,
        })
    }
}

impl NetDiagData {
    /// Decodes a DIAG_GET.ans (or DIAG_GET.rsp) TLV payload.
    ///
    /// Unknown TLV types are ignored so newer diagnostic TLVs do not fail the
    /// decode of the fields this crate understands.
    pub fn decode(payload: &[u8]) -> Result<Self> {
        let tlvs = TlvSet::parse(payload)?;
        let mut out = Self::default();

        for entry in tlvs.entries() {
            let value = entry.value.as_slice();
            match entry.ty {
                diag_tlv::EXT_MAC_ADDRESS => out.ext_mac_addr = Some(value.to_vec()),
                diag_tlv::MAC_ADDRESS => out.mac_addr = Some(read_u16(value, "MAC Address")?),
                diag_tlv::MODE => out.mode = Some(ModeData::decode(value)?),
                diag_tlv::TIMEOUT => out.timeout = Some(read_u32(value, "Timeout")?),
                diag_tlv::CONNECTIVITY => out.connectivity = Some(decode_connectivity(value)?),
                diag_tlv::ROUTE64 => out.route64 = Some(decode_route64(value)?),
                diag_tlv::LEADER_DATA => out.leader_data = Some(decode_leader_data(value)?),
                diag_tlv::NETWORK_DATA => out.network_data = Some(NetworkData::decode(value)?),
                diag_tlv::IPV6_ADDRESSES => {
                    out.addresses = Some(decode_ipv6_address_list(value)?);
                }
                diag_tlv::MAC_COUNTERS => out.mac_counters = Some(decode_mac_counters(value)?),
                diag_tlv::BATTERY_LEVEL => {
                    out.battery_level = Some(read_u8(value, "Battery Level")?);
                }
                diag_tlv::SUPPLY_VOLTAGE => {
                    out.supply_voltage = Some(read_u16(value, "Supply Voltage")?);
                }
                diag_tlv::CHILD_TABLE => out.child_table = Some(decode_child_table(value)?),
                diag_tlv::CHANNEL_PAGES => out.channel_pages = Some(value.to_vec()),
                diag_tlv::TYPE_LIST => out.type_list = Some(value.to_vec()),
                diag_tlv::EUI64 => {
                    out.eui64 = Some(value.try_into().map_err(|_| {
                        Error::Dataset(format!("EUI-64 must be 8 bytes, got {}", value.len()))
                    })?);
                }
                diag_tlv::CHILD_IPV6_ADDRESSES => {
                    out.child_ipv6_addresses
                        .get_or_insert_with(Vec::new)
                        .push(decode_child_ipv6_addresses(value)?);
                }
                _ => {}
            }
        }
        Ok(out)
    }
}

impl NetworkData {
    /// Decodes a Thread Network Data TLV value into prefix entries.
    ///
    /// Network-data sub-TLVs carry the type in the upper seven bits of the
    /// first byte with the stable flag in the least-significant bit.
    pub fn decode(value: &[u8]) -> Result<Self> {
        const NETWORK_DATA_PREFIX: u8 = 1;

        let mut prefixes = Vec::new();
        for (ty, value) in NetworkDataTlvIter::new(value) {
            if ty? == NETWORK_DATA_PREFIX {
                prefixes.push(decode_prefix_entry(value)?);
            }
        }
        Ok(Self { prefixes })
    }
}

/// Iterator over network-data scoped TLVs yielding `(type, value)` pairs.
struct NetworkDataTlvIter<'a> {
    bytes: &'a [u8],
}

impl<'a> NetworkDataTlvIter<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

impl<'a> Iterator for NetworkDataTlvIter<'a> {
    type Item = (Result<u8>, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.bytes.is_empty() {
            return None;
        }
        if self.bytes.len() < 2 {
            self.bytes = &[];
            return Some((
                Err(Error::Dataset(
                    "network data TLV header is truncated".to_string(),
                )),
                &[],
            ));
        }
        let ty = self.bytes[0] >> 1;
        let len = self.bytes[1] as usize;
        // Consume the header and value as shrinking slices rather than with
        // index arithmetic: every TLV provably strips its two header bytes,
        // so malformed lengths can only error, never stall the iterator.
        let after_header = &self.bytes[2..];
        if after_header.len() < len {
            self.bytes = &[];
            return Some((
                Err(Error::Dataset(
                    "network data TLV value is truncated".to_string(),
                )),
                &[],
            ));
        }
        let value = &after_header[..len];
        self.bytes = &after_header[len..];
        Some((Ok(ty), value))
    }
}

fn decode_prefix_entry(value: &[u8]) -> Result<PrefixEntry> {
    const NETWORK_DATA_HAS_ROUTE: u8 = 0;
    const NETWORK_DATA_BORDER_ROUTER: u8 = 2;
    const NETWORK_DATA_6LOWPAN_CONTEXT: u8 = 3;

    if value.len() < 2 {
        return Err(Error::Dataset("Prefix entry is truncated".to_string()));
    }
    let domain_id = value[0];
    let prefix_bit_length = value[1];
    let prefix_len = (prefix_bit_length as usize).div_ceil(8);
    let sub_tlv_offset = 2 + prefix_len;
    if value.len() < sub_tlv_offset {
        return Err(Error::Dataset("Prefix bytes are truncated".to_string()));
    }

    let mut entry = PrefixEntry {
        domain_id,
        prefix_bit_length,
        prefix: value[2..sub_tlv_offset].to_vec(),
        ..PrefixEntry::default()
    };

    for (ty, value) in NetworkDataTlvIter::new(&value[sub_tlv_offset..]) {
        match ty? {
            NETWORK_DATA_HAS_ROUTE => entry.has_route.extend(decode_has_route(value)?),
            NETWORK_DATA_BORDER_ROUTER => {
                entry.border_routers.extend(decode_border_router(value)?);
            }
            NETWORK_DATA_6LOWPAN_CONTEXT => {
                entry.six_low_pan_context = Some(decode_six_low_pan_context(value)?);
            }
            _ => {}
        }
    }
    Ok(entry)
}

fn decode_has_route(value: &[u8]) -> Result<Vec<HasRouteEntry>> {
    const HAS_ROUTE_ENTRY_LEN: usize = 3;

    if value.len() % HAS_ROUTE_ENTRY_LEN != 0 {
        return Err(Error::Dataset(format!(
            "HasRoute length {} is not a multiple of {HAS_ROUTE_ENTRY_LEN}",
            value.len()
        )));
    }
    Ok(value
        .chunks_exact(HAS_ROUTE_ENTRY_LEN)
        .map(|chunk| HasRouteEntry {
            rloc16: u16::from_be_bytes([chunk[0], chunk[1]]),
            router_preference: (chunk[2] >> 6) & 0x03,
            is_nat64: (chunk[2] >> 5) & 0x01 != 0,
        })
        .collect())
}

fn decode_border_router(value: &[u8]) -> Result<Vec<BorderRouterEntry>> {
    const BORDER_ROUTER_ENTRY_LEN: usize = 4;

    if value.len() % BORDER_ROUTER_ENTRY_LEN != 0 {
        return Err(Error::Dataset(format!(
            "BorderRouter length {} is not a multiple of {BORDER_ROUTER_ENTRY_LEN}",
            value.len()
        )));
    }
    Ok(value
        .chunks_exact(BORDER_ROUTER_ENTRY_LEN)
        .map(|chunk| BorderRouterEntry {
            rloc16: u16::from_be_bytes([chunk[0], chunk[1]]),
            prefix_preference: (chunk[2] >> 6) & 0x03,
            is_preferred: (chunk[2] >> 5) & 0x01 != 0,
            is_slaac: (chunk[2] >> 4) & 0x01 != 0,
            is_dhcp: (chunk[2] >> 3) & 0x01 != 0,
            is_configure: (chunk[2] >> 2) & 0x01 != 0,
            is_default_route: (chunk[2] >> 1) & 0x01 != 0,
            is_on_mesh: chunk[2] & 0x01 != 0,
            is_nd_dns: (chunk[3] >> 7) & 0x01 != 0,
            is_dp: (chunk[3] >> 6) & 0x01 != 0,
        })
        .collect())
}

fn decode_six_low_pan_context(value: &[u8]) -> Result<SixLowPanContext> {
    let [flags, context_length] = value else {
        return Err(Error::Dataset(format!(
            "6LoWPAN context must be 2 bytes, got {}",
            value.len()
        )));
    };
    Ok(SixLowPanContext {
        is_compress: (flags >> 4) & 0x01 != 0,
        context_id: flags & 0x0f,
        context_length: *context_length,
    })
}

fn decode_connectivity(value: &[u8]) -> Result<Connectivity> {
    if value.len() < 7 {
        return Err(Error::Dataset(format!(
            "Connectivity must be at least 7 bytes, got {}",
            value.len()
        )));
    }
    // Parent priority is the 2-bit signed field in the most significant bits
    // of the first byte: 01 high, 00 medium, 11 low, 10 reserved.
    let parent_priority = match value[0] >> 6 {
        0b01 => 1,
        0b00 => 0,
        0b11 => -1,
        _ => -2,
    };
    let mut out = Connectivity {
        parent_priority,
        link_quality_3: value[1],
        link_quality_2: value[2],
        link_quality_1: value[3],
        leader_cost: value[4],
        id_sequence: value[5],
        active_routers: value[6],
        rx_off_child_buffer_size: None,
        rx_off_child_datagram_count: None,
    };
    if value.len() >= 10 {
        out.rx_off_child_buffer_size = Some(u16::from_be_bytes([value[7], value[8]]));
        out.rx_off_child_datagram_count = Some(value[9]);
    }
    Ok(out)
}

fn decode_route64(value: &[u8]) -> Result<Route64> {
    const ROUTER_ID_MASK_LEN: usize = 8;

    if value.len() < ROUTER_ID_MASK_LEN + 1 {
        return Err(Error::Dataset(format!(
            "Route64 must be at least {} bytes, got {}",
            ROUTER_ID_MASK_LEN + 1,
            value.len()
        )));
    }
    let id_sequence = value[0];
    // The length check above guarantees these bytes are present.
    let mut mask = [0u8; ROUTER_ID_MASK_LEN];
    mask.copy_from_slice(&value[1..1 + ROUTER_ID_MASK_LEN]);
    let router_ids: Vec<u8> = (0..ROUTER_ID_MASK_LEN * 8)
        .filter(|bit| mask[bit / 8] & (0x80 >> (bit % 8)) != 0)
        .map(|bit| bit as u8)
        .collect();

    let route_bytes = &value[1 + ROUTER_ID_MASK_LEN..];
    if route_bytes.len() != router_ids.len() {
        return Err(Error::Dataset(format!(
            "Route64 route data has {} entries but the mask assigns {} router IDs",
            route_bytes.len(),
            router_ids.len()
        )));
    }
    let route_data = router_ids
        .into_iter()
        .zip(route_bytes)
        .map(|(router_id, byte)| RouteDataEntry {
            router_id,
            outgoing_link_quality: (byte >> 6) & 0x03,
            incoming_link_quality: (byte >> 4) & 0x03,
            route_cost: byte & 0x0f,
        })
        .collect();
    Ok(Route64 {
        id_sequence,
        mask,
        route_data,
    })
}

fn decode_leader_data(value: &[u8]) -> Result<LeaderData> {
    if value.len() != 8 {
        return Err(Error::Dataset(format!(
            "Leader Data must be 8 bytes, got {}",
            value.len()
        )));
    }
    Ok(LeaderData {
        partition_id: u32::from_be_bytes([value[0], value[1], value[2], value[3]]),
        weighting: value[4],
        data_version: value[5],
        stable_data_version: value[6],
        router_id: value[7],
    })
}

fn decode_ipv6_address_list(value: &[u8]) -> Result<Vec<Ipv6Addr>> {
    if value.len() % 16 != 0 {
        return Err(Error::Dataset(format!(
            "IPv6 address list length {} is not a multiple of 16",
            value.len()
        )));
    }
    Ok(value
        .chunks_exact(16)
        .map(|chunk| {
            // `chunks_exact(16)` yields exactly 16 bytes.
            let mut octets = [0u8; 16];
            octets.copy_from_slice(chunk);
            Ipv6Addr::from(octets)
        })
        .collect())
}

fn decode_mac_counters(value: &[u8]) -> Result<MacCounters> {
    if value.len() != 36 {
        return Err(Error::Dataset(format!(
            "MAC Counters must be 36 bytes, got {}",
            value.len()
        )));
    }
    // The 36-byte length check above guarantees each 4-byte window is present.
    let counter = |idx: usize| {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&value[idx..idx + 4]);
        u32::from_be_bytes(buf)
    };
    Ok(MacCounters {
        if_in_unknown_protos: counter(0),
        if_in_errors: counter(4),
        if_out_errors: counter(8),
        if_in_ucast_pkts: counter(12),
        if_in_broadcast_pkts: counter(16),
        if_in_discards: counter(20),
        if_out_ucast_pkts: counter(24),
        if_out_broadcast_pkts: counter(28),
        if_out_discards: counter(32),
    })
}

fn decode_child_table(value: &[u8]) -> Result<Vec<ChildTableEntry>> {
    const CHILD_ENTRY_LEN: usize = 3;

    if value.len() % CHILD_ENTRY_LEN != 0 {
        return Err(Error::Dataset(format!(
            "Child Table length {} is not a multiple of {CHILD_ENTRY_LEN}",
            value.len()
        )));
    }
    value
        .chunks_exact(CHILD_ENTRY_LEN)
        .map(|chunk| {
            Ok(ChildTableEntry {
                timeout_exponent: chunk[0] >> 3,
                incoming_link_quality: (chunk[0] >> 1) & 0x03,
                // The Child ID is 9 bits: the least-significant bit of the
                // first byte is the high bit of the ID.
                child_id: u16::from(chunk[0] & 0x01) << 8 | u16::from(chunk[1]),
                mode: ModeData::decode(&chunk[2..3])?,
            })
        })
        .collect()
}

fn decode_child_ipv6_addresses(value: &[u8]) -> Result<ChildIpv6AddrInfo> {
    if value.len() < 2 || (value.len() - 2) % 16 != 0 {
        return Err(Error::Dataset(
            "Child IPv6 Address List must be an RLOC16 followed by whole addresses".to_string(),
        ));
    }
    let rloc16 = u16::from_be_bytes([value[0], value[1]]);
    Ok(ChildIpv6AddrInfo {
        rloc16,
        child_id: rloc16 & 0x01ff,
        addresses: decode_ipv6_address_list(&value[2..])?,
    })
}

fn read_u8(value: &[u8], name: &str) -> Result<u8> {
    let [byte] = value else {
        return Err(Error::Dataset(format!(
            "{name} must be 1 byte, got {}",
            value.len()
        )));
    };
    Ok(*byte)
}

fn read_u16(value: &[u8], name: &str) -> Result<u16> {
    crate::wire::read_u16(value)
        .ok_or_else(|| Error::Dataset(format!("{name} must be 2 bytes, got {}", value.len())))
}

fn read_u32(value: &[u8], name: &str) -> Result<u32> {
    crate::wire::read_u32(value)
        .ok_or_else(|| Error::Dataset(format!("{name} must be 4 bytes, got {}", value.len())))
}
