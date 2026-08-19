//! Typed network-diagnostic data model.
//!
//! These structs mirror the `NetDiagData` surface of the C++ `ot-commissioner`
//! reference (`include/commissioner/network_diag_data.hpp`). Bit layouts follow
//! the Thread 1.4 specification (§4.4.2 Mode TLV, §4.4.7 Connectivity TLV,
//! §10.11.4 network diagnostic TLVs). Decoding lives in [`super::decode`].

use std::net::Ipv6Addr;

/// MLE Mode TLV bits (Thread 1.4 §4.4.2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ModeData {
    /// R bit: the device keeps its receiver on when idle.
    pub rx_on_when_idle: bool,
    /// Negated D bit: the device is a Minimal Thread Device.
    pub is_mtd: bool,
    /// N bit: the device requires full Network Data.
    pub requires_full_network_data: bool,
}

/// One Child Entry of a Child Table TLV (Thread 1.4 §10.11.4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChildTableEntry {
    /// 5-bit timeout exponent; the poll period is `2^(exponent - 4)` seconds.
    pub timeout_exponent: u8,
    /// Incoming link quality (0 when unknown).
    pub incoming_link_quality: u8,
    /// 9-bit Child ID.
    pub child_id: u16,
    /// Child MLE mode.
    pub mode: ModeData,
}

impl ChildTableEntry {
    /// Returns the child timeout in whole seconds (zero for sub-second values).
    pub const fn timeout_seconds(&self) -> u32 {
        if self.timeout_exponent < 4 {
            0
        } else {
            1 << (self.timeout_exponent - 4)
        }
    }
}

/// Leader Data TLV value (Thread 1.4 §4.4.12).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LeaderData {
    /// Partition ID.
    pub partition_id: u32,
    /// Leader weighting.
    pub weighting: u8,
    /// Network Data version.
    pub data_version: u8,
    /// Stable Network Data version.
    pub stable_data_version: u8,
    /// Leader Router ID.
    pub router_id: u8,
}

/// One assigned-router entry of a Route64 TLV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteDataEntry {
    /// Router ID this entry describes.
    pub router_id: u8,
    /// Outgoing link quality.
    pub outgoing_link_quality: u8,
    /// Incoming link quality.
    pub incoming_link_quality: u8,
    /// Route cost.
    pub route_cost: u8,
}

/// Route64 TLV value (Thread 1.4 §4.4.10).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Route64 {
    /// Router ID sequence number.
    pub id_sequence: u8,
    /// 64-bit assigned Router ID mask.
    pub mask: [u8; 8],
    /// Route data for each assigned router ID, in mask order.
    pub route_data: Vec<RouteDataEntry>,
}

/// Child IPv6 Address List TLV value (Thread 1.4 §10.11.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildIpv6AddrInfo {
    /// RLOC16 of the child.
    pub rloc16: u16,
    /// 9-bit Child ID extracted from the RLOC16.
    pub child_id: u16,
    /// Registered IPv6 addresses.
    pub addresses: Vec<Ipv6Addr>,
}

/// MAC Counters TLV value (Thread 1.4 §10.11.4.1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MacCounters {
    /// ifInUnknownProtos counter.
    pub if_in_unknown_protos: u32,
    /// ifInErrors counter.
    pub if_in_errors: u32,
    /// ifOutErrors counter.
    pub if_out_errors: u32,
    /// ifInUcastPkts counter.
    pub if_in_ucast_pkts: u32,
    /// ifInBroadcastPkts counter.
    pub if_in_broadcast_pkts: u32,
    /// ifInDiscards counter.
    pub if_in_discards: u32,
    /// ifOutUcastPkts counter.
    pub if_out_ucast_pkts: u32,
    /// ifOutBroadcastPkts counter.
    pub if_out_broadcast_pkts: u32,
    /// ifOutDiscards counter.
    pub if_out_discards: u32,
}

/// Connectivity TLV value (Thread 1.4 §4.4.7).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Connectivity {
    /// Parent priority: 1 high, 0 medium, -1 low, -2 reserved.
    pub parent_priority: i8,
    /// Neighbor count with link quality 3.
    pub link_quality_3: u8,
    /// Neighbor count with link quality 2.
    pub link_quality_2: u8,
    /// Neighbor count with link quality 1.
    pub link_quality_1: u8,
    /// Routing cost to the leader.
    pub leader_cost: u8,
    /// Most recent ID sequence number.
    pub id_sequence: u8,
    /// Number of active routers.
    pub active_routers: u8,
    /// Optional rx-off child buffer size.
    pub rx_off_child_buffer_size: Option<u16>,
    /// Optional rx-off child datagram count.
    pub rx_off_child_datagram_count: Option<u8>,
}

/// One HasRoute entry of a Prefix TLV (Thread 1.4 §5.18.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HasRouteEntry {
    /// RLOC16 of the route server.
    pub rloc16: u16,
    /// Router preference.
    pub router_preference: u8,
    /// NAT64 prefix flag.
    pub is_nat64: bool,
}

/// One BorderRouter entry of a Prefix TLV (Thread 1.4 §5.18.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BorderRouterEntry {
    /// RLOC16 of the border router.
    pub rloc16: u16,
    /// Prefix preference.
    pub prefix_preference: u8,
    /// P (preferred) flag.
    pub is_preferred: bool,
    /// S (SLAAC) flag.
    pub is_slaac: bool,
    /// D (DHCP) flag.
    pub is_dhcp: bool,
    /// C (configure) flag.
    pub is_configure: bool,
    /// R (default route) flag.
    pub is_default_route: bool,
    /// O (on-mesh) flag.
    pub is_on_mesh: bool,
    /// N (ND DNS) flag.
    pub is_nd_dns: bool,
    /// DP (domain prefix) flag.
    pub is_dp: bool,
}

/// 6LoWPAN ID sub-TLV of a Prefix TLV (Thread 1.4 §5.18.2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SixLowPanContext {
    /// C (compression) flag.
    pub is_compress: bool,
    /// Context ID.
    pub context_id: u8,
    /// Context length in bits.
    pub context_length: u8,
}

/// One Prefix TLV of Thread Network Data (Thread 1.4 §5.18).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PrefixEntry {
    /// Domain ID.
    pub domain_id: u8,
    /// Prefix length in bits.
    pub prefix_bit_length: u8,
    /// Prefix bytes (`(prefix_bit_length + 7) / 8` bytes).
    pub prefix: Vec<u8>,
    /// 6LoWPAN context, when present.
    pub six_low_pan_context: Option<SixLowPanContext>,
    /// HasRoute entries.
    pub has_route: Vec<HasRouteEntry>,
    /// BorderRouter entries.
    pub border_routers: Vec<BorderRouterEntry>,
}

/// Thread Network Data TLV value (Thread 1.4 §5.18).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkData {
    /// Prefix entries.
    pub prefixes: Vec<PrefixEntry>,
}

/// Decoded network diagnostic answer data.
///
/// Every field is optional; a field is `Some` only when the corresponding TLV
/// appeared in the DIAG_GET.ans payload. Decode a payload with
/// [`NetDiagData::decode`](super::NetDiagData::decode).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetDiagData {
    /// Extended MAC Address TLV (0).
    pub ext_mac_addr: Option<Vec<u8>>,
    /// MAC Address (RLOC16) TLV (1).
    pub mac_addr: Option<u16>,
    /// Mode TLV (2).
    pub mode: Option<ModeData>,
    /// Timeout TLV (3) in seconds.
    pub timeout: Option<u32>,
    /// Connectivity TLV (4).
    pub connectivity: Option<Connectivity>,
    /// Route64 TLV (5).
    pub route64: Option<Route64>,
    /// Leader Data TLV (6).
    pub leader_data: Option<LeaderData>,
    /// Network Data TLV (7).
    pub network_data: Option<NetworkData>,
    /// IPv6 Address List TLV (8).
    pub addresses: Option<Vec<Ipv6Addr>>,
    /// MAC Counters TLV (9).
    pub mac_counters: Option<MacCounters>,
    /// Battery Level TLV (14) in percent.
    pub battery_level: Option<u8>,
    /// Supply Voltage TLV (15) in millivolts.
    pub supply_voltage: Option<u16>,
    /// Child Table TLV (16).
    pub child_table: Option<Vec<ChildTableEntry>>,
    /// Channel Pages TLV (17).
    pub channel_pages: Option<Vec<u8>>,
    /// Type List TLV (18).
    pub type_list: Option<Vec<u8>>,
    /// EUI-64 TLV (23).
    pub eui64: Option<[u8; 8]>,
    /// Child IPv6 Address List TLVs (30), one entry per child.
    pub child_ipv6_addresses: Option<Vec<ChildIpv6AddrInfo>>,
}
