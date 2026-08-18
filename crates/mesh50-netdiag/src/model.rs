//! Serializable network-topology model built from MeshCoP diagnostic answers.

use std::net::Ipv6Addr;

use mesh50::meshcop::diag::{
    ChildTableEntry, Connectivity, LeaderData, MacCounters, ModeData, NetDiagData, NetworkData,
};
use serde::Serialize;

/// Placeholder substituted for sensitive fields unless `--show-secrets` is set.
pub const REDACTED: &str = "<redacted>";

/// Complete picture of one Thread network at collection time.
#[derive(Debug, Serialize)]
pub struct TopologySnapshot {
    pub generated_unix_time: u64,
    pub border_agent: String,
    pub network: NetworkInfo,
    pub nodes: Vec<Node>,
    pub links: Vec<Link>,
}

impl TopologySnapshot {
    /// Replaces sensitive network identifiers (extended PAN ID, mesh-local
    /// prefix, per-node IPv6 addresses) with [`REDACTED`]. These match the
    /// dataset fields the other examples redact by default; call this unless
    /// the user opted into `--show-secrets`.
    pub fn redact_secrets(&mut self) {
        if self.network.extended_pan_id.is_some() {
            self.network.extended_pan_id = Some(REDACTED.to_string());
        }
        if self.network.mesh_local_prefix.is_some() {
            self.network.mesh_local_prefix = Some(REDACTED.to_string());
        }
        for node in &mut self.nodes {
            node.redact_secrets();
        }
    }
}

/// Network-wide facts from the active dataset and the leader's answer.
#[derive(Debug, Default, Serialize)]
pub struct NetworkInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pan_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extended_pan_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_page: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mesh_local_prefix: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leader_rloc16: Option<String>,
}

/// How a node's information was obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Discovery {
    /// The node answered a DIAG_GET.req addressed to it.
    DirectQuery,
    /// The node was synthesized from its parent's child table.
    ParentTable,
    /// The node is in the leader's router table but did not answer.
    Unreachable,
}

/// MLE role of a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Leader,
    Router,
    Child,
}

/// MLE mode bits.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct ModeInfo {
    pub rx_on_when_idle: bool,
    /// `ftd` (Full Thread Device) or `mtd` (Minimal Thread Device).
    pub device_type: &'static str,
    pub full_network_data: bool,
}

impl ModeInfo {
    pub fn from_mode(mode: &ModeData) -> Self {
        Self {
            rx_on_when_idle: mode.rx_on_when_idle,
            device_type: if mode.is_mtd { "mtd" } else { "ftd" },
            full_network_data: mode.requires_full_network_data,
        }
    }
}

/// Connectivity TLV details.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct ConnectivityInfo {
    pub parent_priority: i8,
    pub link_quality_3_neighbors: u8,
    pub link_quality_2_neighbors: u8,
    pub link_quality_1_neighbors: u8,
    pub leader_cost: u8,
    pub id_sequence: u8,
    pub active_routers: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_off_child_buffer_size: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_off_child_datagram_count: Option<u8>,
}

impl ConnectivityInfo {
    fn from_connectivity(value: &Connectivity) -> Self {
        Self {
            parent_priority: value.parent_priority,
            link_quality_3_neighbors: value.link_quality_3,
            link_quality_2_neighbors: value.link_quality_2,
            link_quality_1_neighbors: value.link_quality_1,
            leader_cost: value.leader_cost,
            id_sequence: value.id_sequence,
            active_routers: value.active_routers,
            rx_off_child_buffer_size: value.rx_off_child_buffer_size,
            rx_off_child_datagram_count: value.rx_off_child_datagram_count,
        }
    }
}

/// Leader Data TLV details.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct LeaderDataInfo {
    pub partition_id: u32,
    pub weighting: u8,
    pub data_version: u8,
    pub stable_data_version: u8,
    pub leader_router_id: u8,
}

impl LeaderDataInfo {
    fn from_leader_data(value: &LeaderData) -> Self {
        Self {
            partition_id: value.partition_id,
            weighting: value.weighting,
            data_version: value.data_version,
            stable_data_version: value.stable_data_version,
            leader_router_id: value.router_id,
        }
    }
}

/// One Route64 entry as seen by the reporting router.
#[derive(Debug, Clone, Serialize)]
pub struct RouteEntryInfo {
    pub router_id: u8,
    pub rloc16: String,
    /// `self`, `neighbor` (direct radio link), or `multihop`.
    pub relation: &'static str,
    pub link_quality_in: u8,
    pub link_quality_out: u8,
    pub route_cost: u8,
}

/// One child-table entry as recorded by the parent.
#[derive(Debug, Clone, Serialize)]
pub struct ChildEntryInfo {
    pub rloc16: String,
    pub child_id: u16,
    pub timeout_seconds: u32,
    pub incoming_link_quality: u8,
    pub mode: ModeInfo,
}

/// MAC counters TLV details.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct MacCountersInfo {
    pub if_in_unknown_protos: u32,
    pub if_in_errors: u32,
    pub if_out_errors: u32,
    pub if_in_ucast_pkts: u32,
    pub if_in_broadcast_pkts: u32,
    pub if_in_discards: u32,
    pub if_out_ucast_pkts: u32,
    pub if_out_broadcast_pkts: u32,
    pub if_out_discards: u32,
}

impl MacCountersInfo {
    fn from_counters(value: &MacCounters) -> Self {
        Self {
            if_in_unknown_protos: value.if_in_unknown_protos,
            if_in_errors: value.if_in_errors,
            if_out_errors: value.if_out_errors,
            if_in_ucast_pkts: value.if_in_ucast_pkts,
            if_in_broadcast_pkts: value.if_in_broadcast_pkts,
            if_in_discards: value.if_in_discards,
            if_out_ucast_pkts: value.if_out_ucast_pkts,
            if_out_broadcast_pkts: value.if_out_broadcast_pkts,
            if_out_discards: value.if_out_discards,
        }
    }
}

/// One Thread Network Data prefix.
#[derive(Debug, Clone, Serialize)]
pub struct PrefixInfo {
    pub prefix: String,
    pub domain_id: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub six_lowpan_context_id: Option<u8>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub has_route: Vec<HasRouteInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub border_routers: Vec<BorderRouterInfo>,
}

/// One HasRoute entry of a prefix.
#[derive(Debug, Clone, Serialize)]
pub struct HasRouteInfo {
    pub rloc16: String,
    pub preference: u8,
    pub nat64: bool,
}

/// One BorderRouter entry of a prefix.
#[derive(Debug, Clone, Serialize)]
pub struct BorderRouterInfo {
    pub rloc16: String,
    pub preference: u8,
    pub flags: String,
}

/// Everything known about one device.
#[derive(Debug, Serialize)]
pub struct Node {
    pub rloc16: String,
    pub router_id: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub child_id: Option<u16>,
    pub role: Role,
    pub discovery: Discovery,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_rloc16: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ext_mac_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eui64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<ModeInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ipv6_addresses: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connectivity: Option<ConnectivityInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leader_data: Option<LeaderDataInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub route_table: Vec<RouteEntryInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub child_table: Vec<ChildEntryInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_counters: Option<MacCountersInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub battery_level_percent: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supply_voltage_mv: Option<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub network_data_prefixes: Vec<PrefixInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_pages: Option<Vec<u8>>,
}

impl Node {
    /// Creates a placeholder for a router that did not answer.
    pub fn unreachable(rloc16: u16) -> Self {
        Self::skeleton(rloc16, Role::Router, Discovery::Unreachable)
    }

    /// Creates an empty node record.
    pub fn skeleton(rloc16: u16, role: Role, discovery: Discovery) -> Self {
        Self {
            rloc16: format_rloc16(rloc16),
            router_id: router_id(rloc16),
            child_id: child_id(rloc16),
            role,
            discovery,
            parent_rloc16: None,
            ext_mac_address: None,
            eui64: None,
            mode: None,
            timeout_seconds: None,
            ipv6_addresses: Vec::new(),
            connectivity: None,
            leader_data: None,
            route_table: Vec::new(),
            child_table: Vec::new(),
            mac_counters: None,
            battery_level_percent: None,
            supply_voltage_mv: None,
            network_data_prefixes: Vec::new(),
            channel_pages: None,
        }
    }

    /// Builds a node from a direct diagnostic answer.
    pub fn from_diag(rloc16: u16, role: Role, data: &NetDiagData) -> Self {
        let mut node = Self::skeleton(rloc16, role, Discovery::DirectQuery);
        node.merge_diag(data);
        node
    }

    /// Redacts this node's IPv6 addresses (they embed the mesh-local prefix /
    /// ML-EID), preserving the count so the topology shape is still visible.
    pub fn redact_secrets(&mut self) {
        for address in &mut self.ipv6_addresses {
            *address = REDACTED.to_string();
        }
    }

    /// Overlays a diagnostic answer onto this record.
    pub fn merge_diag(&mut self, data: &NetDiagData) {
        self.discovery = Discovery::DirectQuery;
        if let Some(ext_mac) = &data.ext_mac_addr {
            self.ext_mac_address = Some(hex::encode(ext_mac));
        }
        if let Some(eui64) = &data.eui64 {
            self.eui64 = Some(hex::encode(eui64));
        }
        if let Some(mode) = &data.mode {
            self.mode = Some(ModeInfo::from_mode(mode));
        }
        if let Some(timeout) = data.timeout {
            self.timeout_seconds = Some(timeout);
        }
        if let Some(addresses) = &data.addresses {
            self.ipv6_addresses = addresses.iter().map(Ipv6Addr::to_string).collect();
        }
        if let Some(connectivity) = &data.connectivity {
            self.connectivity = Some(ConnectivityInfo::from_connectivity(connectivity));
        }
        if let Some(leader_data) = &data.leader_data {
            self.leader_data = Some(LeaderDataInfo::from_leader_data(leader_data));
        }
        if let Some(route64) = &data.route64 {
            let own_router_id = self.router_id;
            self.route_table = route64
                .route_data
                .iter()
                .map(|entry| RouteEntryInfo {
                    router_id: entry.router_id,
                    rloc16: format_rloc16(u16::from(entry.router_id) << 10),
                    relation: if entry.router_id == own_router_id {
                        "self"
                    } else if entry.incoming_link_quality > 0 || entry.outgoing_link_quality > 0 {
                        "neighbor"
                    } else {
                        "multihop"
                    },
                    link_quality_in: entry.incoming_link_quality,
                    link_quality_out: entry.outgoing_link_quality,
                    route_cost: entry.route_cost,
                })
                .collect();
        }
        if let Some(children) = &data.child_table {
            let parent_rloc = (u16::from(self.router_id)) << 10;
            self.child_table = children
                .iter()
                .map(|entry| child_entry_info(parent_rloc, entry))
                .collect();
        }
        if let Some(counters) = &data.mac_counters {
            self.mac_counters = Some(MacCountersInfo::from_counters(counters));
        }
        if let Some(battery) = data.battery_level {
            self.battery_level_percent = Some(battery);
        }
        if let Some(voltage) = data.supply_voltage {
            self.supply_voltage_mv = Some(voltage);
        }
        if let Some(network_data) = &data.network_data {
            self.network_data_prefixes = prefix_infos(network_data);
        }
        if let Some(pages) = &data.channel_pages {
            self.channel_pages = Some(pages.clone());
        }
    }
}

/// Builds the parent-view child entry for `entry` under `parent_rloc`.
pub fn child_entry_info(parent_rloc: u16, entry: &ChildTableEntry) -> ChildEntryInfo {
    ChildEntryInfo {
        rloc16: format_rloc16(parent_rloc | entry.child_id),
        child_id: entry.child_id,
        timeout_seconds: entry.timeout_seconds(),
        incoming_link_quality: entry.incoming_link_quality,
        mode: ModeInfo::from_mode(&entry.mode),
    }
}

fn prefix_infos(network_data: &NetworkData) -> Vec<PrefixInfo> {
    network_data
        .prefixes
        .iter()
        .map(|prefix| PrefixInfo {
            prefix: format_prefix(&prefix.prefix, prefix.prefix_bit_length),
            domain_id: prefix.domain_id,
            six_lowpan_context_id: prefix.six_low_pan_context.map(|context| context.context_id),
            has_route: prefix
                .has_route
                .iter()
                .map(|entry| HasRouteInfo {
                    rloc16: format_rloc16(entry.rloc16),
                    preference: entry.router_preference,
                    nat64: entry.is_nat64,
                })
                .collect(),
            border_routers: prefix
                .border_routers
                .iter()
                .map(|entry| BorderRouterInfo {
                    rloc16: format_rloc16(entry.rloc16),
                    preference: entry.prefix_preference,
                    flags: border_router_flags(entry),
                })
                .collect(),
        })
        .collect()
}

fn border_router_flags(entry: &mesh50::meshcop::diag::BorderRouterEntry) -> String {
    let mut flags = String::new();
    for (set, label) in [
        (entry.is_preferred, 'p'),
        (entry.is_slaac, 'a'),
        (entry.is_dhcp, 'd'),
        (entry.is_configure, 'c'),
        (entry.is_default_route, 'r'),
        (entry.is_on_mesh, 'o'),
        (entry.is_nd_dns, 'n'),
        (entry.is_dp, 'D'),
    ] {
        if set {
            flags.push(label);
        }
    }
    flags
}

/// A point-to-point relationship between two nodes.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Link {
    /// Direct radio link between two routers (from their Route64 tables).
    Mesh {
        a: String,
        b: String,
        /// Link quality as reported by `a` (in = a hears b, out = b hears a).
        #[serde(skip_serializing_if = "Option::is_none")]
        a_view: Option<LinkView>,
        /// Link quality as reported by `b`.
        #[serde(skip_serializing_if = "Option::is_none")]
        b_view: Option<LinkView>,
    },
    /// Parent-child attachment.
    ParentChild {
        parent: String,
        child: String,
        link_quality: u8,
        timeout_seconds: u32,
    },
}

/// One router's view of a mesh link.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct LinkView {
    #[serde(rename = "in")]
    pub lq_in: u8,
    #[serde(rename = "out")]
    pub lq_out: u8,
}

/// Formats an RLOC16 as `0x%04x`.
pub fn format_rloc16(rloc16: u16) -> String {
    format!("0x{rloc16:04x}")
}

/// Extracts the router ID (top 6 bits) of an RLOC16.
pub fn router_id(rloc16: u16) -> u8 {
    (rloc16 >> 10) as u8
}

/// Extracts the child ID (low 10 bits), `None` when the RLOC is a router's.
pub fn child_id(rloc16: u16) -> Option<u16> {
    match rloc16 & 0x03ff {
        0 => None,
        id => Some(id),
    }
}

/// Formats prefix bytes and a bit length as `addr/len`.
fn format_prefix(prefix: &[u8], bit_length: u8) -> String {
    let mut octets = [0u8; 16];
    let len = prefix.len().min(16);
    octets[..len].copy_from_slice(&prefix[..len]);
    format!("{}/{bit_length}", Ipv6Addr::from(octets))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fixtures::{diagnostic_fixture, topology_fixture};

    #[test]
    fn diagnostic_data_populates_every_supported_node_section() {
        let node = Node::from_diag(0x0400, Role::Leader, &diagnostic_fixture());

        assert_eq!(node.rloc16, "0x0400");
        assert_eq!(node.router_id, 1);
        assert_eq!(node.child_id, None);
        assert_eq!(node.discovery, Discovery::DirectQuery);
        assert_eq!(node.ext_mac_address.as_deref(), Some("0200000000000001"));
        assert_eq!(node.eui64.as_deref(), Some("0200000000000002"));
        assert_eq!(node.timeout_seconds, Some(300));
        assert_eq!(node.ipv6_addresses, ["fd11:2233:4455:6677::1"]);

        let mode = node.mode.expect("fixture has mode data");
        assert!(mode.rx_on_when_idle);
        assert_eq!(mode.device_type, "ftd");
        assert!(mode.full_network_data);

        let connectivity = node.connectivity.expect("fixture has connectivity");
        assert_eq!(connectivity.parent_priority, 1);
        assert_eq!(connectivity.link_quality_3_neighbors, 2);
        assert_eq!(connectivity.id_sequence, 7);
        assert_eq!(connectivity.rx_off_child_buffer_size, Some(1280));

        let leader = node.leader_data.expect("fixture has leader data");
        assert_eq!(leader.partition_id, 0x1234_5678);
        assert_eq!(leader.leader_router_id, 1);

        assert_eq!(node.route_table.len(), 5);
        assert_eq!(node.route_table[0].relation, "self");
        assert_eq!(node.route_table[1].relation, "neighbor");
        assert_eq!(node.route_table[2].relation, "multihop");
        assert_eq!(node.route_table[3].relation, "neighbor");
        assert_eq!(node.route_table[4].relation, "neighbor");
        assert_eq!(node.route_table[1].rloc16, "0x0800");

        assert_eq!(node.child_table.len(), 1);
        assert_eq!(node.child_table[0].rloc16, "0x0401");
        assert_eq!(node.child_table[0].timeout_seconds, 32);
        assert_eq!(node.battery_level_percent, Some(87));
        assert_eq!(node.supply_voltage_mv, Some(3_300));
        assert_eq!(node.channel_pages, Some(vec![0, 2]));

        let counters = node.mac_counters.expect("fixture has counters");
        assert_eq!(counters.if_in_unknown_protos, 1);
        assert_eq!(counters.if_out_discards, 9);

        let prefix = &node.network_data_prefixes[0];
        assert_eq!(prefix.prefix, "fd11:2233:4455:6677::/64");
        assert_eq!(prefix.six_lowpan_context_id, Some(1));
        assert_eq!(prefix.has_route[0].rloc16, "0x0800");
        assert!(prefix.has_route[0].nat64);
        assert_eq!(prefix.border_routers[0].flags, "padcronD");
    }

    #[test]
    fn skeleton_helpers_and_redaction_preserve_topology_shape() {
        assert_eq!(format_rloc16(1), "0x0001");
        assert_eq!(router_id(0xfc01), 63);
        assert_eq!(child_id(0x0400), None);
        assert_eq!(child_id(0x0401), Some(1));

        let unreachable = Node::unreachable(0x0800);
        assert_eq!(unreachable.discovery, Discovery::Unreachable);
        assert_eq!(unreachable.role, Role::Router);

        let mut snapshot = topology_fixture();
        snapshot.redact_secrets();
        assert_eq!(snapshot.network.extended_pan_id.as_deref(), Some(REDACTED));
        assert_eq!(
            snapshot.network.mesh_local_prefix.as_deref(),
            Some(REDACTED)
        );
        assert_eq!(snapshot.nodes[0].ipv6_addresses, [REDACTED]);
        assert_eq!(snapshot.nodes.len(), 3);
        assert_eq!(snapshot.links.len(), 2);
    }
}
