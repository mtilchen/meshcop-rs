use std::net::Ipv6Addr;

use mesh50::meshcop::diag::{
    BorderRouterEntry, ChildTableEntry, Connectivity, HasRouteEntry, LeaderData, MacCounters,
    ModeData, NetDiagData, NetworkData, PrefixEntry, Route64, RouteDataEntry, SixLowPanContext,
};

use crate::model::{
    Discovery, Link, LinkView, ModeInfo, NetworkInfo, Node, Role, TopologySnapshot,
};

pub fn diagnostic_fixture() -> NetDiagData {
    NetDiagData {
        ext_mac_addr: Some(vec![0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]),
        mac_addr: Some(0x0400),
        mode: Some(ModeData {
            rx_on_when_idle: true,
            is_mtd: false,
            requires_full_network_data: true,
        }),
        timeout: Some(300),
        connectivity: Some(Connectivity {
            parent_priority: 1,
            link_quality_3: 2,
            link_quality_2: 1,
            link_quality_1: 0,
            leader_cost: 1,
            id_sequence: 7,
            active_routers: 2,
            rx_off_child_buffer_size: Some(1280),
            rx_off_child_datagram_count: Some(4),
        }),
        route64: Some(Route64 {
            id_sequence: 7,
            mask: [0; 8],
            route_data: vec![
                RouteDataEntry {
                    router_id: 1,
                    outgoing_link_quality: 3,
                    incoming_link_quality: 3,
                    route_cost: 0,
                },
                RouteDataEntry {
                    router_id: 2,
                    outgoing_link_quality: 2,
                    incoming_link_quality: 3,
                    route_cost: 1,
                },
                RouteDataEntry {
                    router_id: 3,
                    outgoing_link_quality: 0,
                    incoming_link_quality: 0,
                    route_cost: 2,
                },
                RouteDataEntry {
                    router_id: 4,
                    outgoing_link_quality: 0,
                    incoming_link_quality: 1,
                    route_cost: 2,
                },
                RouteDataEntry {
                    router_id: 5,
                    outgoing_link_quality: 1,
                    incoming_link_quality: 0,
                    route_cost: 2,
                },
            ],
        }),
        leader_data: Some(LeaderData {
            partition_id: 0x1234_5678,
            weighting: 64,
            data_version: 9,
            stable_data_version: 8,
            router_id: 1,
        }),
        network_data: Some(NetworkData {
            prefixes: vec![PrefixEntry {
                domain_id: 0,
                prefix_bit_length: 64,
                prefix: vec![0xfd, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77],
                six_low_pan_context: Some(SixLowPanContext {
                    is_compress: true,
                    context_id: 1,
                    context_length: 64,
                }),
                has_route: vec![HasRouteEntry {
                    rloc16: 0x0800,
                    router_preference: 1,
                    is_nat64: true,
                }],
                border_routers: vec![BorderRouterEntry {
                    rloc16: 0x0400,
                    prefix_preference: 2,
                    is_preferred: true,
                    is_slaac: true,
                    is_dhcp: true,
                    is_configure: true,
                    is_default_route: true,
                    is_on_mesh: true,
                    is_nd_dns: true,
                    is_dp: true,
                }],
            }],
        }),
        addresses: Some(vec![
            "fd11:2233:4455:6677::1"
                .parse::<Ipv6Addr>()
                .expect("fixture address is valid"),
        ]),
        mac_counters: Some(MacCounters {
            if_in_unknown_protos: 1,
            if_in_errors: 2,
            if_out_errors: 3,
            if_in_ucast_pkts: 4,
            if_in_broadcast_pkts: 5,
            if_in_discards: 6,
            if_out_ucast_pkts: 7,
            if_out_broadcast_pkts: 8,
            if_out_discards: 9,
        }),
        battery_level: Some(87),
        supply_voltage: Some(3_300),
        child_table: Some(vec![ChildTableEntry {
            timeout_exponent: 9,
            incoming_link_quality: 3,
            child_id: 1,
            mode: ModeData {
                rx_on_when_idle: false,
                is_mtd: true,
                requires_full_network_data: false,
            },
        }]),
        channel_pages: Some(vec![0, 2]),
        eui64: Some([0x02, 0, 0, 0, 0, 0, 0, 2]),
        ..NetDiagData::default()
    }
}

pub fn topology_fixture() -> TopologySnapshot {
    let leader = Node::from_diag(0x0400, Role::Leader, &diagnostic_fixture());
    let router = Node::unreachable(0x0800);
    let mut child = Node::skeleton(0x0401, Role::Child, Discovery::ParentTable);
    child.parent_rloc16 = Some("0x0400".to_string());
    child.mode = Some(ModeInfo {
        rx_on_when_idle: false,
        device_type: "mtd",
        full_network_data: false,
    });

    TopologySnapshot {
        generated_unix_time: 1_700_000_000,
        border_agent: "192.0.2.1:49154".to_string(),
        network: NetworkInfo {
            network_name: Some("fixture-net".to_string()),
            pan_id: Some("0x1234".to_string()),
            extended_pan_id: Some("0011223344556677".to_string()),
            channel_page: Some(0),
            channel: Some(15),
            mesh_local_prefix: Some("fd11:2233:4455:6677::/64".to_string()),
            partition_id: Some(0x1234_5678),
            leader_rloc16: Some("0x0400".to_string()),
        },
        nodes: vec![leader, router, child],
        links: vec![
            Link::Mesh {
                a: "0x0400".to_string(),
                b: "0x0800".to_string(),
                a_view: Some(LinkView {
                    lq_in: 3,
                    lq_out: 2,
                }),
                b_view: Some(LinkView {
                    lq_in: 2,
                    lq_out: 3,
                }),
            },
            Link::ParentChild {
                parent: "0x0400".to_string(),
                child: "0x0401".to_string(),
                link_quality: 3,
                timeout_seconds: 32,
            },
        ],
    }
}
