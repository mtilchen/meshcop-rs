//! Markdown rendering of the topology model.

use std::fmt::Write as _;

use crate::model::{Link, LinkView, Node, Role, TopologySnapshot};

/// Renders the full snapshot as a markdown report.
pub fn topology_markdown(snapshot: &TopologySnapshot) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Thread network diagnostic report\n");
    let _ = writeln!(
        out,
        "Collected via border agent `{}` (unix time {}).\n",
        snapshot.border_agent, snapshot.generated_unix_time
    );

    let _ = writeln!(out, "## Network\n");
    let _ = writeln!(out, "| Property | Value |");
    let _ = writeln!(out, "| --- | --- |");
    let network = &snapshot.network;
    let mut row = |name: &str, value: Option<String>| {
        if let Some(value) = value {
            let _ = writeln!(out, "| {name} | {value} |");
        }
    };
    row("Network name", network.network_name.clone());
    row("PAN ID", network.pan_id.clone());
    row("Extended PAN ID", network.extended_pan_id.clone());
    row(
        "Channel",
        network.channel.map(|channel| match network.channel_page {
            Some(page) => format!("{channel} (page {page})"),
            None => channel.to_string(),
        }),
    );
    row("Mesh-local prefix", network.mesh_local_prefix.clone());
    row(
        "Partition ID",
        network.partition_id.map(|id| format!("0x{id:08x}")),
    );
    row("Leader RLOC16", network.leader_rloc16.clone());
    let routers = snapshot
        .nodes
        .iter()
        .filter(|node| node.role != Role::Child)
        .count();
    let children = snapshot.nodes.len() - routers;
    let _ = writeln!(out, "| Routers | {routers} |");
    let _ = writeln!(out, "| Children | {children} |");

    let _ = writeln!(out, "\n## Topology\n");
    let _ = writeln!(out, "```mermaid");
    out.push_str(&mermaid_graph(snapshot));
    let _ = writeln!(out, "```");

    let _ = writeln!(out, "\n## Nodes\n");
    for node in &snapshot.nodes {
        out.push_str(&node_markdown(node, 3));
    }

    let _ = writeln!(out, "\n## Links\n");
    let _ = writeln!(out, "| Kind | A | B | Link quality | Notes |");
    let _ = writeln!(out, "| --- | --- | --- | --- | --- |");
    for link in &snapshot.links {
        match link {
            Link::Mesh {
                a,
                b,
                a_view,
                b_view,
            } => {
                // Quality is reported from A's perspective. A view is
                // perspective-dependent (in = A hears B, out = B hears A), so
                // when only B reported, swap in/out to express it as A's view.
                let quality = match (a_view, b_view) {
                    (Some(va), _) => format!("in {} / out {}", va.lq_in, va.lq_out),
                    (None, Some(vb)) => format!("in {} / out {} (from B)", vb.lq_out, vb.lq_in),
                    (None, None) => "unknown".to_string(),
                };
                let note = match (a_view, b_view) {
                    (Some(_), Some(_)) => "both views collected",
                    _ => "one-sided view",
                };
                let _ = writeln!(out, "| mesh | {a} | {b} | {quality} | {note} |");
            }
            Link::ParentChild {
                parent,
                child,
                link_quality,
                timeout_seconds,
            } => {
                let _ = writeln!(
                    out,
                    "| parent-child | {parent} | {child} | in {link_quality} | timeout {timeout_seconds}s |"
                );
            }
        }
    }
    out
}

/// Renders one node as a markdown report (used by the `node` command).
pub fn node_report_markdown(node: &Node) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "# Node {} diagnostic report\n", node.rloc16);
    out.push_str(&node_markdown(node, 2));
    out
}

fn node_markdown(node: &Node, heading_level: usize) -> String {
    let mut out = String::new();
    let heading = "#".repeat(heading_level);
    let role = match node.role {
        Role::Leader => "leader",
        Role::Router => "router",
        Role::Child => "child",
    };
    let _ = writeln!(out, "{heading} {} — {role}\n", node.rloc16);

    let _ = writeln!(out, "| Property | Value |");
    let _ = writeln!(out, "| --- | --- |");
    let _ = writeln!(out, "| Router ID | {} |", node.router_id);
    if let Some(child_id) = node.child_id {
        let _ = writeln!(out, "| Child ID | {child_id} |");
    }
    let _ = writeln!(out, "| Discovery | {:?} |", node.discovery);
    if let Some(parent) = &node.parent_rloc16 {
        let _ = writeln!(out, "| Parent | {parent} |");
    }
    if let Some(ext_mac) = &node.ext_mac_address {
        let _ = writeln!(out, "| Extended MAC | `{ext_mac}` |");
    }
    if let Some(eui64) = &node.eui64 {
        let _ = writeln!(out, "| EUI-64 | `{eui64}` |");
    }
    if let Some(mode) = &node.mode {
        let _ = writeln!(
            out,
            "| Mode | {} {}, network data: {} |",
            if mode.rx_on_when_idle {
                "rx-on"
            } else {
                "sleepy"
            },
            mode.device_type,
            if mode.full_network_data {
                "full"
            } else {
                "stable-only"
            },
        );
    }
    if let Some(timeout) = node.timeout_seconds {
        let _ = writeln!(out, "| Timeout | {timeout}s |");
    }
    if let Some(connectivity) = &node.connectivity {
        let _ = writeln!(
            out,
            "| Connectivity | parent priority {}, neighbors lq3/lq2/lq1 = {}/{}/{}, leader cost {}, active routers {} |",
            connectivity.parent_priority,
            connectivity.link_quality_3_neighbors,
            connectivity.link_quality_2_neighbors,
            connectivity.link_quality_1_neighbors,
            connectivity.leader_cost,
            connectivity.active_routers,
        );
    }
    if let Some(leader_data) = &node.leader_data {
        let _ = writeln!(
            out,
            "| Leader data | partition 0x{:08x}, weighting {}, data version {}/{} (stable), leader router {} |",
            leader_data.partition_id,
            leader_data.weighting,
            leader_data.data_version,
            leader_data.stable_data_version,
            leader_data.leader_router_id,
        );
    }
    if let Some(battery) = node.battery_level_percent {
        let _ = writeln!(out, "| Battery | {battery}% |");
    }
    if let Some(voltage) = node.supply_voltage_mv {
        let _ = writeln!(out, "| Supply voltage | {voltage} mV |");
    }
    if let Some(pages) = &node.channel_pages {
        let _ = writeln!(out, "| Channel pages | {pages:?} |");
    }

    if !node.ipv6_addresses.is_empty() {
        let _ = writeln!(out, "\nIPv6 addresses:\n");
        for address in &node.ipv6_addresses {
            let _ = writeln!(out, "- `{address}`");
        }
    }

    if !node.route_table.is_empty() {
        let _ = writeln!(out, "\nRoute table:\n");
        let _ = writeln!(out, "| To router | Relation | LQ in | LQ out | Cost |");
        let _ = writeln!(out, "| --- | --- | --- | --- | --- |");
        for entry in &node.route_table {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} | {} |",
                entry.rloc16,
                entry.relation,
                entry.link_quality_in,
                entry.link_quality_out,
                entry.route_cost,
            );
        }
    }

    if !node.child_table.is_empty() {
        let _ = writeln!(out, "\nChild table:\n");
        let _ = writeln!(out, "| Child | Timeout | LQ in | Mode |");
        let _ = writeln!(out, "| --- | --- | --- | --- |");
        for entry in &node.child_table {
            let _ = writeln!(
                out,
                "| {} | {}s | {} | {} {} |",
                entry.rloc16,
                entry.timeout_seconds,
                entry.incoming_link_quality,
                if entry.mode.rx_on_when_idle {
                    "rx-on"
                } else {
                    "sleepy"
                },
                entry.mode.device_type,
            );
        }
    }

    if !node.network_data_prefixes.is_empty() {
        let _ = writeln!(out, "\nNetwork data prefixes:\n");
        let _ = writeln!(out, "| Prefix | Context | Border routers | Has route |");
        let _ = writeln!(out, "| --- | --- | --- | --- |");
        for prefix in &node.network_data_prefixes {
            let border_routers = prefix
                .border_routers
                .iter()
                .map(|entry| format!("{} [{}]", entry.rloc16, entry.flags))
                .collect::<Vec<_>>()
                .join(", ");
            let has_route = prefix
                .has_route
                .iter()
                .map(|entry| entry.rloc16.clone())
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(
                out,
                "| `{}` | {} | {} | {} |",
                prefix.prefix,
                prefix
                    .six_lowpan_context_id
                    .map(|id| format!("6lo cid {id}"))
                    .unwrap_or_else(|| "—".to_string()),
                if border_routers.is_empty() {
                    "—".to_string()
                } else {
                    border_routers
                },
                if has_route.is_empty() {
                    "—".to_string()
                } else {
                    has_route
                },
            );
        }
    }

    if let Some(counters) = &node.mac_counters {
        let _ = writeln!(out, "\nMAC counters:\n");
        let _ = writeln!(out, "| Counter | Value |");
        let _ = writeln!(out, "| --- | --- |");
        for (name, value) in [
            ("ifInUcastPkts", counters.if_in_ucast_pkts),
            ("ifInBroadcastPkts", counters.if_in_broadcast_pkts),
            ("ifInDiscards", counters.if_in_discards),
            ("ifInErrors", counters.if_in_errors),
            ("ifInUnknownProtos", counters.if_in_unknown_protos),
            ("ifOutUcastPkts", counters.if_out_ucast_pkts),
            ("ifOutBroadcastPkts", counters.if_out_broadcast_pkts),
            ("ifOutDiscards", counters.if_out_discards),
            ("ifOutErrors", counters.if_out_errors),
        ] {
            let _ = writeln!(out, "| {name} | {value} |");
        }
    }

    out.push('\n');
    out
}

/// Mermaid `graph TD` rendering of nodes and links.
fn mermaid_graph(snapshot: &TopologySnapshot) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "graph TD");
    for node in &snapshot.nodes {
        let id = mermaid_id(&node.rloc16);
        let label = match node.role {
            Role::Leader => format!("{}<br/>leader", node.rloc16),
            Role::Router => format!("{}<br/>router", node.rloc16),
            Role::Child => format!("{}<br/>child", node.rloc16),
        };
        let _ = writeln!(out, "    {id}[\"{label}\"]");
    }
    for link in &snapshot.links {
        match link {
            Link::Mesh {
                a,
                b,
                a_view,
                b_view,
            } => {
                // Prefer A's own view; otherwise show B's view with in/out
                // swapped so the edge label is in A's perspective (the table and
                // ASCII graph do the same), rather than an unhelpful "lq ?".
                let label = a_view
                    .or_else(|| {
                        b_view.map(|view| LinkView {
                            lq_in: view.lq_out,
                            lq_out: view.lq_in,
                        })
                    })
                    .map(|view| format!("lq {}/{}", view.lq_in, view.lq_out))
                    .unwrap_or_else(|| "lq ?".to_string());
                let _ = writeln!(
                    out,
                    "    {} ---|\"{label}\"| {}",
                    mermaid_id(a),
                    mermaid_id(b)
                );
            }
            Link::ParentChild {
                parent,
                child,
                link_quality,
                ..
            } => {
                let _ = writeln!(
                    out,
                    "    {} -->|\"child lq {link_quality}\"| {}",
                    mermaid_id(parent),
                    mermaid_id(child)
                );
            }
        }
    }
    out
}

fn mermaid_id(rloc16: &str) -> String {
    format!("N{}", rloc16.trim_start_matches("0x"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Discovery, Link, LinkView, Node, Role};
    use crate::test_fixtures::topology_fixture;

    #[test]
    fn topology_report_renders_fixture_network_nodes_and_links() {
        let mut snapshot = topology_fixture();
        snapshot
            .nodes
            .push(Node::skeleton(0x0402, Role::Child, Discovery::ParentTable));
        snapshot
            .nodes
            .push(Node::skeleton(0x0403, Role::Child, Discovery::ParentTable));
        let report = topology_markdown(&snapshot);

        for expected in [
            "# Thread network diagnostic report",
            "| Network name | fixture-net |",
            "| Channel | 15 (page 0) |",
            "| Routers | 2 |",
            "| Children | 3 |",
            "N0400[\"0x0400<br/>leader\"]",
            "N0400 ---|\"lq 3/2\"| N0800",
            "N0400 -->|\"child lq 3\"| N0401",
            "| mesh | 0x0400 | 0x0800 | in 3 / out 2 | both views collected |",
            "| parent-child | 0x0400 | 0x0401 | in 3 | timeout 32s |",
            "Network data prefixes:",
            "| `fd11:2233:4455:6677::/64` | 6lo cid 1 | 0x0400 [padcronD] | 0x0800 |",
            "ifOutErrors",
        ] {
            assert!(report.contains(expected), "missing report text: {expected}");
        }
    }

    #[test]
    fn node_report_and_json_render_the_same_fixture_data() {
        let snapshot = topology_fixture();
        let leader = &snapshot.nodes[0];
        let markdown = node_report_markdown(leader);
        assert!(markdown.starts_with("# Node 0x0400 diagnostic report"));
        assert!(markdown.contains("| Mode | rx-on ftd, network data: full |"));
        assert!(markdown.contains("| Connectivity | parent priority 1"));
        assert!(markdown.contains("| Leader data | partition 0x12345678"));
        assert!(markdown.contains("| Battery | 87% |"));
        assert!(markdown.contains("- `fd11:2233:4455:6677::1`"));
        assert!(markdown.contains("| 0x0800 | neighbor | 3 | 2 | 1 |"));
        assert!(markdown.contains("| 0x0401 | 32s | 3 | sleepy mtd |"));

        let json = serde_json::to_value(&snapshot).expect("fixture serializes");
        assert_eq!(json["network"]["network_name"], "fixture-net");
        assert_eq!(json["nodes"][0]["role"], "leader");
        assert_eq!(json["nodes"][1]["discovery"], "unreachable");
        assert_eq!(json["links"][1]["kind"], "parent-child");
    }

    #[test]
    fn one_sided_and_unknown_mesh_views_render_in_a_perspective() {
        let mut snapshot = topology_fixture();
        snapshot.links = vec![
            Link::Mesh {
                a: "0x0400".to_string(),
                b: "0x0800".to_string(),
                a_view: None,
                b_view: Some(LinkView {
                    lq_in: 1,
                    lq_out: 2,
                }),
            },
            Link::Mesh {
                a: "0x0800".to_string(),
                b: "0x0c00".to_string(),
                a_view: None,
                b_view: None,
            },
        ];
        snapshot
            .nodes
            .push(Node::skeleton(0x0c00, Role::Router, Discovery::DirectQuery));

        let report = topology_markdown(&snapshot);
        assert!(report.contains("N0400 ---|\"lq 2/1\"| N0800"));
        assert!(report.contains("| mesh | 0x0400 | 0x0800 | in 2 / out 1 (from B) |"));
        assert!(report.contains("N0800 ---|\"lq ?\"| N0c00"));
        assert!(report.contains("| mesh | 0x0800 | 0x0c00 | unknown | one-sided view |"));
    }
}
