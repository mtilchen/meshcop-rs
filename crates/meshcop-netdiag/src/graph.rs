//! Plain-text graphical rendering of the topology for terminals.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::model::{Link, LinkView, Node, Role, TopologySnapshot};

/// Renders an ASCII tree: the leader at the root, routers as a mesh summary,
/// and children indented under their parent.
pub fn topology_ascii(snapshot: &TopologySnapshot) -> String {
    let mut out = String::new();
    let name = snapshot
        .network
        .network_name
        .clone()
        .unwrap_or_else(|| "Thread network".to_string());
    let _ = writeln!(out, "{name}");
    if let (Some(channel), Some(pan)) = (snapshot.network.channel, &snapshot.network.pan_id) {
        let _ = writeln!(out, "  channel {channel}, pan {pan}");
    }
    let _ = writeln!(out);

    // Index children by parent RLOC16.
    let mut children_by_parent: BTreeMap<String, Vec<&Node>> = BTreeMap::new();
    for node in &snapshot.nodes {
        if node.role == Role::Child {
            if let Some(parent) = &node.parent_rloc16 {
                children_by_parent
                    .entry(parent.clone())
                    .or_default()
                    .push(node);
            }
        }
    }

    let routers: Vec<&Node> = snapshot
        .nodes
        .iter()
        .filter(|node| node.role != Role::Child)
        .collect();

    for (index, router) in routers.iter().enumerate() {
        let last_router = index + 1 == routers.len();
        let marker = if last_router { "└─" } else { "├─" };
        let role = match router.role {
            Role::Leader => "LEADER",
            _ => "router",
        };
        let reachable = match router.discovery {
            crate::model::Discovery::Unreachable => "  (unreachable)",
            _ => "",
        };
        let _ = writeln!(out, "{marker} [{role}] {}{reachable}", router.rloc16);

        let child_indent = if last_router { "   " } else { "│  " };
        let neighbors = mesh_neighbors(snapshot, &router.rloc16);
        if !neighbors.is_empty() {
            let _ = writeln!(out, "{child_indent}· mesh links: {}", neighbors.join(", "));
        }
        if let Some(connectivity) = &router.connectivity {
            let _ = writeln!(
                out,
                "{child_indent}· neighbors lq3/lq2/lq1 = {}/{}/{}, leader cost {}",
                connectivity.link_quality_3_neighbors,
                connectivity.link_quality_2_neighbors,
                connectivity.link_quality_1_neighbors,
                connectivity.leader_cost,
            );
        }

        if let Some(children) = children_by_parent.get(&router.rloc16) {
            for (child_index, child) in children.iter().enumerate() {
                let last_child = child_index + 1 == children.len();
                let child_marker = if last_child { "└─" } else { "├─" };
                let kind = child
                    .mode
                    .map(|mode| {
                        format!(
                            "{} {}",
                            if mode.rx_on_when_idle {
                                "rx-on"
                            } else {
                                "sleepy"
                            },
                            mode.device_type
                        )
                    })
                    .unwrap_or_else(|| "child".to_string());
                let direct = match child.discovery {
                    crate::model::Discovery::DirectQuery => "",
                    _ => " (parent-table only)",
                };
                let _ = writeln!(
                    out,
                    "{child_indent}{child_marker} {} [{kind}]{direct}",
                    child.rloc16
                );
            }
        }
    }

    let _ = writeln!(
        out,
        "\n{} routers, {} children, {} links",
        routers.len(),
        snapshot.nodes.len() - routers.len(),
        snapshot.links.len(),
    );
    out
}

/// RLOC16s of mesh neighbors of `rloc`, with link quality from `rloc`'s own
/// perspective (in = `rloc` hears the neighbor, out = the neighbor hears `rloc`).
fn mesh_neighbors(snapshot: &TopologySnapshot, rloc: &str) -> Vec<String> {
    let mut neighbors = Vec::new();
    for link in &snapshot.links {
        if let Link::Mesh {
            a,
            b,
            a_view,
            b_view,
        } = link
        {
            let (other, view) = if a == rloc {
                (b, own_view(*a_view, *b_view))
            } else if b == rloc {
                (a, own_view(*b_view, *a_view))
            } else {
                continue;
            };
            match view {
                Some(view) => {
                    neighbors.push(format!("{other} (lq {}/{})", view.lq_in, view.lq_out))
                }
                None => neighbors.push(other.clone()),
            }
        }
    }
    neighbors
}

/// Returns the node's own link view, or the peer's view with in/out swapped
/// (a link view is perspective-dependent), preferring the node's own.
fn own_view(own: Option<LinkView>, peer: Option<LinkView>) -> Option<LinkView> {
    own.or_else(|| {
        peer.map(|view| LinkView {
            lq_in: view.lq_out,
            lq_out: view.lq_in,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Discovery, Link, LinkView, Node, Role};
    use crate::test_fixtures::topology_fixture;

    #[test]
    fn ascii_layout_places_children_under_parents_and_summarizes_mesh() {
        let graph = topology_ascii(&topology_fixture());

        assert!(graph.starts_with("fixture-net\n  channel 15, pan 0x1234\n"));
        assert!(graph.contains("├─ [LEADER] 0x0400"));
        assert!(graph.contains("│  · mesh links: 0x0800 (lq 3/2)"));
        assert!(graph.contains("│  · neighbors lq3/lq2/lq1 = 2/1/0, leader cost 1"));
        assert!(graph.contains("│  └─ 0x0401 [sleepy mtd] (parent-table only)"));
        assert!(graph.contains("└─ [router] 0x0800  (unreachable)"));
        assert!(graph.contains("   · mesh links: 0x0400 (lq 2/3)"));
        assert!(graph.ends_with("2 routers, 1 children, 2 links\n"));
    }

    #[test]
    fn layout_handles_missing_metadata_and_peer_only_link_views() {
        let mut snapshot = topology_fixture();
        snapshot.network.network_name = None;
        snapshot.network.channel = None;
        snapshot.nodes.clear();

        let mut leader = Node::skeleton(0x0400, Role::Leader, Discovery::DirectQuery);
        leader.connectivity = None;
        let mut first_child = Node::skeleton(0x0401, Role::Child, Discovery::DirectQuery);
        first_child.parent_rloc16 = Some("0x0400".to_string());
        let mut last_child = Node::skeleton(0x0402, Role::Child, Discovery::ParentTable);
        last_child.parent_rloc16 = Some("0x0400".to_string());
        snapshot.nodes = vec![leader, first_child, last_child];
        snapshot.links = vec![Link::Mesh {
            a: "0x0400".to_string(),
            b: "0x0800".to_string(),
            a_view: None,
            b_view: Some(LinkView {
                lq_in: 1,
                lq_out: 2,
            }),
        }];

        let graph = topology_ascii(&snapshot);
        assert!(graph.starts_with("Thread network\n\n"));
        assert!(graph.contains("· mesh links: 0x0800 (lq 2/1)"));
        assert!(graph.contains("├─ 0x0401 [child]\n"));
        assert!(graph.contains("└─ 0x0402 [child] (parent-table only)"));

        snapshot.links = vec![Link::Mesh {
            a: "0x0400".to_string(),
            b: "0x0800".to_string(),
            a_view: None,
            b_view: None,
        }];
        assert!(topology_ascii(&snapshot).contains("· mesh links: 0x0800"));
    }

    #[test]
    fn own_view_prefers_local_data_and_reverses_peer_data() {
        let local = LinkView {
            lq_in: 3,
            lq_out: 2,
        };
        let peer = LinkView {
            lq_in: 1,
            lq_out: 2,
        };

        let preferred = own_view(Some(local), Some(peer)).expect("local view is retained");
        assert_eq!((preferred.lq_in, preferred.lq_out), (3, 2));
        let reversed = own_view(None, Some(peer)).expect("peer view is available");
        assert_eq!((reversed.lq_in, reversed.lq_out), (2, 1));
        assert!(own_view(None, None).is_none());
    }
}
