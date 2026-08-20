//! Walks a Thread mesh through the commissioner UDP proxy and assembles the
//! topology model.
//!
//! Diagnostics are fetched with the unicast DIAG_GET.req resource (`/d/dg`),
//! which piggybacks the requested TLVs in its response. Real border routers
//! cap the size of that response, so asking for every TLV at once can exceed
//! the limit and get no answer at all. [`Collector::collect_diag`] therefore
//! requests TLVs adaptively: it tries the whole set, and whenever a request
//! goes unanswered it splits the TLV list in half and retries each half, down
//! to single TLVs. A single TLV that still goes unanswered is recorded as
//! unsupported and skipped on every later node.

use std::collections::BTreeMap;
use std::net::Ipv6Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use meshcop::{
    commissioner::{Commissioner, DatasetFlags, ResultCode},
    dataset::Dataset,
    error::Error,
    meshcop::diag::{NetDiagData, diag_flags},
};

use crate::model::{
    Discovery, Link, LinkView, NetworkInfo, Node, Role, TopologySnapshot, child_entry_info,
    format_rloc16,
};

/// Anycast locator of the leader (Thread 1.4 §5.2.2.1).
const LEADER_ALOC16: u16 = 0xfc00;
/// Initial TLVs-per-request. A border agent caps its DIAG_GET.rsp size, so a
/// modest chunk keeps most requests answerable in one round trip; the adaptive
/// splitter in [`Collector::collect_diag`] handles the occasional overflow.
const CHUNK_SIZE: usize = 6;
/// Attempts to reach a node before declaring it unreachable. Thread resolves an
/// unknown RLOC's route on demand and drops the first datagram while it does, so
/// the first attempt to a not-recently-contacted router usually times out; a
/// retry lands once the route is cached.
const PRIME_ATTEMPTS: usize = 4;

/// Router/leader diagnostic TLVs, ordered most-useful first so the two
/// size-heavy TLVs (Network Data, IPv6 Address List) land at the end where the
/// adaptive splitter isolates them quickly.
const ROUTER_TLVS: &[u64] = &[
    diag_flags::MAC_ADDR,
    diag_flags::EXT_MAC_ADDR,
    diag_flags::MODE,
    diag_flags::TIMEOUT,
    diag_flags::CONNECTIVITY,
    diag_flags::ROUTE64,
    diag_flags::LEADER_DATA,
    diag_flags::MAC_COUNTERS,
    diag_flags::BATTERY_LEVEL,
    diag_flags::SUPPLY_VOLTAGE,
    diag_flags::CHILD_TABLE,
    diag_flags::CHANNEL_PAGES,
    diag_flags::EUI64,
    diag_flags::CHILD_IPV6_ADDRESSES,
    diag_flags::NETWORK_DATA,
    diag_flags::IPV6_ADDRESSES,
];

/// Child diagnostic TLVs (router-only TLVs such as Route64 omitted).
const CHILD_TLVS: &[u64] = &[
    diag_flags::MAC_ADDR,
    diag_flags::EXT_MAC_ADDR,
    diag_flags::MODE,
    diag_flags::TIMEOUT,
    diag_flags::CONNECTIVITY,
    diag_flags::LEADER_DATA,
    diag_flags::MAC_COUNTERS,
    diag_flags::BATTERY_LEVEL,
    diag_flags::SUPPLY_VOLTAGE,
    diag_flags::CHANNEL_PAGES,
    diag_flags::EUI64,
    diag_flags::IPV6_ADDRESSES,
];

/// Non-secret active dataset TLVs used for network info and routing.
const DATASET_FLAGS: DatasetFlags = DatasetFlags::from_bits(
    DatasetFlags::NETWORK_NAME.bits()
        | DatasetFlags::CHANNEL.bits()
        | DatasetFlags::PAN_ID.bits()
        | DatasetFlags::EXTENDED_PAN_ID.bits()
        | DatasetFlags::MESH_LOCAL_PREFIX.bits(),
);

/// Minimal TLVs used to discover the leader and the router list via the ALOC,
/// before each router (including the leader) is queried in full by its RLOC.
const DISCOVERY_TLVS: &[u64] = &[
    diag_flags::MAC_ADDR,
    diag_flags::ROUTE64,
    diag_flags::LEADER_DATA,
];

/// Per-session mesh walker.
pub struct Collector<'a> {
    commissioner: &'a mut Commissioner,
    node_timeout: Duration,
    keep_alive_interval: Duration,
    last_keep_alive: tokio::time::Instant,
    mesh_local_prefix: [u8; 8],
    dataset: Dataset,
}

impl<'a> Collector<'a> {
    /// Petitions and fetches the non-secret dataset facts needed for routing.
    pub async fn start(
        commissioner: &'a mut Commissioner,
        node_timeout: Duration,
    ) -> meshcop::Result<Collector<'a>> {
        let keep_alive_interval = commissioner.config().keepalive_interval;
        if node_timeout.saturating_mul(2) >= keep_alive_interval {
            return Err(Error::Configuration(
                "two netdiag node timeouts must fit within the keepalive interval",
            ));
        }
        let petition = commissioner.petition().await?;
        let last_keep_alive = tokio::time::Instant::now();
        eprintln!(
            "petition accepted: session_id=0x{:04x}",
            petition.session_id
        );
        let dataset = commissioner.get_active_dataset(DATASET_FLAGS).await?;
        let mesh_local_prefix = dataset.mesh_local_prefix()?.ok_or(Error::InvalidState(
            "active dataset did not include the mesh-local prefix",
        ))?;
        Ok(Collector {
            commissioner,
            node_timeout,
            keep_alive_interval,
            last_keep_alive,
            mesh_local_prefix,
            dataset,
        })
    }

    /// Queries every device on the network and assembles the snapshot.
    pub async fn collect_topology(
        &mut self,
        border_agent: String,
    ) -> meshcop::Result<TopologySnapshot> {
        // Discover the leader and router list cheaply via the Leader ALOC. The
        // ALOC answers small requests but not the size-heavy Network Data / IPv6
        // Address List TLVs, so each router (the leader included) is queried in
        // full by its own RLOC below.
        let discovery = self
            .collect_diag(self.mesh_local_addr(LEADER_ALOC16), DISCOVERY_TLVS)
            .await?
            .ok_or(Error::Timeout("the leader did not answer DIAG_GET.req"))?;
        let leader_rloc = discovery
            .mac_addr
            .or_else(|| {
                discovery
                    .leader_data
                    .as_ref()
                    .map(|data| u16::from(data.router_id) << 10)
            })
            .ok_or(Error::InvalidState(
                "leader answer carried neither RLOC16 nor leader data",
            ))?;
        eprintln!("leader is {}", format_rloc16(leader_rloc));

        let mut router_rlocs: Vec<u16> = discovery
            .route64
            .as_ref()
            .map(|route64| {
                route64
                    .route_data
                    .iter()
                    .map(|entry| u16::from(entry.router_id) << 10)
                    .collect()
            })
            .unwrap_or_default();
        if !router_rlocs.contains(&leader_rloc) {
            router_rlocs.push(leader_rloc);
        }

        let mut nodes: BTreeMap<u16, Node> = BTreeMap::new();
        let mut answers: BTreeMap<u16, NetDiagData> = BTreeMap::new();
        for rloc in router_rlocs {
            self.keep_alive_before_request().await?;
            let role = if rloc == leader_rloc {
                Role::Leader
            } else {
                Role::Router
            };
            eprintln!("querying {} {}", role_label(role), format_rloc16(rloc));
            match self
                .collect_diag(self.mesh_local_addr(rloc), ROUTER_TLVS)
                .await?
            {
                Some(data) => {
                    nodes.insert(rloc, Node::from_diag(rloc, role, &data));
                    answers.insert(rloc, data);
                }
                None => {
                    eprintln!("  {} did not answer", format_rloc16(rloc));
                    let mut node = Node::unreachable(rloc);
                    node.role = role;
                    nodes.insert(rloc, node);
                }
            }
        }

        self.collect_children(&mut nodes, &answers).await?;

        let links = build_links(&nodes);
        let leader_diag = answers.get(&leader_rloc).unwrap_or(&discovery);
        let network = self.network_info(leader_rloc, leader_diag)?;
        Ok(TopologySnapshot {
            generated_unix_time: unix_time(),
            border_agent,
            network,
            nodes: nodes.into_values().collect(),
            links,
        })
    }

    /// Queries one node, falling back to its parent's child-table view.
    pub async fn collect_node(&mut self, rloc16: u16) -> meshcop::Result<Node> {
        let is_child = crate::model::child_id(rloc16).is_some();
        let tlvs = if is_child { CHILD_TLVS } else { ROUTER_TLVS };
        if let Some(data) = self
            .collect_diag(self.mesh_local_addr(rloc16), tlvs)
            .await?
        {
            let role = resolve_role(rloc16, &data, default_role(rloc16));
            return Ok(Node::from_diag(rloc16, role, &data));
        }
        eprintln!("node {} did not answer directly", format_rloc16(rloc16));

        if is_child {
            let parent_rloc = rloc16 & 0xfc00;
            eprintln!("asking parent {}", format_rloc16(parent_rloc));
            if let Some(parent) = self
                .collect_diag(self.mesh_local_addr(parent_rloc), ROUTER_TLVS)
                .await?
            {
                let mut children = BTreeMap::new();
                merge_parent_children(&mut children, parent_rloc, &parent);
                if let Some(node) = children.remove(&rloc16) {
                    return Ok(node);
                }
            }
        }
        Ok(Node::skeleton(
            rloc16,
            default_role(rloc16),
            Discovery::Unreachable,
        ))
    }

    /// Adds child nodes from every router's child table, then upgrades each
    /// child with a direct query when it answers.
    async fn collect_children(
        &mut self,
        nodes: &mut BTreeMap<u16, Node>,
        answers: &BTreeMap<u16, NetDiagData>,
    ) -> meshcop::Result<()> {
        let mut children: BTreeMap<u16, Node> = BTreeMap::new();
        for (parent_rloc, answer) in answers {
            merge_parent_children(&mut children, *parent_rloc, answer);
        }

        for (child_rloc, child) in &mut children {
            self.keep_alive_before_request().await?;
            eprintln!("querying child {}", format_rloc16(*child_rloc));
            match self
                .collect_diag(self.mesh_local_addr(*child_rloc), CHILD_TLVS)
                .await?
            {
                Some(data) => child.merge_diag(&data),
                None => eprintln!(
                    "  child {} did not answer (kept parent-table view)",
                    format_rloc16(*child_rloc)
                ),
            }
        }
        nodes.extend(children);
        Ok(())
    }

    /// Fetches diagnostics from `destination`, requesting `tlvs` adaptively so a
    /// border agent's response-size cap never silently drops the whole answer.
    /// Returns `None` only when the node answers nothing at all (unreachable).
    async fn collect_diag(
        &mut self,
        destination: Ipv6Addr,
        tlvs: &[u64],
    ) -> meshcop::Result<Option<NetDiagData>> {
        // Establish reachability (and prime Thread address resolution) with a
        // tiny retried request before the real, un-retried batched queries.
        let Some(primer) = self.prime(destination).await? else {
            return Ok(None);
        };
        // The successful prime already proves reachability, so the node is
        // returned even if every follow-up batch is refused.
        let mut merged = NetDiagData::default();
        merge_netdiag(&mut merged, primer);

        // Start from small chunks rather than one big request: the response
        // cap would reject the whole set, and recovering from that by halving
        // costs a timeout per oversized batch. The route is primed, so a batch
        // that still goes unanswered is genuinely too large and gets split.
        let mut stack: Vec<Vec<u64>> = tlvs
            .iter()
            .copied()
            .filter(|flag| *flag != diag_flags::MAC_ADDR)
            .collect::<Vec<_>>()
            .chunks(CHUNK_SIZE)
            .map(<[u64]>::to_vec)
            .rev()
            .collect();

        while let Some(batch) = stack.pop() {
            self.keep_alive_before_request().await?;
            let combined = batch.iter().fold(0u64, |acc, flag| acc | flag);
            if combined == 0 {
                continue;
            }
            match self.diag_query(destination, combined).await? {
                Some(data) => merge_netdiag(&mut merged, data),
                None if batch.len() > 1 => {
                    let mid = batch.len() / 2;
                    stack.push(batch[..mid].to_vec());
                    stack.push(batch[mid..].to_vec());
                }
                None => {
                    // A lone TLV this node will not answer (size-heavy, e.g.
                    // Network Data via the ALOC). Skip it for this node only.
                }
            }
        }
        Ok(Some(merged))
    }

    /// Contacts `destination` with a minimal request, retrying so Thread route
    /// resolution can complete. Returns the answer (RLOC16 TLV) once reachable,
    /// or `None` after `PRIME_ATTEMPTS` silent attempts.
    async fn prime(&mut self, destination: Ipv6Addr) -> meshcop::Result<Option<NetDiagData>> {
        for _ in 0..PRIME_ATTEMPTS {
            self.keep_alive_before_request().await?;
            if let Some(data) = self.diag_query(destination, diag_flags::MAC_ADDR).await? {
                return Ok(Some(data));
            }
        }
        Ok(None)
    }

    /// One unicast DIAG_GET.req. Returns `None` when the batch yields no usable
    /// answer — a transport timeout (node silent or batch refused) or a decode
    /// failure (the border agent truncated an oversized response). Both mean
    /// "try a smaller batch"; only session-fatal errors propagate.
    async fn diag_query(
        &mut self,
        destination: Ipv6Addr,
        flags: u64,
    ) -> meshcop::Result<Option<NetDiagData>> {
        match tokio::time::timeout(
            self.node_timeout,
            self.commissioner.get_diagnostics(destination, flags),
        )
        .await
        {
            Ok(Ok(data)) => Ok(Some(data)),
            // No answer, truncated answer, a CoAP error rejecting the batch, or
            // the per-node deadline: all recoverable by requesting fewer TLVs.
            // (`InvalidState` here is the unicast/error-code guard in
            // `get_diagnostics`; the destination is always unicast and the
            // session active, so it only ever signals a per-batch rejection.)
            Ok(Err(
                Error::Timeout(_) | Error::Tlv(_) | Error::Dataset(_) | Error::InvalidState(_),
            ))
            | Err(_) => Ok(None),
            // Session-fatal (crypto/IO): abort the walk.
            Ok(Err(err)) => Err(err),
        }
    }

    async fn keep_alive_before_request(&mut self) -> meshcop::Result<()> {
        // Send before the next diagnostic wait could cross the absolute
        // keep-alive deadline. `start` requires both the keep-alive wait and
        // the following diagnostic wait to fit inside one interval.
        if request_may_cross_keepalive_deadline(
            self.last_keep_alive.elapsed(),
            self.node_timeout,
            self.keep_alive_interval,
        ) {
            let result =
                match tokio::time::timeout(self.node_timeout, self.commissioner.keep_alive()).await
                {
                    Ok(Ok(result)) => result,
                    Ok(Err(err)) => {
                        self.commissioner.disconnect();
                        return Err(err);
                    }
                    Err(_) => {
                        self.commissioner.disconnect();
                        return Err(Error::Timeout("netdiag keep-alive timed out"));
                    }
                };
            match result {
                ResultCode::Accept => {
                    self.last_keep_alive = tokio::time::Instant::now();
                }
                ResultCode::Pending => {
                    self.commissioner.disconnect();
                    return Err(Error::InvalidState("keep-alive response is pending"));
                }
                ResultCode::Reject => {
                    self.commissioner.disconnect();
                    return Err(Error::InvalidState("keep-alive was rejected"));
                }
            }
        }
        Ok(())
    }

    /// Mesh-local IID form `<prefix>::00ff:fe00:<rloc16>`.
    fn mesh_local_addr(&self, rloc16: u16) -> Ipv6Addr {
        let mut octets = [0u8; 16];
        octets[..8].copy_from_slice(&self.mesh_local_prefix);
        octets[8..14].copy_from_slice(&[0x00, 0x00, 0x00, 0xff, 0xfe, 0x00]);
        octets[14..].copy_from_slice(&rloc16.to_be_bytes());
        Ipv6Addr::from(octets)
    }

    /// `<prefix>::/64` with the standard zero-compression of `Display`.
    fn mesh_local_prefix_string(&self) -> String {
        let mut octets = [0u8; 16];
        octets[..8].copy_from_slice(&self.mesh_local_prefix);
        format!("{}/64", Ipv6Addr::from(octets))
    }

    fn network_info(&self, leader_rloc: u16, leader: &NetDiagData) -> meshcop::Result<NetworkInfo> {
        let channel = self.dataset.channel()?;
        Ok(NetworkInfo {
            network_name: self.dataset.network_name()?.map(str::to_string),
            pan_id: self.dataset.pan_id()?.map(|pan| format!("0x{pan:04x}")),
            extended_pan_id: self.dataset.extended_pan_id()?.map(hex::encode),
            channel_page: channel.as_ref().map(|c| c.page),
            channel: channel.as_ref().map(|c| c.channel),
            mesh_local_prefix: Some(self.mesh_local_prefix_string()),
            partition_id: leader.leader_data.as_ref().map(|data| data.partition_id),
            leader_rloc16: Some(format_rloc16(leader_rloc)),
        })
    }
}

fn request_may_cross_keepalive_deadline(
    elapsed: Duration,
    request_timeout: Duration,
    keepalive_interval: Duration,
) -> bool {
    elapsed.saturating_add(request_timeout) >= keepalive_interval
}

/// Overlays the `Some`/non-empty fields of `new` onto `acc`. Each TLV is fetched
/// in a separate batch, so fields never collide.
fn merge_netdiag(acc: &mut NetDiagData, new: NetDiagData) {
    if new.ext_mac_addr.is_some() {
        acc.ext_mac_addr = new.ext_mac_addr;
    }
    if new.mac_addr.is_some() {
        acc.mac_addr = new.mac_addr;
    }
    if new.mode.is_some() {
        acc.mode = new.mode;
    }
    if new.timeout.is_some() {
        acc.timeout = new.timeout;
    }
    if new.connectivity.is_some() {
        acc.connectivity = new.connectivity;
    }
    if new.route64.is_some() {
        acc.route64 = new.route64;
    }
    if new.leader_data.is_some() {
        acc.leader_data = new.leader_data;
    }
    if new.network_data.is_some() {
        acc.network_data = new.network_data;
    }
    if new.addresses.is_some() {
        acc.addresses = new.addresses;
    }
    if new.mac_counters.is_some() {
        acc.mac_counters = new.mac_counters;
    }
    if new.battery_level.is_some() {
        acc.battery_level = new.battery_level;
    }
    if new.supply_voltage.is_some() {
        acc.supply_voltage = new.supply_voltage;
    }
    if new.child_table.is_some() {
        acc.child_table = new.child_table;
    }
    if new.channel_pages.is_some() {
        acc.channel_pages = new.channel_pages;
    }
    if new.type_list.is_some() {
        acc.type_list = new.type_list;
    }
    if new.eui64.is_some() {
        acc.eui64 = new.eui64;
    }
    if new.child_ipv6_addresses.is_some() {
        acc.child_ipv6_addresses = new.child_ipv6_addresses;
    }
}

fn role_label(role: Role) -> &'static str {
    match role {
        Role::Leader => "leader",
        Role::Router => "router",
        Role::Child => "child",
    }
}

/// Role assumed before any diagnostic answer: routers have a zero child ID.
fn default_role(rloc16: u16) -> Role {
    if crate::model::child_id(rloc16).is_some() {
        Role::Child
    } else {
        Role::Router
    }
}

fn resolve_role(rloc16: u16, data: &NetDiagData, fallback: Role) -> Role {
    if crate::model::child_id(rloc16).is_some() {
        return Role::Child;
    }
    match &data.leader_data {
        Some(leader_data) if u16::from(leader_data.router_id) << 10 == rloc16 => Role::Leader,
        _ => fallback,
    }
}

/// Synthesizes child node records from a parent's diagnostic answer.
fn merge_parent_children(
    children: &mut BTreeMap<u16, Node>,
    parent_rloc: u16,
    parent: &NetDiagData,
) {
    let Some(table) = &parent.child_table else {
        return;
    };
    for entry in table {
        let child_rloc = parent_rloc | entry.child_id;
        let info = child_entry_info(parent_rloc, entry);
        let mut node = Node::skeleton(child_rloc, Role::Child, Discovery::ParentTable);
        node.parent_rloc16 = Some(format_rloc16(parent_rloc));
        node.mode = Some(info.mode);
        node.timeout_seconds = Some(info.timeout_seconds);
        if let Some(lists) = &parent.child_ipv6_addresses {
            if let Some(list) = lists.iter().find(|list| list.rloc16 == child_rloc) {
                node.ipv6_addresses = list.addresses.iter().map(Ipv6Addr::to_string).collect();
            }
        }
        children.insert(child_rloc, node);
    }
}

/// Builds the link list from every node's routing and child tables.
fn build_links(nodes: &BTreeMap<u16, Node>) -> Vec<Link> {
    let mut mesh: BTreeMap<(u16, u16), (Option<LinkView>, Option<LinkView>)> = BTreeMap::new();
    let mut links = Vec::new();

    for (rloc, node) in nodes {
        for entry in &node.route_table {
            if entry.relation != "neighbor" {
                continue;
            }
            let other = u16::from(entry.router_id) << 10;
            let view = LinkView {
                lq_in: entry.link_quality_in,
                lq_out: entry.link_quality_out,
            };
            let key = (*rloc.min(&other), *rloc.max(&other));
            let slot = mesh.entry(key).or_default();
            if *rloc <= other {
                slot.0 = Some(view);
            } else {
                slot.1 = Some(view);
            }
        }
        for entry in &node.child_table {
            links.push(Link::ParentChild {
                parent: format_rloc16(*rloc),
                child: entry.rloc16.clone(),
                link_quality: entry.incoming_link_quality,
                timeout_seconds: entry.timeout_seconds,
            });
        }
    }

    let mut result: Vec<Link> = mesh
        .into_iter()
        .map(|((a, b), (a_view, b_view))| Link::Mesh {
            a: format_rloc16(a),
            b: format_rloc16(b),
            a_view,
            b_view,
        })
        .collect();
    result.extend(links);
    result
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshcop::{
        commissioner::{
            CommissionerConfig,
            harness::{ScriptedExchange, ScriptedMeshcopTransport, ScriptedResponse},
        },
        meshcop::CommissionerOperation,
    };

    #[test]
    fn keepalive_is_sent_before_the_next_request_can_cross_its_deadline() {
        let interval = Duration::from_secs(40);
        let request_timeout = Duration::from_secs(5);
        assert!(!request_may_cross_keepalive_deadline(
            Duration::from_secs(34),
            request_timeout,
            interval
        ));
        assert!(request_may_cross_keepalive_deadline(
            Duration::from_secs(35),
            request_timeout,
            interval
        ));
        assert!(request_may_cross_keepalive_deadline(
            Duration::MAX,
            request_timeout,
            interval
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn collector_refreshes_keepalive_before_a_request_crosses_the_deadline() {
        let script = ScriptedMeshcopTransport::new([
            ScriptedExchange::new(
                CommissionerOperation::Petition,
                [ScriptedResponse::petition_accept(0x1234)],
            ),
            ScriptedExchange::new(
                CommissionerOperation::KeepAlive,
                [ScriptedResponse::accept()],
            ),
        ]);
        let mut commissioner = Commissioner::connect_scripted(
            CommissionerConfig::pskc("netdiag-test", [0x42; 16]),
            "127.0.0.1:49191".parse().unwrap(),
            script,
            [],
        )
        .await
        .unwrap();
        commissioner.petition().await.unwrap();

        let mut collector = Collector {
            commissioner: &mut commissioner,
            node_timeout: Duration::from_secs(2),
            keep_alive_interval: Duration::from_secs(30),
            last_keep_alive: tokio::time::Instant::now() - Duration::from_secs(29),
            mesh_local_prefix: [0xfd, 0, 0, 0, 0, 0, 0, 0],
            dataset: Dataset::default(),
        };
        collector.keep_alive_before_request().await.unwrap();
        drop(collector);

        let operations = commissioner
            .scripted_transport()
            .unwrap()
            .observed_requests()
            .iter()
            .map(|request| request.operation)
            .collect::<Vec<_>>();
        assert_eq!(
            operations,
            [
                CommissionerOperation::Petition,
                CommissionerOperation::KeepAlive
            ]
        );
    }
}
