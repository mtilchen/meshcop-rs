//! Read-only live probe for scan and diagnostic operations.
//!
//! Exercises the asynchronous MGMT pipeline against real hardware, without
//! mutating the network or leaking secrets. It:
//!   1. connects, petitions, and computes the Leader ALOC from the configured
//!      mesh-local prefix,
//!   2. starts an energy scan on the network channel and waits for the
//!      MGMT_ED_REPORT answer,
//!   3. queries the network's own PAN ID for conflicts (no conflict is the
//!      expected outcome on a healthy network),
//!   4. requests network diagnostics from the leader and decodes the
//!      DIAG_GET.ans answer,
//!   5. starts an announce-begin on the network channel — only when
//!      `MESH50_MUTATE_OK=1`, since it makes devices transmit MLE
//!      Announce frames — and
//!   6. resigns.
//!
//! Usage:
//!   ESP_MATTER_TEST_THREAD_DATASET_HEX=<hex> \
//!   cargo run --example live_scan_diag_probe -- <host:port>
//!
//! Pass `--show-secrets` (or set `MESH50_SHOW_SECRETS`) to print
//! mesh-local addresses; they are redacted by default.

use std::net::{Ipv6Addr, SocketAddr};
use std::time::Duration;

use mesh50::{
    commissioner::{Commissioner, CommissionerConfig, CommissionerEvent},
    dataset::Dataset,
    meshcop::diag::diag_flags,
};

#[path = "support/args.rs"]
mod support;

const EVENT_TIMEOUT: Duration = Duration::from_secs(20);
const CONFLICT_TIMEOUT: Duration = Duration::from_secs(8);
const SCAN_COUNT: u8 = 1;
const SCAN_PERIOD_MS: u16 = 500;
const SCAN_DURATION_MS: u16 = 200;
const ANNOUNCE_COUNT: u8 = 1;
const ANNOUNCE_PERIOD_MS: u16 = 500;

#[tokio::main]
async fn main() -> mesh50::Result<()> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    let show_secrets = support::show_secrets_requested(&mut args);

    let border_agent: SocketAddr = args
        .into_iter()
        .next()
        .or_else(|| std::env::var("MESH50_BORDER_AGENT").ok())
        .expect("border-agent host:port argument or MESH50_BORDER_AGENT required")
        .parse()
        .expect("border-agent address must be host:port");

    let dataset_hex = std::env::var("ESP_MATTER_TEST_THREAD_DATASET_HEX")
        .expect("ESP_MATTER_TEST_THREAD_DATASET_HEX must contain an active dataset with PSKc");
    let dataset = Dataset::from_hex(dataset_hex)?;
    let config = CommissionerConfig::from_dataset("mesh50-scan", &dataset)?;

    let channel = dataset
        .channel()?
        .expect("configured dataset must contain a channel");
    let pan_id = dataset
        .pan_id()?
        .expect("configured dataset must contain a PAN ID");
    let leader_aloc = leader_aloc_from_dataset(&dataset)?;
    let channel_mask = page0_channel_mask(channel.channel);

    println!("== connecting to {border_agent} ==");
    let mut commissioner = Commissioner::connect(config, border_agent).await?;

    let probe_result = probe(
        &mut commissioner,
        leader_aloc,
        channel_mask,
        channel.channel,
        pan_id,
        show_secrets,
    )
    .await;
    let resign_result = commissioner.resign().await;
    match &probe_result {
        Ok(()) => println!("== probe succeeded; resigning =="),
        Err(err) => println!("== probe failed ({err}); resigning =="),
    }
    probe_result?;
    resign_result?;
    println!("== done ==");
    Ok(())
}

async fn probe(
    commissioner: &mut Commissioner,
    leader_aloc: Ipv6Addr,
    channel_mask: u32,
    channel: u16,
    pan_id: u16,
    show_secrets: bool,
) -> mesh50::Result<()> {
    let petition = commissioner.petition().await?;
    println!(
        "petition accepted: session_id=0x{:04x}",
        petition.session_id
    );

    println!("-- energy scan (channel {channel}, mask 0x{channel_mask:08x}) --");
    commissioner
        .energy_scan(
            channel_mask,
            SCAN_COUNT,
            SCAN_PERIOD_MS,
            SCAN_DURATION_MS,
            leader_aloc,
        )
        .await?;
    println!("energy scan accepted; waiting for MGMT_ED_REPORT.ans");
    match wait_for_event(commissioner, EVENT_TIMEOUT, |event| {
        matches!(event, CommissionerEvent::EnergyReport { .. })
    })
    .await?
    {
        Some(CommissionerEvent::EnergyReport {
            peer_addr,
            channel_mask,
            energy_list,
        }) => {
            let energy_dbm = energy_list
                .iter()
                .map(|raw| format!("{}", *raw as i8))
                .collect::<Vec<_>>()
                .join(",");
            println!(
                "energy report: peer={} mask=0x{channel_mask:08x} samples_dbm=[{energy_dbm}]",
                redact_addr(&peer_addr, show_secrets)
            );
        }
        Some(_) => unreachable!("wait_for_event only returns matching events"),
        None => println!("no energy report within {EVENT_TIMEOUT:?}"),
    }

    println!("-- PAN ID query (pan_id=0x{pan_id:04x}) --");
    commissioner
        .pan_id_query(channel_mask, pan_id, leader_aloc)
        .await?;
    println!("PAN ID query accepted; waiting for conflict reports");
    match wait_for_event(commissioner, CONFLICT_TIMEOUT, |event| {
        matches!(event, CommissionerEvent::PanIdConflict { .. })
    })
    .await?
    {
        Some(CommissionerEvent::PanIdConflict {
            peer_addr,
            channel_mask,
            pan_id,
        }) => println!(
            "PAN ID conflict: peer={} mask=0x{channel_mask:08x} pan_id=0x{pan_id:04x}",
            redact_addr(&peer_addr, show_secrets)
        ),
        Some(_) => unreachable!("wait_for_event only returns matching events"),
        None => println!(
            "no conflict reported within {CONFLICT_TIMEOUT:?} (expected on a healthy network)"
        ),
    }

    println!("-- network diagnostics (DIAG_GET to leader) --");
    let flags = diag_flags::EXT_MAC_ADDR
        | diag_flags::MAC_ADDR
        | diag_flags::MODE
        | diag_flags::ROUTE64
        | diag_flags::LEADER_DATA
        | diag_flags::IPV6_ADDRESSES
        | diag_flags::CHILD_TABLE
        | diag_flags::CONNECTIVITY
        | diag_flags::NETWORK_DATA
        | diag_flags::CHANNEL_PAGES;
    commissioner.diagnostic_get(None, flags).await?;
    println!("diagnostic get accepted; waiting for DIAG_GET.ans");
    match wait_for_event(commissioner, EVENT_TIMEOUT, |event| {
        matches!(event, CommissionerEvent::DiagnosticAnswer { .. })
    })
    .await?
    {
        Some(CommissionerEvent::DiagnosticAnswer { peer_addr, data }) => {
            println!(
                "diagnostic answer from peer={}",
                redact_addr(&peer_addr, show_secrets)
            );
            print_diag_summary(&data, show_secrets);
        }
        Some(_) => unreachable!("wait_for_event only returns matching events"),
        None => println!("no diagnostic answer within {EVENT_TIMEOUT:?}"),
    }

    // Announce-begin makes devices transmit MLE Announce frames on the masked
    // channels, so it is treated as a mutating operation and gated.
    if std::env::var_os("MESH50_MUTATE_OK").is_some_and(|value| value == "1") {
        println!("-- announce begin (channel {channel}) --");
        commissioner
            .announce_begin(
                channel_mask,
                ANNOUNCE_COUNT,
                ANNOUNCE_PERIOD_MS,
                leader_aloc,
            )
            .await?;
        println!("announce begin accepted (devices announce on channel {channel})");
    } else {
        println!("-- announce begin skipped (set MESH50_MUTATE_OK=1 to enable) --");
    }

    Ok(())
}

/// Drains commissioner events until `matches` accepts one or `timeout` lapses.
async fn wait_for_event(
    commissioner: &mut Commissioner,
    timeout: Duration,
    matches: impl Fn(&CommissionerEvent) -> bool,
) -> mesh50::Result<Option<CommissionerEvent>> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        match tokio::time::timeout(remaining, commissioner.next_event()).await {
            Ok(Ok(Some(event))) if matches(&event) => return Ok(Some(event)),
            Ok(Ok(Some(other))) => println!("  (other event: {})", event_label(&other)),
            Ok(Ok(None)) => return Ok(None),
            Ok(Err(err)) => return Err(err),
            Err(_elapsed) => return Ok(None),
        }
    }
}

fn event_label(event: &CommissionerEvent) -> &'static str {
    match event {
        CommissionerEvent::KeepAliveResponse(_) => "keep-alive response",
        CommissionerEvent::DatasetChanged => "dataset changed",
        CommissionerEvent::PanIdConflict { .. } => "PAN ID conflict",
        CommissionerEvent::EnergyReport { .. } => "energy report",
        CommissionerEvent::JoinerMessage { .. } => "joiner message",
        CommissionerEvent::DiagnosticAnswer { .. } => "diagnostic answer",
        _ => "unhandled event",
    }
}

fn print_diag_summary(data: &mesh50::meshcop::NetDiagData, show_secrets: bool) {
    if let Some(ext_mac) = &data.ext_mac_addr {
        println!("diag_ext_mac={}", hex::encode(ext_mac));
    }
    if let Some(rloc16) = data.mac_addr {
        println!("diag_rloc16=0x{rloc16:04x}");
    }
    if let Some(mode) = &data.mode {
        println!("diag_mode={mode:?}");
    }
    if let Some(leader) = &data.leader_data {
        println!(
            "diag_leader partition_id=0x{:08x} weighting={} data_version={} \
             stable_data_version={} router_id={}",
            leader.partition_id,
            leader.weighting,
            leader.data_version,
            leader.stable_data_version,
            leader.router_id
        );
    }
    if let Some(route64) = &data.route64 {
        println!(
            "diag_route64 id_sequence={} routers={}",
            route64.id_sequence,
            route64.route_data.len()
        );
    }
    if let Some(connectivity) = &data.connectivity {
        println!(
            "diag_connectivity parent_priority={} lq3={} lq2={} lq1={} leader_cost={}",
            connectivity.parent_priority,
            connectivity.link_quality_3,
            connectivity.link_quality_2,
            connectivity.link_quality_1,
            connectivity.leader_cost
        );
    }
    if let Some(addresses) = &data.addresses {
        if show_secrets {
            for address in addresses {
                println!("diag_address={address}");
            }
        } else {
            println!("diag_addresses={} (redacted)", addresses.len());
        }
    }
    if let Some(children) = &data.child_table {
        println!("diag_child_table entries={}", children.len());
        for child in children {
            println!(
                "  child_id={} timeout_s={} incoming_lq={}",
                child.child_id,
                child.timeout_seconds(),
                child.incoming_link_quality
            );
        }
    }
    if let Some(network_data) = &data.network_data {
        println!("diag_network_data prefixes={}", network_data.prefixes.len());
    }
    if let Some(pages) = &data.channel_pages {
        println!("diag_channel_pages={pages:?}");
    }
}

/// Builds the Leader ALOC (`<mesh-local-prefix>::ff:fe00:fc00`).
fn leader_aloc_from_dataset(dataset: &Dataset) -> mesh50::Result<Ipv6Addr> {
    let prefix = dataset
        .mesh_local_prefix()?
        .expect("configured dataset must contain a mesh-local prefix");
    let mut octets = [0u8; 16];
    octets[..8].copy_from_slice(&prefix);
    octets[8..].copy_from_slice(&[0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0xfc, 0x00]);
    Ok(Ipv6Addr::from(octets))
}

/// Page-0 channel mask bit for `channel` (`0x80 >> (channel % 8)` in byte
/// `channel / 8` of the big-endian mask).
fn page0_channel_mask(channel: u16) -> u32 {
    assert!(channel <= 31, "page-0 channels fit in a 32-bit mask");
    1u32 << (31 - channel)
}

fn redact_addr(addr: &str, show_secrets: bool) -> String {
    if show_secrets {
        addr.to_string()
    } else {
        "<redacted>".to_string()
    }
}
