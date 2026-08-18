//! Read-only live functional probe against a real Thread border agent.
//!
//! Exercises the core commissioner path plus the newer UDP-proxy / ALOC
//! routing against real hardware, without mutating the network or leaking
//! secrets. It:
//!   1. connects and runs the DTLS EC J-PAKE handshake,
//!   2. petitions to become the active commissioner,
//!   3. sends a keep-alive,
//!   4. reads the active dataset and compares it to the configured one,
//!   5. reads the commissioner dataset through the UDP proxy (Leader ALOC,
//!      which first fetches and caches the mesh-local prefix), and
//!   6. resigns.
//!
//! Usage:
//!   ESP_MATTER_TEST_THREAD_DATASET_HEX=<hex> \
//!   MESH50_BORDER_AGENT=host:port \
//!   cargo run --example live_parity_probe
//!
//! Pass `--show-secrets` (or set `MESH50_SHOW_SECRETS`) to print
//! sensitive dataset TLVs; they are redacted by default.

use std::net::SocketAddr;

use mesh50::{
    commissioner::{
        Commissioner, CommissionerConfig, CommissionerDatasetFlags, DatasetFlags, ResultCode,
    },
    dataset::Dataset,
};

#[path = "support/mod.rs"]
mod support;

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
    let expected = Dataset::from_hex(dataset_hex)?;
    let config = CommissionerConfig::from_dataset("mesh50-probe", &expected)?;

    println!("== connecting to {border_agent} ==");
    let mut commissioner = Commissioner::connect(config, border_agent).await?;

    // All steps after a successful petition run inside `probe` so a failure
    // still resigns the session before returning.
    let probe_result = probe(&mut commissioner, &expected, show_secrets).await;
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
    expected: &Dataset,
    show_secrets: bool,
) -> mesh50::Result<()> {
    let petition = commissioner.petition().await?;
    println!(
        "petition accepted: session_id=0x{:04x}",
        petition.session_id
    );
    if let Some(existing) = &petition.existing_commissioner_id {
        println!("  (border agent reported existing commissioner: {existing})");
    }

    let keep_alive = commissioner.keep_alive().await?;
    println!("keep-alive: {}", result_code_label(keep_alive));

    let live = commissioner.get_active_dataset(DatasetFlags::ALL).await?;
    println!("-- live active dataset --");
    support::print_dataset_summary("active", &live, show_secrets)?;
    if live == *expected {
        println!("active dataset MATCHES the configured dataset");
    } else {
        println!(
            "active dataset DIFFERS from the configured dataset (live tlvs={}, configured tlvs={})",
            live.entries().len(),
            expected.entries().len()
        );
    }

    // This read goes through the UDP proxy to the Leader ALOC, which first
    // fetches and caches the mesh-local prefix from the active dataset.
    match commissioner
        .get_commissioner_dataset(CommissionerDatasetFlags::ALL)
        .await
    {
        Ok(commissioner_dataset) => {
            println!("-- commissioner dataset (via UDP proxy to Leader ALOC) --");
            support::print_dataset_summary("commissioner", &commissioner_dataset, show_secrets)?;
        }
        Err(err) => println!("commissioner dataset read failed: {err}"),
    }

    Ok(())
}

fn result_code_label(code: ResultCode) -> &'static str {
    match code {
        ResultCode::Accept => "Accept",
        ResultCode::Pending => "Pending",
        ResultCode::Reject => "Reject",
    }
}
