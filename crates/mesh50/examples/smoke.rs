use std::net::SocketAddr;

use mesh50::{
    commissioner::{Commissioner, CommissionerConfig, DatasetFlags},
    dataset::Dataset,
};

#[path = "support/mod.rs"]
mod support;

#[tokio::main]
async fn main() -> mesh50::Result<()> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    let show_secrets = support::show_secrets_requested(&mut args);
    let dataset_hex = std::env::var("ESP_MATTER_TEST_THREAD_DATASET_HEX")
        .expect("ESP_MATTER_TEST_THREAD_DATASET_HEX must contain an active dataset with PSKc");
    let border_agent: SocketAddr = std::env::var("MESH50_BORDER_AGENT")
        .unwrap_or_else(|_| "192.168.4.48:49156".to_string())
        .parse()
        .expect("MESH50_BORDER_AGENT must be host:port");

    let dataset = Dataset::from_hex(dataset_hex)?;
    let config = CommissionerConfig::from_dataset("mesh50-smoke", &dataset)?;
    let mut commissioner = Commissioner::connect(config, border_agent).await?;

    commissioner.petition().await?;
    let smoke_result = async {
        commissioner.keep_alive().await?;
        let active = commissioner.get_active_dataset(DatasetFlags::EMPTY).await?;
        support::print_dataset_summary("active_dataset", &active, show_secrets)?;
        let pending = commissioner
            .get_pending_dataset(DatasetFlags::EMPTY)
            .await?;
        support::print_dataset_summary("pending_dataset", &pending, show_secrets)?;
        Ok::<(), mesh50::Error>(())
    }
    .await;
    let resign_result = commissioner.resign().await;
    smoke_result?;
    resign_result
}
