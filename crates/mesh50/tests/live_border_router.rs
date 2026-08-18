use std::net::SocketAddr;

use mesh50::{
    commissioner::{Commissioner, CommissionerConfig, DatasetFlags},
    dataset::Dataset,
    error::Error,
};

#[tokio::test]
#[ignore = "requires a Thread border agent at 192.168.4.48:49156 and ESP_MATTER_TEST_THREAD_DATASET_HEX"]
async fn live_border_router_read_only_smoke() -> mesh50::Result<()> {
    let dataset_hex = std::env::var("ESP_MATTER_TEST_THREAD_DATASET_HEX")
        .expect("ESP_MATTER_TEST_THREAD_DATASET_HEX must contain a dataset with PSKc");
    let border_agent: SocketAddr = std::env::var("MESH50_BORDER_AGENT")
        .unwrap_or_else(|_| "192.168.4.48:49156".to_string())
        .parse()
        .expect("MESH50_BORDER_AGENT must be host:port");

    let dataset = Dataset::from_hex(dataset_hex)?;
    let config = CommissionerConfig::from_dataset("mesh50-live", &dataset)?;
    let mut commissioner = Commissioner::connect(config, border_agent).await?;

    let petition = commissioner.petition().await?;
    assert!(petition.session_id != 0);
    let read_result = async {
        assert_eq!(
            commissioner.keep_alive().await?,
            mesh50::commissioner::ResultCode::Accept
        );
        let active = commissioner
            .get_active_dataset(DatasetFlags::ACTIVE_TIMESTAMP | DatasetFlags::NETWORK_NAME)
            .await?;
        assert!(active.network_name()?.is_some());
        Ok::<(), mesh50::Error>(())
    }
    .await;
    let resign_result = commissioner.resign().await;
    read_result?;
    resign_result
}

#[tokio::test]
#[ignore = "requires a Thread border agent at 192.168.4.48:49156 and ESP_MATTER_TEST_THREAD_DATASET_HEX"]
async fn live_border_router_active_dataset_matches_env() -> mesh50::Result<()> {
    let dataset_hex = std::env::var("ESP_MATTER_TEST_THREAD_DATASET_HEX")
        .expect("ESP_MATTER_TEST_THREAD_DATASET_HEX must contain a dataset with PSKc");
    let border_agent: SocketAddr = std::env::var("MESH50_BORDER_AGENT")
        .unwrap_or_else(|_| "192.168.4.48:49156".to_string())
        .parse()
        .expect("MESH50_BORDER_AGENT must be host:port");

    let expected = Dataset::from_hex(dataset_hex)?;
    let config = CommissionerConfig::from_dataset("mesh50-compare", &expected)?;
    let mut commissioner = Commissioner::connect(config, border_agent).await?;

    let petition = commissioner.petition().await?;
    assert!(petition.session_id != 0);
    let live_bytes = commissioner
        .get_raw_active_dataset(DatasetFlags::EMPTY)
        .await;
    let resign_result = commissioner.resign().await;
    let live = Dataset::from_bytes(&live_bytes?)?;

    if live != expected {
        return Err(Error::Dataset(format!(
            "active dataset mismatch: env {}, live {}",
            dataset_summary(&expected)?,
            dataset_summary(&live)?
        )));
    }

    resign_result
}

fn dataset_summary(dataset: &Dataset) -> mesh50::Result<String> {
    let type_lengths = dataset
        .entries()
        .iter()
        .map(|entry| format!("0x{:02x}:{}", entry.ty, entry.value.len()))
        .collect::<Vec<_>>()
        .join(",");
    Ok(format!(
        "encoded_len={} tlvs=[{}]",
        dataset.to_bytes()?.len(),
        type_lengths
    ))
}
