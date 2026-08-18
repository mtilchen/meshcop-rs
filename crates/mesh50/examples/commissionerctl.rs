use std::net::SocketAddr;

use mesh50::{
    commissioner::{Commissioner, CommissionerConfig, DatasetFlags},
    dataset::Dataset,
};

#[path = "support/mod.rs"]
mod support;

#[tokio::main]
async fn main() -> mesh50::Result<()> {
    let mut raw_args = std::env::args().skip(1).collect::<Vec<_>>();
    let show_secrets = support::show_secrets_requested(&mut raw_args);
    let mut args = raw_args.into_iter();
    let Some(command) = args.next() else {
        eprintln!(
            "usage: commissionerctl [--show-secrets] <decode-dataset|connect|get-active-dataset|petition> [args...]"
        );
        std::process::exit(2);
    };

    match command.as_str() {
        "decode-dataset" => {
            let hex = args
                .next()
                .or_else(|| std::env::var("ESP_MATTER_TEST_THREAD_DATASET_HEX").ok())
                .expect("dataset hex argument or ESP_MATTER_TEST_THREAD_DATASET_HEX required");
            let dataset = Dataset::from_hex(hex)?;
            support::print_dataset_summary("dataset", &dataset, show_secrets)?;
        }
        "connect" => {
            let addr = border_agent_arg(args.next())?;
            let config = config_from_env()?;
            let commissioner = Commissioner::connect(config, addr).await?;
            println!("connected to {}", commissioner.border_agent());
        }
        "petition" => {
            require_mutation_gate("petition")?;
            let addr = border_agent_arg(args.next())?;
            let config = config_from_env()?;
            let mut commissioner = Commissioner::connect(config, addr).await?;
            let petition = commissioner.petition().await?;
            let resign_result = commissioner.resign().await;
            println!("petition accepted session_id=0x{:04x}", petition.session_id);
            resign_result?;
        }
        "get-active-dataset" => {
            let addr = border_agent_arg(args.next())?;
            let config = config_from_env()?;
            let mut commissioner = Commissioner::connect(config, addr).await?;
            commissioner.petition().await?;
            let dataset_result = commissioner.get_active_dataset(DatasetFlags::EMPTY).await;
            let resign_result = commissioner.resign().await;
            let dataset = dataset_result?;
            support::print_dataset_summary("active_dataset", &dataset, show_secrets)?;
            resign_result?;
        }
        other => {
            eprintln!("unknown command: {other}");
            std::process::exit(2);
        }
    }

    Ok(())
}

fn require_mutation_gate(command: &str) -> mesh50::Result<()> {
    if std::env::var_os("MESH50_MUTATE_OK").is_some() {
        return Ok(());
    }
    Err(mesh50::Error::InvalidState(match command {
        "petition" => "petition command requires MESH50_MUTATE_OK=1",
        _ => "mutating command requires MESH50_MUTATE_OK=1",
    }))
}

fn border_agent_arg(arg: Option<String>) -> mesh50::Result<SocketAddr> {
    let raw = arg
        .or_else(|| std::env::var("MESH50_BORDER_AGENT").ok())
        .unwrap_or_else(|| "192.168.4.48:49156".to_string());
    raw.parse().map_err(|err| {
        mesh50::Error::Dataset(format!("invalid border-agent address `{raw}`: {err}"))
    })
}

fn config_from_env() -> mesh50::Result<CommissionerConfig> {
    let dataset_hex = std::env::var("ESP_MATTER_TEST_THREAD_DATASET_HEX")
        .expect("ESP_MATTER_TEST_THREAD_DATASET_HEX must contain an active dataset with PSKc");
    let dataset = Dataset::from_hex(dataset_hex)?;
    CommissionerConfig::from_dataset("mesh50", &dataset)
}
