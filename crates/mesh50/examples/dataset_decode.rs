use mesh50::dataset::Dataset;

#[path = "support/mod.rs"]
mod support;

fn main() -> mesh50::Result<()> {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    let show_secrets = support::show_secrets_requested(&mut args);
    let hex = args
        .into_iter()
        .next()
        .or_else(|| std::env::var("ESP_MATTER_TEST_THREAD_DATASET_HEX").ok())
        .expect("usage: dataset_decode [--show-secrets] <dataset-hex>");

    let dataset = Dataset::from_hex(hex)?;
    support::print_dataset_summary("dataset", &dataset, show_secrets)?;
    Ok(())
}
