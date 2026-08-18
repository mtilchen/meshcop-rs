//! The `ot-commissioner-rs` interactive CLI binary: a faithful reimplementation
//! of the C++ `ot-commissioner` command-line REPL on top of MeshCoP for Rust.
//! The full command surface lives in [`crate::cli`].
//!
//! ```text
//! ot-commissioner-rs -h|--help
//! ot-commissioner-rs -v|--version
//! ot-commissioner-rs [-r|--registry <registryFileName>] [-c|--config <configFileName>]
//! ot-commissioner-rs [-r|--registry <registryFileName>] [configFileName]
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// `unwrap`/`expect` are prohibited in production code (allowed in tests via
// `allow-{unwrap,expect}-in-tests` in `clippy.toml`). `cargo clippy -- -D
// warnings` promotes these to hard errors.
#![warn(clippy::unwrap_used, clippy::expect_used)]

use std::process::ExitCode;

mod cli;

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let program = args
        .first()
        .map(String::as_str)
        .unwrap_or("ot-commissioner-rs")
        .to_string();

    match cli::parse_invocation(args.get(1..).unwrap_or(&[])) {
        cli::CliInvocation::Usage => {
            cli::print_usage(&program);
            ExitCode::SUCCESS
        }
        cli::CliInvocation::Version => {
            cli::print_version();
            ExitCode::SUCCESS
        }
        cli::CliInvocation::UsageError => {
            cli::print_usage(&program);
            ExitCode::FAILURE
        }
        cli::CliInvocation::Run(config_path) => {
            cli::print_logo();
            match cli::run(config_path.as_deref()).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => ExitCode::FAILURE,
            }
        }
    }
}
