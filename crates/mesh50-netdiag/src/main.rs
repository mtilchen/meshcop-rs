//! Mesh Five-O network diagnostics (`mesh50-netdiag`) for Thread.
//!
//! Connects to a Thread network through a border agent (PSKc commissioner
//! authentication), then walks the mesh with MeshCoP network-diagnostic
//! queries (`DIAG_GET`) routed through the UDP proxy. It can emit a serialized
//! topology (JSON) or render it as a markdown report or an ASCII graph, and it
//! can fetch a single node's diagnostics on demand.
//!
//! ```text
//! mesh50-netdiag --border-agent 192.0.2.1:49154 --pskc <32-hex> topology --format markdown
//! mesh50-netdiag --border-agent 192.0.2.1:49154 --pskc <32-hex> node --rloc16 0xa400 --format json
//! ```
//!
//! The tool is strictly read-only: it never writes datasets or mutates the
//! network. It always resigns the commissioner session before exiting.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::unwrap_used, clippy::expect_used)]

use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

use argh::FromArgs;
use mesh50::{
    commissioner::{Commissioner, CommissionerConfig},
    error::Error,
};

mod collect;
mod graph;
mod model;
mod report;
#[cfg(test)]
mod test_fixtures;

use collect::Collector;

const DEFAULT_COMMISSIONER_ID: &str = "mesh50-netdiag";
const DEFAULT_NODE_TIMEOUT_SECS: u64 = 2;

/// Environment variable holding the PSKc, preferred over `--pskc` so the
/// credential never lands in the process table or shell history.
const PSKC_ENV: &str = "NETDIAG_PSKC";

/// Map and report Thread network diagnostics through a border agent.
#[derive(FromArgs)]
struct Args {
    /// border agent socket address, `host:port`
    #[argh(option, short = 'b')]
    border_agent: String,

    /// PSKc as 32 hex characters; prefer the NETDIAG_PSKC env var so the
    /// credential is not exposed on the command line
    #[argh(option)]
    pskc: Option<String>,

    /// commissioner ID string sent in the petition
    #[argh(option, default = "DEFAULT_COMMISSIONER_ID.to_string()")]
    commissioner_id: String,

    /// per-node diagnostic answer timeout, in seconds
    #[argh(option, default = "DEFAULT_NODE_TIMEOUT_SECS")]
    node_timeout: u64,

    /// print sensitive fields (extended PAN ID, mesh-local prefix, IPv6
    /// addresses); redacted by default. Also honored via MESH50_SHOW_SECRETS
    #[argh(switch)]
    show_secrets: bool,

    #[argh(subcommand)]
    command: Command,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum Command {
    Topology(TopologyCmd),
    Node(NodeCmd),
}

/// Walk the whole network and emit its topology.
#[derive(FromArgs)]
#[argh(subcommand, name = "topology")]
struct TopologyCmd {
    /// output format: `json`, `markdown`, or `graph` (default `json`)
    #[argh(option, short = 'f', default = "OutputFormat::Json")]
    format: OutputFormat,

    /// pretty-print JSON output
    #[argh(switch)]
    pretty: bool,
}

/// Fetch diagnostics for one node by RLOC16.
#[derive(FromArgs)]
#[argh(subcommand, name = "node")]
struct NodeCmd {
    /// target RLOC16, e.g. `0xa400` or `41984`
    #[argh(option, short = 'r')]
    rloc16: String,

    /// output format: `json` or `markdown` (default `json`)
    #[argh(option, short = 'f', default = "OutputFormat::Json")]
    format: OutputFormat,

    /// pretty-print JSON output
    #[argh(switch)]
    pretty: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Json,
    Markdown,
    Graph,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "markdown" | "md" => Ok(Self::Markdown),
            "graph" | "ascii" => Ok(Self::Graph),
            other => Err(format!(
                "unknown format `{other}` (expected json, markdown, or graph)"
            )),
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Args = argh::from_env();
    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> mesh50::Result<()> {
    let border_agent: SocketAddr = args.border_agent.parse().map_err(|_| {
        Error::Dataset(format!(
            "invalid border-agent address `{}`",
            args.border_agent
        ))
    })?;
    let pskc = resolve_pskc(args.pskc.as_deref())?;
    let node_timeout = Duration::from_secs(args.node_timeout.max(1));
    let show_secrets = args.show_secrets || std::env::var_os("MESH50_SHOW_SECRETS").is_some();

    let config = CommissionerConfig::pskc(args.commissioner_id, pskc);
    eprintln!("connecting to {border_agent}");
    let mut commissioner = Commissioner::connect(config, border_agent).await?;

    let result = dispatch(
        &mut commissioner,
        &args.command,
        node_timeout,
        &args.border_agent,
        show_secrets,
    )
    .await;
    let resign = commissioner.resign().await;
    let output = result?;
    resign?;
    print!("{output}");
    Ok(())
}

async fn dispatch(
    commissioner: &mut Commissioner,
    command: &Command,
    node_timeout: Duration,
    border_agent: &str,
    show_secrets: bool,
) -> mesh50::Result<String> {
    let mut collector = Collector::start(commissioner, node_timeout).await?;
    match command {
        Command::Topology(cmd) => {
            let mut snapshot = collector.collect_topology(border_agent.to_string()).await?;
            if !show_secrets {
                snapshot.redact_secrets();
            }
            render_topology(&snapshot, cmd.format, cmd.pretty)
        }
        Command::Node(cmd) => {
            let rloc16 = parse_rloc16(&cmd.rloc16)?;
            let mut node = collector.collect_node(rloc16).await?;
            if !show_secrets {
                node.redact_secrets();
            }
            render_node(&node, cmd.format, cmd.pretty)
        }
    }
}

fn render_topology(
    snapshot: &model::TopologySnapshot,
    format: OutputFormat,
    pretty: bool,
) -> mesh50::Result<String> {
    match format {
        OutputFormat::Json => json(snapshot, pretty),
        OutputFormat::Markdown => Ok(report::topology_markdown(snapshot)),
        OutputFormat::Graph => Ok(graph::topology_ascii(snapshot)),
    }
}

fn render_node(node: &model::Node, format: OutputFormat, pretty: bool) -> mesh50::Result<String> {
    match format {
        OutputFormat::Json => json(node, pretty),
        OutputFormat::Markdown | OutputFormat::Graph => Ok(report::node_report_markdown(node)),
    }
}

fn json<T: serde::Serialize>(value: &T, pretty: bool) -> mesh50::Result<String> {
    let serialized = if pretty {
        serde_json::to_string_pretty(value)
    } else {
        serde_json::to_string(value)
    }
    .map_err(|err| Error::Dataset(format!("failed to serialize output: {err}")))?;
    Ok(format!("{serialized}\n"))
}

/// Resolves the PSKc, preferring the `NETDIAG_PSKC` env var over `--pskc`.
fn resolve_pskc(pskc_arg: Option<&str>) -> mesh50::Result<[u8; 16]> {
    let hex_str = std::env::var(PSKC_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| pskc_arg.map(str::to_string))
        .ok_or_else(|| {
            Error::Dataset(format!(
                "PSKc required: set the {PSKC_ENV} env var (preferred) or pass --pskc"
            ))
        })?;
    let bytes = hex::decode(hex_str.trim())
        .map_err(|err| Error::Dataset(format!("PSKc must be valid hex: {err}")))?;
    bytes
        .try_into()
        .map_err(|_| Error::Dataset("PSKc must be exactly 16 bytes (32 hex chars)".to_string()))
}

fn parse_rloc16(value: &str) -> mesh50::Result<u16> {
    let trimmed = value.trim();
    let parsed = if let Some(hex_digits) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u16::from_str_radix(hex_digits, 16)
    } else {
        trimmed.parse::<u16>()
    };
    parsed.map_err(|_| Error::Dataset(format!("invalid RLOC16 `{value}`")))
}
