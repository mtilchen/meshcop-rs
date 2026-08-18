//! Live interop test against a real OpenThread border agent.
//!
//! `tools/ci/interop.sh` builds OpenThread (a posix `ot-daemon` border router
//! driven by a simulated RCP), forms a Thread network, and runs this test
//! against the daemon's border agent over loopback. The script provides:
//!
//! - `MESH50_INTEROP_BORDER_AGENT` — `host:port` of the live agent.
//! - `MESH50_INTEROP_DATASET_HEX` — the active dataset reported by
//!   `ot-ctl dataset active -x`, including the PSKc used to authenticate.
//!
//! The dataset for this network is disposable CI test data (the fixed vectors
//! from the C++ `ot-commissioner` integration suite), but the test still never
//! prints TLV values on failure — only types and lengths — so it stays safe to
//! run against a private network by hand.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use mesh50::{
    commissioner::{
        Commissioner, CommissionerConfig, CommissionerDatasetFlags, CommissionerEvent,
        DatasetFlags, ResultCode, StaticJoinerHandler,
    },
    dataset::Dataset,
    error::Error,
    meshcop::{TLV_BORDER_AGENT_LOCATOR, TLV_COMMISSIONER_SESSION_ID},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

#[tokio::test]
#[ignore = "requires a live OpenThread border agent; run via tools/ci/interop.sh"]
async fn interop_commissioner_session_against_openthread() -> mesh50::Result<()> {
    let border_agent: SocketAddr = std::env::var("MESH50_INTEROP_BORDER_AGENT")
        .expect("MESH50_INTEROP_BORDER_AGENT must be host:port")
        .parse()
        .expect("MESH50_INTEROP_BORDER_AGENT must parse as a socket address");
    let dataset_hex = std::env::var("MESH50_INTEROP_DATASET_HEX")
        .expect("MESH50_INTEROP_DATASET_HEX must contain the active dataset with PSKc");

    let expected = Dataset::from_hex(dataset_hex)?;
    let config = CommissionerConfig::from_dataset("mesh50-interop", &expected)?;

    // DTLS 1.2 + EC J-PAKE handshake authenticated with the network PSKc.
    let mut commissioner = Commissioner::connect(config, border_agent).await?;

    // COMM_PET.req: become the active commissioner.
    let petition = commissioner.petition().await?;
    assert_ne!(petition.session_id, 0, "petition returned session id 0");

    // Run the session body without `?` so the commissioner always resigns,
    // leaving the agent free for the next run even when an assertion fails.
    let session = exercise_session(&mut commissioner, &expected).await;
    let resign = commissioner.resign().await;
    session?;
    resign
}

async fn exercise_session(
    commissioner: &mut Commissioner,
    expected: &Dataset,
) -> mesh50::Result<()> {
    // COMM_KA.req on the established session.
    assert_eq!(
        commissioner.keep_alive().await?,
        ResultCode::Accept,
        "keep-alive was rejected"
    );

    // MGMT_ACTIVE_GET.req directly to the border agent: the live network's
    // dataset must match what ot-ctl reported, independent of TLV order.
    let live = Dataset::from_bytes(
        &commissioner
            .get_raw_active_dataset(DatasetFlags::EMPTY)
            .await?,
    )?;
    assert_datasets_equivalent(expected, &live)?;

    // MGMT_COMMISSIONER_GET.req: routed through the UDP_TX/UDP_RX proxy to
    // the leader ALOC, which exercises the mesh-local-prefix fetch and the
    // encapsulation path against a real leader.
    let commissioner_dataset = commissioner
        .get_commissioner_dataset(CommissionerDatasetFlags::EMPTY)
        .await?;
    for (name, ty) in [
        ("Border Agent Locator", TLV_BORDER_AGENT_LOCATOR),
        ("Commissioner Session ID", TLV_COMMISSIONER_SESSION_ID),
    ] {
        assert!(
            commissioner_dataset
                .entries()
                .iter()
                .any(|entry| entry.ty == ty),
            "commissioner dataset is missing the {name} TLV"
        );
    }
    Ok(())
}

/// Factory EUI-64 of OpenThread simulation node 2 (`ot-cli-ftd 2`), the same
/// joiner identity the C++ `ot-commissioner` integration suite uses.
const JOINER_EUI64: u64 = 0x18b4_3000_0000_0002;
/// Joining credential shared between the commissioner and the joiner node.
const JOINER_PSKD: &str = "J01NME";
/// How long the joiner gets to scan, complete DTLS + JOIN_FIN, and be
/// entrusted before the test gives up.
const JOIN_DEADLINE: Duration = Duration::from_secs(90);

#[tokio::test]
#[ignore = "requires a live OpenThread border agent; run via tools/ci/interop.sh"]
async fn interop_joiner_commissioning_against_openthread() -> mesh50::Result<()> {
    let border_agent: SocketAddr = std::env::var("MESH50_INTEROP_BORDER_AGENT")
        .expect("MESH50_INTEROP_BORDER_AGENT must be host:port")
        .parse()
        .expect("MESH50_INTEROP_BORDER_AGENT must parse as a socket address");
    let dataset_hex = std::env::var("MESH50_INTEROP_DATASET_HEX")
        .expect("MESH50_INTEROP_DATASET_HEX must contain the active dataset with PSKc");
    let joiner_cli = PathBuf::from(
        std::env::var("MESH50_INTEROP_JOINER_CLI")
            .expect("MESH50_INTEROP_JOINER_CLI must point at a simulation ot-cli-ftd"),
    );

    let expected = Dataset::from_hex(dataset_hex)?;
    let channel = expected
        .channel()?
        .expect("the interop network dataset always carries a channel")
        .channel;
    let config = CommissionerConfig::from_dataset("mesh50-interop", &expected)?;

    let mut commissioner = Commissioner::connect(config, border_agent).await?;
    let petition = commissioner.petition().await?;
    assert_ne!(petition.session_id, 0, "petition returned session id 0");

    // The handler authenticates the joiner's DTLS session with its PSKd and
    // approves its JOIN_FIN; enabling by EUI-64 exercises the SHA-256 joiner
    // ID derivation and the steering-data Bloom filter against OpenThread's
    // own computation of both.
    let mut handler = StaticJoinerHandler::new();
    handler.enable_eui64(JOINER_EUI64, JOINER_PSKD);
    commissioner.set_joiner_handler(handler);

    let session = commission_joiner(&mut commissioner, &joiner_cli, channel).await;
    let resign = commissioner.resign().await;
    session?;
    resign
}

async fn commission_joiner(
    commissioner: &mut Commissioner,
    joiner_cli: &std::path::Path,
    channel: u16,
) -> mesh50::Result<()> {
    let joiner_id = mesh50::crypto::compute_joiner_id(JOINER_EUI64);
    // MGMT_COMMISSIONER_SET: advertise the joiner in the steering data so it
    // can discover the network.
    commissioner.enable_joiner(&joiner_id).await?;

    let mut joiner = JoinerCli::spawn(joiner_cli, 2)?;
    joiner.command("ifconfig up").await?;
    joiner.command(&format!("channel {channel}")).await?;
    joiner
        .command(&format!("joiner start {JOINER_PSKD}"))
        .await?;

    // Drive the joiner to completion in the background while this task keeps
    // pumping commissioner events: every RLY_RX hop of the joiner's DTLS
    // handshake, the JOIN_FIN exchange, and the KEK hand-off to the joiner
    // router are serviced inside `next_event`.
    let mut driver = tokio::spawn(async move {
        joiner.wait_for_line("Join success", "Join failed").await?;
        joiner.command("thread start").await?;
        joiner.wait_for_attach().await?;
        Ok::<(), Error>(())
    });

    let deadline = tokio::time::Instant::now() + JOIN_DEADLINE;
    let mut connected = false;
    let mut finalized = false;
    let mut joined = false;
    while !(finalized && joined) {
        if tokio::time::Instant::now() >= deadline {
            return Err(Error::InvalidState(if !connected {
                "joiner never reached the commissioner over the relay"
            } else if !finalized {
                "joiner connected but JOIN_FIN never completed"
            } else {
                "joiner was entrusted but never attached to the network"
            }));
        }
        tokio::select! {
            result = &mut driver, if !joined => {
                result.map_err(|err| {
                    Error::InvalidState(if err.is_panic() {
                        "the joiner driver task panicked"
                    } else {
                        "the joiner driver task was cancelled"
                    })
                })??;
                joined = true;
            }
            event = tokio::time::timeout(Duration::from_secs(2), commissioner.next_event()) => {
                match event {
                    // No traffic in this poll tick; check the deadline again.
                    Err(_elapsed) => {}
                    Ok(event) => match event? {
                        Some(CommissionerEvent::JoinerConnected { joiner_id: id }) => {
                            assert_eq!(id, joiner_id, "an unexpected joiner connected");
                            connected = true;
                        }
                        Some(CommissionerEvent::JoinerFinalized {
                            joiner_id: id,
                            accepted,
                            info,
                        }) => {
                            assert_eq!(id, joiner_id, "an unexpected joiner finalized");
                            assert!(accepted, "the joiner's JOIN_FIN was rejected");
                            assert!(
                                !info.vendor_name.is_empty(),
                                "JOIN_FIN carried no vendor name"
                            );
                            println!(
                                "joiner finalized: vendor {} {} ({})",
                                info.vendor_name, info.vendor_model, info.vendor_sw_version
                            );
                            finalized = true;
                        }
                        _ => {}
                    },
                }
            }
        }
    }
    Ok(())
}

/// A simulated OpenThread joiner node driven over its CLI pipe.
///
/// Output framing (verified against the simulation CLI): lines end with
/// `\r\n`, commands echo behind a `> ` prompt, and every command terminates
/// with `Done` or `Error ...`. Joining completes asynchronously with a later
/// `Join success` / `Join failed` line.
struct JoinerCli {
    stdin: ChildStdin,
    lines: Lines<BufReader<ChildStdout>>,
    _child: Child,
}

impl JoinerCli {
    /// Spawns `ot-cli-ftd <node_id>` in a fresh scratch directory so stale
    /// simulated-flash state from earlier runs cannot leak in.
    fn spawn(binary: &std::path::Path, node_id: u32) -> mesh50::Result<Self> {
        let scratch = std::env::temp_dir().join(format!(
            "ot-rs-interop-joiner-{}-{node_id}",
            std::process::id()
        ));
        if scratch.exists() {
            std::fs::remove_dir_all(&scratch)?;
        }
        // The simulation platform keeps its flash files under ./tmp.
        std::fs::create_dir_all(scratch.join("tmp"))?;

        let mut child = Command::new(binary)
            .arg(node_id.to_string())
            .current_dir(&scratch)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let stdin = child.stdin.take().expect("joiner stdin is piped");
        let stdout = child.stdout.take().expect("joiner stdout is piped");
        Ok(Self {
            stdin,
            lines: BufReader::new(stdout).lines(),
            _child: child,
        })
    }

    /// Sends one CLI command and consumes lines through its `Done`.
    async fn command(&mut self, command: &str) -> mesh50::Result<()> {
        self.stdin.write_all(command.as_bytes()).await?;
        self.stdin.write_all(b"\n").await?;
        self.stdin.flush().await?;
        self.wait_for_line("Done", "Error").await
    }

    /// Reads lines until one contains `success` (Ok) or `failure` (Err).
    async fn wait_for_line(&mut self, success: &str, failure: &str) -> mesh50::Result<()> {
        loop {
            let line = tokio::time::timeout(JOIN_DEADLINE, self.lines.next_line())
                .await
                .map_err(|_| Error::Timeout("the joiner CLI went quiet"))??
                .ok_or(Error::InvalidState("the joiner CLI exited unexpectedly"))?;
            if line.contains(success) {
                return Ok(());
            }
            if line.contains(failure) {
                println!("joiner CLI reported: {}", line.trim());
                return Err(Error::InvalidState("the joiner CLI reported a failure"));
            }
        }
    }

    /// Polls `state` until the node attaches as child, router, or leader.
    async fn wait_for_attach(&mut self) -> mesh50::Result<()> {
        const ATTACH_ATTEMPTS: u32 = 30;
        for _ in 0..ATTACH_ATTEMPTS {
            self.stdin.write_all(b"state\n").await?;
            self.stdin.flush().await?;
            loop {
                let line = tokio::time::timeout(Duration::from_secs(10), self.lines.next_line())
                    .await
                    .map_err(|_| Error::Timeout("the joiner CLI went quiet"))??
                    .ok_or(Error::InvalidState("the joiner CLI exited unexpectedly"))?;
                let line = line.trim();
                if ["child", "router", "leader"]
                    .iter()
                    .any(|role| line.ends_with(role))
                {
                    return Ok(());
                }
                if line.contains("Done") {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        Err(Error::Timeout(
            "the joiner never attached to the Thread network",
        ))
    }
}

/// Compares two datasets as unordered TLV sets, reporting only TLV types and
/// lengths on mismatch so dataset values never reach the logs.
fn assert_datasets_equivalent(expected: &Dataset, live: &Dataset) -> mesh50::Result<()> {
    let canonical = |dataset: &Dataset| -> BTreeSet<(u8, Vec<u8>)> {
        dataset
            .entries()
            .iter()
            .map(|entry| (entry.ty, entry.value.to_vec()))
            .collect()
    };
    if canonical(expected) != canonical(live) {
        return Err(Error::Dataset(format!(
            "active dataset mismatch: expected {}, live {}",
            dataset_summary(expected),
            dataset_summary(live)
        )));
    }
    Ok(())
}

fn dataset_summary(dataset: &Dataset) -> String {
    let type_lengths = dataset
        .entries()
        .iter()
        .map(|entry| format!("0x{:02x}:{}", entry.ty, entry.value.len()))
        .collect::<Vec<_>>()
        .join(",");
    format!("tlvs=[{type_lengths}]")
}
