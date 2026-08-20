//! Live interop test against a real OpenThread border agent.
//!
//! `tools/ci/interop.sh` builds OpenThread (a posix `ot-daemon` border router
//! driven by a simulated RCP), forms a Thread network, and runs this test
//! against the daemon's border agent over loopback. The script provides:
//!
//! - `MESHCOP_INTEROP_BORDER_AGENT` — `host:port` of the live agent.
//! - `MESHCOP_INTEROP_DATASET_HEX` — the active dataset reported by
//!   `ot-ctl dataset active -x`, including the PSKc used to authenticate.
//! - `MESHCOP_INTEROP_JOINER_CLI` — a simulated OpenThread FTD used as a
//!   real joiner peer.
//! - `MESHCOP_MUTATE_OK=1` — explicit authorization for the joiner test to
//!   update steering data on the disposable network.
//!
//! A protocol-aware loopback UDP fault proxy also drops one datagram from each
//! DTLS handshake flight position and the first confirmable CoAP
//! request/response once, proving recovery against the live OpenThread
//! implementation rather than only the in-process peer.
//!
//! The dataset for this network is disposable CI test data (the fixed vectors
//! from the C++ `ot-commissioner` integration suite), but the test still never
//! prints TLV values on failure — only types and lengths — so it stays safe to
//! run against a private network by hand.

use std::collections::BTreeSet;
use std::net::{Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use meshcop::{
    commissioner::{
        Commissioner, CommissionerConfig, CommissionerDatasetFlags, CommissionerEvent,
        CommissionerState, DatasetFlags, PetitionResponse, ResultCode, StaticJoinerHandler,
    },
    dataset::Dataset,
    error::Error,
    meshcop::{
        TLV_BORDER_AGENT_LOCATOR, TLV_COMMISSIONER_SESSION_ID,
        diag::{NetDiagData, diag_flags},
    },
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::net::UdpSocket;
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

#[tokio::test]
#[ignore = "requires a live OpenThread border agent; run via tools/ci/interop.sh"]
async fn interop_commissioner_session_against_openthread() -> meshcop::Result<()> {
    let (border_agent, expected) = interop_inputs()?;
    let config = CommissionerConfig::from_dataset("meshcop-session", &expected)?;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FaultTarget {
    InitialClientHello,
    HelloVerifyRequest,
    CookieClientHello,
    ServerHandshake,
    ClientFinished,
    ServerFinished,
    PetitionRequest,
    PetitionResponse,
}

#[tokio::test]
#[ignore = "requires a live OpenThread border agent; run via tools/ci/interop.sh"]
async fn interop_packet_loss_recovery_against_openthread() -> meshcop::Result<()> {
    let (border_agent, expected) = interop_inputs()?;
    for target in [
        FaultTarget::InitialClientHello,
        FaultTarget::HelloVerifyRequest,
        FaultTarget::CookieClientHello,
        FaultTarget::ServerHandshake,
        FaultTarget::ClientFinished,
        FaultTarget::ServerFinished,
        FaultTarget::PetitionRequest,
        FaultTarget::PetitionResponse,
    ] {
        run_packet_loss_case(border_agent, &expected, target).await?;
    }
    Ok(())
}

async fn run_packet_loss_case(
    border_agent: SocketAddr,
    dataset: &Dataset,
    target: FaultTarget,
) -> meshcop::Result<()> {
    let proxy = UdpSocket::bind("[::1]:0").await?;
    let proxy_addr = proxy.local_addr()?;
    let dropped = Arc::new(AtomicBool::new(false));
    let proxy_dropped = Arc::clone(&dropped);
    let proxy_task =
        tokio::spawn(
            async move { run_fault_proxy(proxy, border_agent, target, proxy_dropped).await },
        );

    let config = CommissionerConfig::from_dataset("meshcop-loss", dataset)?;
    let mut commissioner = Commissioner::connect(config, proxy_addr).await?;
    let petition = commissioner.petition().await;
    let resign = resign_if_active(&mut commissioner).await;
    proxy_task.abort();
    match proxy_task.await {
        Err(error) if error.is_cancelled() => {}
        Err(_) => return Err(Error::InvalidState("fault proxy task panicked")),
        Ok(Err(error)) => return Err(error),
        Ok(Ok(())) => return Err(Error::InvalidState("fault proxy exited unexpectedly")),
    }

    petition?;
    resign?;
    if !dropped.load(Ordering::Relaxed) {
        return Err(Error::Dataset(format!(
            "fault proxy did not observe and drop {target:?}"
        )));
    }
    Ok(())
}

async fn run_fault_proxy(
    socket: UdpSocket,
    border_agent: SocketAddr,
    target: FaultTarget,
    dropped: Arc<AtomicBool>,
) -> meshcop::Result<()> {
    let mut commissioner_addr = None;
    let mut buffer = [0u8; meshcop_dtls::driver::MAX_DATAGRAM_SIZE];
    loop {
        let (length, source) = socket.recv_from(&mut buffer).await?;
        let (from_commissioner, destination) = if source == border_agent {
            let Some(commissioner_addr) = commissioner_addr else {
                continue;
            };
            (false, commissioner_addr)
        } else {
            match commissioner_addr {
                None => commissioner_addr = Some(source),
                Some(expected) if source != expected => continue,
                Some(_) => {}
            }
            (true, border_agent)
        };

        let observed = classify_fault_target(&buffer[..length], from_commissioner);
        if observed == Some(target) && !dropped.swap(true, Ordering::Relaxed) {
            continue;
        }
        socket.send_to(&buffer[..length], destination).await?;
    }
}

fn classify_fault_target(datagram: &[u8], from_commissioner: bool) -> Option<FaultTarget> {
    use meshcop_dtls::{
        ClientHello, ContentType, DtlsRecord, HandshakeType, parse_unfragmented_handshake_messages,
    };

    let Ok(records) = DtlsRecord::parse_datagram(datagram) else {
        return None;
    };
    if records.iter().any(|record| {
        record.header.epoch == 1 && record.header.content_type == ContentType::ApplicationData
    }) {
        return Some(if from_commissioner {
            FaultTarget::PetitionRequest
        } else {
            FaultTarget::PetitionResponse
        });
    }

    for record in &records {
        if record.header.epoch != 0 || record.header.content_type != ContentType::Handshake {
            continue;
        }
        let Ok(messages) = parse_unfragmented_handshake_messages(record) else {
            continue;
        };
        for message in messages {
            match message.message_type {
                HandshakeType::ClientHello => {
                    let Ok(hello) = ClientHello::decode(&message.payload) else {
                        continue;
                    };
                    return Some(if hello.cookie.is_empty() {
                        FaultTarget::InitialClientHello
                    } else {
                        FaultTarget::CookieClientHello
                    });
                }
                HandshakeType::HelloVerifyRequest => {
                    return Some(FaultTarget::HelloVerifyRequest);
                }
                HandshakeType::ServerHello
                | HandshakeType::ServerKeyExchange
                | HandshakeType::ServerHelloDone => {
                    return Some(FaultTarget::ServerHandshake);
                }
                HandshakeType::ClientKeyExchange => {
                    return Some(FaultTarget::ClientFinished);
                }
                _ => {}
            }
        }
    }

    if records.iter().any(|record| {
        record.header.epoch == 1 && record.header.content_type == ContentType::Handshake
    }) {
        return Some(if from_commissioner {
            FaultTarget::ClientFinished
        } else {
            FaultTarget::ServerFinished
        });
    }
    None
}

const PRIMARY_COMMISSIONER_ID: &str = "meshcop-primary";
const CONTENDING_COMMISSIONER_ID: &str = "meshcop-contender";
const WRONG_PSKC: [u8; 16] = [0xa5; 16];
const DIAGNOSTIC_FLAGS: u64 =
    diag_flags::MAC_ADDR | diag_flags::MODE | diag_flags::ROUTE64 | diag_flags::LEADER_DATA;
const DIAGNOSTIC_DEADLINE: Duration = Duration::from_secs(10);
const LEADER_ALOC_IID: [u8; 8] = [0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0xfc, 0x00];

fn interop_inputs() -> meshcop::Result<(SocketAddr, Dataset)> {
    let border_agent = std::env::var("MESHCOP_INTEROP_BORDER_AGENT")
        .expect("MESHCOP_INTEROP_BORDER_AGENT must be host:port")
        .parse()
        .expect("MESHCOP_INTEROP_BORDER_AGENT must parse as a socket address");
    let dataset_hex = std::env::var("MESHCOP_INTEROP_DATASET_HEX")
        .expect("MESHCOP_INTEROP_DATASET_HEX must contain the active dataset with PSKc");
    Ok((border_agent, Dataset::from_hex(dataset_hex)?))
}

#[tokio::test]
#[ignore = "requires a live OpenThread border agent; run via tools/ci/interop.sh"]
async fn interop_wrong_pskc_is_rejected_and_border_agent_recovers() -> meshcop::Result<()> {
    let (border_agent, expected) = interop_inputs()?;
    let wrong_config = CommissionerConfig::pskc("meshcop-wrong-pskc", WRONG_PSKC);
    let mut rejected = Commissioner::connect(wrong_config, border_agent).await?;

    let error = rejected
        .petition()
        .await
        .expect_err("a commissioner with the wrong PSKc must not petition successfully");
    let is_authentication_failure = matches!(
        &error,
        Error::Dtls(meshcop_dtls::Error::Crypto(message))
            if message.contains("DTLS alert") && message.contains("level=2")
    );
    assert!(
        is_authentication_failure,
        "wrong PSKc did not produce a fatal DTLS authentication alert: {error}"
    );
    rejected.disconnect();

    // A failed authentication attempt must not wedge the border agent. Prove
    // that a fresh commissioner with the real PSKc can immediately establish
    // DTLS, petition, and resign.
    let config = CommissionerConfig::from_dataset("meshcop-auth-recovery", &expected)?;
    let mut recovered = Commissioner::connect(config, border_agent).await?;
    let petition = recovered.petition().await?;
    assert_ne!(petition.session_id, 0, "petition returned session id 0");
    recovered.resign().await
}

#[tokio::test]
#[ignore = "requires a live OpenThread border agent; run via tools/ci/interop.sh"]
async fn interop_competing_commissioner_is_rejected_then_can_take_over() -> meshcop::Result<()> {
    let (border_agent, expected) = interop_inputs()?;
    let primary_config = CommissionerConfig::from_dataset(PRIMARY_COMMISSIONER_ID, &expected)?;
    let contender_config = CommissionerConfig::from_dataset(CONTENDING_COMMISSIONER_ID, &expected)?;
    let mut primary = Commissioner::connect(primary_config, border_agent).await?;
    let mut contender = Commissioner::connect(contender_config, border_agent).await?;

    primary.petition().await?;
    let rejection = verify_contention_rejection(contender.petition().await);
    if let Err(error) = rejection {
        let _ = resign_if_active(&mut contender).await;
        let _ = resign_if_active(&mut primary).await;
        return Err(error);
    }

    let takeover = async {
        primary.resign().await?;
        let petition = contender.petition().await?;
        if petition.session_id == 0 {
            return Err(Error::InvalidState("takeover returned session id 0"));
        }
        Ok(())
    }
    .await;
    let contender_resign = resign_if_active(&mut contender).await;
    let primary_resign = resign_if_active(&mut primary).await;
    takeover?;
    contender_resign?;
    primary_resign
}

#[tokio::test]
#[ignore = "requires a live OpenThread border agent; run via tools/ci/interop.sh"]
async fn interop_network_diagnostics_against_openthread() -> meshcop::Result<()> {
    let (border_agent, expected) = interop_inputs()?;
    let config = CommissionerConfig::from_dataset("meshcop-diagnostics", &expected)?;
    let mut commissioner = Commissioner::connect(config, border_agent).await?;
    commissioner.petition().await?;

    let session = exercise_diagnostics(&mut commissioner, &expected).await;
    let resign = commissioner.resign().await;
    session?;
    resign
}

fn verify_contention_rejection(result: meshcop::Result<PetitionResponse>) -> meshcop::Result<()> {
    match result {
        Err(Error::PetitionRejected {
            existing_commissioner_id: Some(existing),
        }) if existing == PRIMARY_COMMISSIONER_ID => Ok(()),
        Err(Error::PetitionRejected {
            existing_commissioner_id,
        }) => Err(Error::Dataset(format!(
            "petition rejection identified {existing_commissioner_id:?}, expected {PRIMARY_COMMISSIONER_ID}"
        ))),
        Err(error) => Err(Error::Dataset(format!(
            "contending petition failed with an unexpected error: {error}"
        ))),
        Ok(_) => Err(Error::InvalidState(
            "contending commissioner petition was accepted",
        )),
    }
}

async fn resign_if_active(commissioner: &mut Commissioner) -> meshcop::Result<()> {
    if commissioner.state() == CommissionerState::Active {
        commissioner.resign().await
    } else {
        Ok(())
    }
}

async fn exercise_diagnostics(
    commissioner: &mut Commissioner,
    expected: &Dataset,
) -> meshcop::Result<()> {
    let leader_aloc = leader_aloc_from_dataset(expected)?;

    // Unicast DIAG_GET.req returns the requested TLVs directly in the proxied
    // response. This covers both UDP proxying and typed OpenThread decoding.
    let unicast = commissioner
        .get_diagnostics(leader_aloc, DIAGNOSTIC_FLAGS)
        .await?;
    require_diagnostic_fields("unicast", &unicast)?;

    // DIAG_GET.qry is a separate asynchronous resource: the command is
    // acknowledged first and the leader later emits DIAG_GET.ans.
    commissioner.diagnostic_get(None, DIAGNOSTIC_FLAGS).await?;
    let asynchronous = wait_for_diagnostic_answer(commissioner).await?;
    require_diagnostic_fields("asynchronous", &asynchronous)
}

async fn wait_for_diagnostic_answer(
    commissioner: &mut Commissioner,
) -> meshcop::Result<Box<NetDiagData>> {
    let deadline = tokio::time::Instant::now() + DIAGNOSTIC_DEADLINE;
    loop {
        match tokio::time::timeout_at(deadline, commissioner.next_event()).await {
            Err(_elapsed) => {
                return Err(Error::Timeout("OpenThread diagnostic answer timed out"));
            }
            Ok(Ok(Some(CommissionerEvent::DiagnosticAnswer { data, .. }))) => return Ok(data),
            Ok(Ok(_)) => {}
            Ok(Err(Error::Dtls(meshcop_dtls::Error::Timeout(_)))) => {}
            Ok(Err(error)) => return Err(error),
        }
    }
}

fn require_diagnostic_fields(source: &str, data: &NetDiagData) -> meshcop::Result<()> {
    let missing = [
        ("MAC Address", data.mac_addr.is_some()),
        ("Mode", data.mode.is_some()),
        ("Route64", data.route64.is_some()),
        ("Leader Data", data.leader_data.is_some()),
    ]
    .into_iter()
    .filter_map(|(name, present)| (!present).then_some(name))
    .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(Error::Dataset(format!(
            "{source} diagnostic answer is missing {}",
            missing.join(", ")
        )))
    }
}

fn leader_aloc_from_dataset(dataset: &Dataset) -> meshcop::Result<Ipv6Addr> {
    let prefix = dataset
        .mesh_local_prefix()?
        .ok_or_else(|| Error::Dataset("interop dataset has no mesh-local prefix".to_string()))?;
    let mut octets = [0u8; 16];
    octets[..8].copy_from_slice(&prefix);
    octets[8..].copy_from_slice(&LEADER_ALOC_IID);
    Ok(Ipv6Addr::from(octets))
}

async fn exercise_session(
    commissioner: &mut Commissioner,
    expected: &Dataset,
) -> meshcop::Result<()> {
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
async fn interop_joiner_commissioning_against_openthread() -> meshcop::Result<()> {
    require_mutation_gate()?;
    let (border_agent, expected) = interop_inputs()?;
    let joiner_cli = PathBuf::from(
        std::env::var("MESHCOP_INTEROP_JOINER_CLI")
            .expect("MESHCOP_INTEROP_JOINER_CLI must point at a simulation ot-cli-ftd"),
    );

    let channel = expected
        .channel()?
        .expect("the interop network dataset always carries a channel")
        .channel;
    let config = CommissionerConfig::from_dataset("meshcop-interop", &expected)?;

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

fn require_mutation_gate() -> meshcop::Result<()> {
    if std::env::var("MESHCOP_MUTATE_OK").ok().as_deref() == Some("1") {
        Ok(())
    } else {
        Err(Error::InvalidState(
            "joiner interop requires MESHCOP_MUTATE_OK=1",
        ))
    }
}

async fn commission_joiner(
    commissioner: &mut Commissioner,
    joiner_cli: &std::path::Path,
    channel: u16,
) -> meshcop::Result<()> {
    let joiner_id = meshcop::crypto::compute_joiner_id(JOINER_EUI64);
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
    let keepalive_interval = commissioner.config().keepalive_interval;
    let mut keepalive_deadline = tokio::time::Instant::now() + keepalive_interval;
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
        if tokio::time::Instant::now() >= keepalive_deadline {
            if commissioner.keep_alive().await? != ResultCode::Accept {
                return Err(Error::InvalidState(
                    "commissioner keep-alive was rejected during joiner commissioning",
                ));
            }
            keepalive_deadline = tokio::time::Instant::now() + keepalive_interval;
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
    fn spawn(binary: &std::path::Path, node_id: u32) -> meshcop::Result<Self> {
        let scratch = std::env::temp_dir().join(format!(
            "meshcop-interop-joiner-{}-{node_id}",
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
    async fn command(&mut self, command: &str) -> meshcop::Result<()> {
        self.stdin.write_all(command.as_bytes()).await?;
        self.stdin.write_all(b"\n").await?;
        self.stdin.flush().await?;
        self.wait_for_line("Done", "Error").await
    }

    /// Reads lines until one contains `success` (Ok) or `failure` (Err).
    async fn wait_for_line(&mut self, success: &str, failure: &str) -> meshcop::Result<()> {
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
    async fn wait_for_attach(&mut self) -> meshcop::Result<()> {
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
fn assert_datasets_equivalent(expected: &Dataset, live: &Dataset) -> meshcop::Result<()> {
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
