use super::*;
use meshcop::commissioner::harness::{
    ScriptedExchange, ScriptedMeshcopTransport, ScriptedResponse, run_with_deadline,
};
use meshcop::commissioner::{CommissionerConfig, JoinerHandler};
use meshcop::meshcop::CommissionerOperation;

/// Event wait bound for real-time tests, so a broken session fails the test
/// instead of hanging it.
const EVENT_WAIT: Duration = Duration::from_secs(5);
/// Event wait bound for paused-time tests: longer than any virtual wait they
/// expect, and elapsed instantly when a broken session never answers.
const PAUSED_EVENT_WAIT: Duration = Duration::from_secs(300);

/// Bound on the real-time test's run time. Only the test that runs a real
/// DTLS session over loopback sockets uses real time: a paused clock jumps
/// ahead whenever the runtime waits on a socket, which would fire its timers
/// early.
const SOCKET_TEST_DEADLINE: Duration = Duration::from_secs(3);
/// Bound on a paused-time test's virtual run time: longer than any test waits,
/// and elapsed instantly when a stalled session leaves nothing else to run.
/// Scripted tests run on paused time so a mutation that stalls the session
/// fails them at once instead of after a real-time deadline.
const PAUSED_TEST_DEADLINE: Duration = Duration::from_secs(3600);

/// Runs a real-time socket test body, failing it if it exceeds
/// [`SOCKET_TEST_DEADLINE`].
async fn with_socket_test_deadline(body: impl std::future::Future<Output = ()>) {
    run_with_deadline(SOCKET_TEST_DEADLINE, body).await;
}

/// Runs a paused-time test body, failing it if it exceeds
/// [`PAUSED_TEST_DEADLINE`] of virtual time.
async fn with_paused_test_deadline(body: impl std::future::Future<Output = ()>) {
    run_with_deadline(PAUSED_TEST_DEADLINE, body).await;
}

/// Waits up to `bound` for the interpreter's next session event.
async fn next_event_within(
    interpreter: &mut Interpreter,
    bound: Duration,
) -> Option<CommissionerEvent> {
    tokio::time::timeout(bound, interpreter.next_event())
        .await
        .expect("no session event arrived in time")
}

/// Dispatches one offline command line (no border-agent session) and
/// returns the rendered `[done]`/`[failed]` output.
async fn dispatch_line(line: &str) -> String {
    let mut interpreter = Interpreter::new(CliConfig::default());
    let tokens = tokenize(line).unwrap();
    interpreter.dispatch(&tokens).await.rendered().to_string()
}

/// Dispatches one line on `interpreter` and returns the rendered output.
async fn run_line(interpreter: &mut Interpreter, line: &str) -> String {
    interpreter
        .dispatch(&tokenize(line).unwrap())
        .await
        .rendered()
        .to_string()
}

/// Builds an interpreter whose commissioner runs against the scripted
/// MeshCoP harness, so session commands exercise the production
/// request/response loop without a network.
async fn scripted_interpreter(
    exchanges: impl IntoIterator<Item = (CommissionerOperation, Vec<ScriptedResponse>)>,
    initial_events: impl IntoIterator<Item = CommissionerEvent>,
) -> Interpreter {
    scripted_interpreter_with_config(
        CommissionerConfig::pskc("ot-commissioner-rs", [0x11; 16]),
        exchanges,
        initial_events,
    )
    .await
}

async fn scripted_interpreter_with_config(
    config: CommissionerConfig,
    exchanges: impl IntoIterator<Item = (CommissionerOperation, Vec<ScriptedResponse>)>,
    initial_events: impl IntoIterator<Item = CommissionerEvent>,
) -> Interpreter {
    let script = ScriptedMeshcopTransport::new(
        exchanges
            .into_iter()
            .map(|(operation, responses)| ScriptedExchange::new(operation, responses)),
    );
    let (commissioner, events) = Commissioner::connect_scripted(
        config,
        "127.0.0.1:49156".parse().unwrap(),
        script,
        initial_events,
    )
    .await
    .unwrap();
    commissioner.set_cached_mesh_local_prefix(Some([0xfd, 0x00, 0x0d, 0xb8, 0, 0, 0, 0]));
    let mut interpreter = Interpreter::new(CliConfig::default());
    interpreter.commissioner = Some(commissioner);
    interpreter.events = Some(events);
    interpreter
}

/// Like [`scripted_interpreter`], but petitions first so the session is
/// `Active` — required by mutating and proxied operations.
async fn active_interpreter(
    exchanges: impl IntoIterator<Item = (CommissionerOperation, Vec<ScriptedResponse>)>,
    initial_events: impl IntoIterator<Item = CommissionerEvent>,
) -> Interpreter {
    active_interpreter_with_config(
        CommissionerConfig::pskc("ot-commissioner-rs", [0x11; 16]),
        exchanges,
        initial_events,
    )
    .await
}

async fn active_interpreter_with_config(
    config: CommissionerConfig,
    exchanges: impl IntoIterator<Item = (CommissionerOperation, Vec<ScriptedResponse>)>,
    initial_events: impl IntoIterator<Item = CommissionerEvent>,
) -> Interpreter {
    let mut all = vec![(
        CommissionerOperation::Petition,
        vec![ScriptedResponse::petition_accept(0xbeef)],
    )];
    all.extend(exchanges);
    let interpreter = scripted_interpreter_with_config(config, all, initial_events).await;
    interpreter
        .commissioner
        .as_ref()
        .unwrap()
        .petition()
        .await
        .unwrap();
    interpreter
}

/// An operational dataset carrying every field the per-field
/// `opdataset get` projections support.
fn full_dataset_bytes() -> Vec<u8> {
    let mut dataset = Dataset::default();
    dataset.set_raw(
        meshcop::dataset::TLV_ACTIVE_TIMESTAMP,
        (1u64 << 16).to_be_bytes().to_vec(),
    );
    dataset.set_raw(meshcop::dataset::TLV_CHANNEL, vec![0, 0, 19]);
    dataset.set_raw(
        meshcop::dataset::TLV_CHANNEL_MASK,
        vec![0, 4, 0x00, 0x1f, 0xff, 0xc0],
    );
    dataset.set_raw(
        meshcop::dataset::TLV_EXTENDED_PAN_ID,
        vec![0xa6, 0x39, 0x13, 0x57, 0xb4, 0x75, 0x1d, 0x8a],
    );
    dataset.set_raw(
        meshcop::dataset::TLV_MESH_LOCAL_PREFIX,
        vec![0xfd, 0x00, 0x0d, 0xb8, 0, 0, 0, 0],
    );
    dataset.set_raw(meshcop::dataset::TLV_NETWORK_KEY, vec![0x42; 16]);
    dataset.set_raw(meshcop::dataset::TLV_NETWORK_NAME, b"cli-net".to_vec());
    dataset.set_raw(
        meshcop::dataset::TLV_PAN_ID,
        0xfaceu16.to_be_bytes().to_vec(),
    );
    dataset.set_raw(meshcop::dataset::TLV_PSKC, vec![0x24; 16]);
    dataset.set_raw(
        meshcop::dataset::TLV_SECURITY_POLICY,
        vec![0x02, 0xa0, 0xff, 0xf8],
    );
    dataset.to_bytes().unwrap()
}

fn ok(value: impl std::fmt::Display) -> String {
    format!("{value}\n[done]")
}

#[test]
fn tokenize_honors_whitespace_and_quotes() {
    assert_eq!(tokenize("a b  c").unwrap(), ["a", "b", "c"]);
    assert_eq!(tokenize("set '{\"k\": 1}'").unwrap(), ["set", "{\"k\": 1}"]);
    assert_eq!(tokenize("x \"y z\"").unwrap(), ["x", "y z"]);
    assert!(tokenize("oops 'unterminated").is_err());
}

#[test]
fn integer_parsers_accept_hex_and_decimal() {
    assert_eq!(parse_u32("0x10"), Some(16));
    assert_eq!(parse_u32("16"), Some(16));
    assert_eq!(parse_u64("0xFF"), Some(255));
    assert_eq!(parse_u32("nope"), None);
}

#[test]
fn multi_network_flags_and_known_fields_are_detected() {
    assert!(has_multi_network_flag(&vec![
        "start".to_string(),
        "--nwk".to_string()
    ]));
    assert!(!has_multi_network_flag(&vec!["start".to_string()]));
    assert!(is_known_op_field("channel"));
    assert!(!is_known_op_field("bogus"));
}

#[tokio::test(start_paused = true)]
async fn state_is_disabled_and_active_is_false_before_start() {
    with_paused_test_deadline(async {
        assert_eq!(dispatch_line("state").await, "disabled\n[done]");
        assert_eq!(dispatch_line("active").await, "false\n[done]");
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn invalid_command_reports_the_cpp_help_hint() {
    with_paused_test_deadline(async {
        assert_eq!(
            dispatch_line("bogus").await,
            "'bogus' is not a valid command, type 'help' to list all commands\n[failed]"
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn session_commands_require_a_started_commissioner() {
    with_paused_test_deadline(async {
        assert_eq!(
            dispatch_line("opdataset get active").await,
            format!("{NOT_CONNECTED}\n[failed]")
        );
        assert_eq!(
            dispatch_line("commdataset get").await,
            format!("{NOT_CONNECTED}\n[failed]")
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn out_of_scope_features_fail_with_an_explanation() {
    with_paused_test_deadline(async {
        assert!(
            dispatch_line("token print")
                .await
                .contains("CCM token support is not implemented")
        );
        assert!(
            dispatch_line("br list")
                .await
                .contains("registry is not implemented")
        );
        assert!(
            dispatch_line("borderagent discover")
                .await
                .contains("mDNS border-agent discovery is not implemented")
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn help_lists_every_command_sorted_with_the_footer() {
    with_paused_test_deadline(async {
        let out = dispatch_line("help").await;
        assert!(out.starts_with("active\nannounce\nbbrdataset\nborderagent\nbr\n"));
        assert!(out.contains("\ntype 'help <command>' for help of specific command.\n[done]"));
        // `help <command>` echoes the usage string.
        assert!(
            dispatch_line("help sessionid")
                .await
                .starts_with("usage:\nsessionid")
        );
        assert_eq!(
            dispatch_line("help nope").await,
            "nope is not a valid command\n[failed]"
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn config_set_then_get_pskc_round_trips() {
    with_paused_test_deadline(async {
        let mut interpreter = Interpreter::new(CliConfig::default());
        let set = interpreter
            .dispatch(&tokenize("config set pskc 00112233445566778899aabbccddeeff").unwrap())
            .await;
        assert_eq!(set.rendered().as_str(), "[done]");
        let get = interpreter
            .dispatch(&tokenize("config get pskc").unwrap())
            .await;
        assert_eq!(
            get.rendered().as_str(),
            "00112233445566778899aabbccddeeff\n[done]"
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn too_few_arguments_are_rejected() {
    with_paused_test_deadline(async {
        assert_eq!(
            dispatch_line("config get").await,
            format!("{SYNTAX_FEW_ARGS}\n[failed]")
        );
        assert_eq!(
            dispatch_line("start 127.0.0.1").await,
            format!("{SYNTAX_FEW_ARGS}\n[failed]")
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn evaluate_and_print_handles_blank_bad_and_multi_network_lines() {
    with_paused_test_deadline(async {
        let mut interpreter = Interpreter::new(CliConfig::default());
        // Blank input re-prompts, tokenizer errors and --nwk/--dom report
        // failure, and a normal command dispatches; all print to stdout.
        interpreter.evaluate_and_print("").await;
        interpreter.evaluate_and_print("bad 'quote").await;
        interpreter.evaluate_and_print("start --nwk net1").await;
        interpreter.evaluate_and_print("state").await;
        assert!(!interpreter.should_exit());
        interpreter.evaluate_and_print("exit").await;
        assert!(interpreter.should_exit());
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn start_validates_address_and_config_before_any_network_use() {
    with_paused_test_deadline(async {
        let mut interpreter = Interpreter::new(CliConfig::default());
        assert_eq!(
            run_line(&mut interpreter, "start nothost nope").await,
            "invalid border-agent address 'nothost:nope'\n[failed]"
        );
        // The default configuration has no PSKc, so start fails before
        // connecting anywhere.
        let no_pskc = run_line(&mut interpreter, "start 127.0.0.1 49191").await;
        assert!(no_pskc.ends_with("[failed]"), "{no_pskc}");
    })
    .await
}

#[tokio::test]
async fn start_connect_only_opens_dtls_without_petitioning() {
    with_socket_test_deadline(async {
        const PSKC: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let mut interpreter = Interpreter::new(CliConfig::default());
        let set = run_line(
            &mut interpreter,
            "config set pskc 00112233445566778899aabbccddeeff",
        )
        .await;
        assert_eq!(set, "[done]");
        let border_agent = meshcop_dtls::DtlsServer::bind("127.0.0.1:0").await.unwrap();
        let port = border_agent.local_addr().port();
        let accept = async move {
            border_agent
                .accept(&PSKC, Duration::from_secs(10))
                .await
                .unwrap()
        };

        // --connect-only runs the DTLS handshake but does not petition.
        let start = format!("start 127.0.0.1 {port} --connect-only");
        let (_session, started) = tokio::join!(accept, run_line(&mut interpreter, &start));
        assert_eq!(started, "[done]");
        assert_eq!(run_line(&mut interpreter, "state").await, ok("connected"));
        assert_eq!(run_line(&mut interpreter, "active").await, ok("false"));
        assert_eq!(
            run_line(&mut interpreter, "sessionid").await,
            "commissioner session is not active\n[failed]"
        );
        // stop on an unpetitioned session closes it without a resignation.
        assert_eq!(run_line(&mut interpreter, "stop").await, "[done]");
        assert_eq!(run_line(&mut interpreter, "state").await, ok("disabled"));
        // stop with no session is a no-op success.
        assert_eq!(run_line(&mut interpreter, "stop").await, "[done]");
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn scripted_session_reports_state_sessionid_and_stops() {
    with_paused_test_deadline(async {
        let mut interpreter = scripted_interpreter(
            [
                (
                    CommissionerOperation::Petition,
                    vec![ScriptedResponse::petition_accept(0xbeef)],
                ),
                (
                    CommissionerOperation::KeepAlive,
                    vec![ScriptedResponse::accept()],
                ),
            ],
            [],
        )
        .await;
        interpreter
            .commissioner
            .as_mut()
            .unwrap()
            .petition()
            .await
            .unwrap();
        assert_eq!(run_line(&mut interpreter, "state").await, ok("active"));
        assert_eq!(run_line(&mut interpreter, "active").await, ok("true"));
        assert_eq!(run_line(&mut interpreter, "sessionid").await, ok(0xbeefu16));
        assert_eq!(run_line(&mut interpreter, "stop").await, "[done]");
        assert_eq!(run_line(&mut interpreter, "state").await, ok("disabled"));
    })
    .await
}

#[test]
fn joiner_handler_is_built_from_zeroizing_cli_credentials() {
    let joiner_id = [0x42; 8];
    let mut interpreter = Interpreter::new(CliConfig::default());
    interpreter.joiner_all_pskd = Some(Zeroizing::new("wildcard-secret".to_string()));
    interpreter
        .joiner_pskds
        .insert(joiner_id, Zeroizing::new("joiner-secret".to_string()));

    let mut handler = interpreter.build_joiner_handler();
    assert_eq!(
        handler.joiner_pskd(&joiner_id).as_deref(),
        Some("joiner-secret")
    );
    assert_eq!(
        handler.joiner_pskd(&[0x99; 8]).as_deref(),
        Some("wildcard-secret")
    );
}

#[tokio::test(start_paused = true)]
async fn sessions_keep_themselves_alive_while_the_repl_waits() {
    with_paused_test_deadline(async {
        let mut config = CommissionerConfig::pskc("ot-commissioner-rs", [0x11; 16]);
        config.keepalive_interval = Duration::from_secs(37);
        let mut interpreter = active_interpreter_with_config(
            config,
            [
                (
                    CommissionerOperation::KeepAlive,
                    vec![ScriptedResponse::accept()],
                ),
                (
                    CommissionerOperation::KeepAlive,
                    vec![ScriptedResponse::accept()],
                ),
            ],
            [],
        )
        .await;
        let started = tokio::time::Instant::now();

        for expected_at in [37, 74] {
            let event = next_event_within(&mut interpreter, PAUSED_EVENT_WAIT)
                .await
                .unwrap();
            assert_eq!(
                event,
                CommissionerEvent::KeepAliveResponse(meshcop::commissioner::ResultCode::Accept)
            );
            assert_eq!(started.elapsed(), Duration::from_secs(expected_at));
            assert_eq!(interpreter.handle_background_event(event), None);
        }
        assert_eq!(run_line(&mut interpreter, "state").await, ok("active"));
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_lost_session_is_reported_and_the_state_reads_disabled() {
    with_paused_test_deadline(async {
        let mut interpreter = active_interpreter(
            [(
                CommissionerOperation::KeepAlive,
                vec![ScriptedResponse::reject()],
            )],
            [],
        )
        .await;

        let mut messages = Vec::new();
        while let Some(event) = next_event_within(&mut interpreter, PAUSED_EVENT_WAIT).await {
            messages.extend(interpreter.handle_background_event(event));
        }

        assert_eq!(
            messages,
            ["commissioner session lost: a keep-alive was rejected"]
        );
        assert!(interpreter.events.is_none());
        assert_eq!(run_line(&mut interpreter, "state").await, ok("disabled"));
        assert_eq!(run_line(&mut interpreter, "active").await, ok("false"));
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn background_scan_reports_are_recorded_for_later_commands() {
    with_paused_test_deadline(async {
        let mut interpreter = scripted_interpreter(
            [],
            [CommissionerEvent::EnergyReport {
                peer_addr: "fd00::1".to_string(),
                channel_mask: 0x0000_8000,
                energy_list: vec![0xb0],
            }],
        )
        .await;

        let event = next_event_within(&mut interpreter, EVENT_WAIT)
            .await
            .unwrap();
        assert_eq!(interpreter.handle_background_event(event), None);
        assert_eq!(interpreter.energy_reports.len(), 1);
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn borderagent_get_locator_renders_present_and_missing() {
    with_paused_test_deadline(async {
        let mut interpreter = scripted_interpreter(
            [
                (
                    CommissionerOperation::GetCommissionerDataset,
                    vec![ScriptedResponse::content(vec![
                        meshcop::meshcop::TLV_BORDER_AGENT_LOCATOR,
                        2,
                        0x4c,
                        0x00,
                    ])],
                ),
                (
                    CommissionerOperation::GetCommissionerDataset,
                    vec![ScriptedResponse::content(Vec::new())],
                ),
                (
                    CommissionerOperation::GetCommissionerDataset,
                    vec![ScriptedResponse::reject()],
                ),
            ],
            [],
        )
        .await;
        assert_eq!(
            run_line(&mut interpreter, "borderagent get locator").await,
            ok("0x4c00")
        );
        assert_eq!(
            run_line(&mut interpreter, "borderagent get locator").await,
            "border agent locator not present\n[failed]"
        );
        let rejected = run_line(&mut interpreter, "borderagent get locator").await;
        assert!(rejected.ends_with("[failed]"), "{rejected}");
        // Argument validation happens before any exchange.
        assert_eq!(
            run_line(&mut interpreter, "borderagent get oops").await,
            "only 'borderagent get locator' is supported\n[failed]"
        );
        assert!(
            run_line(&mut interpreter, "borderagent bogus")
                .await
                .contains("is not a valid sub-command")
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn joiner_commands_drive_steering_and_port_exchanges() {
    with_paused_test_deadline(async {
        let mut interpreter = active_interpreter(
            [
                // enable -> read current steering data, then set the updated one
                (
                    CommissionerOperation::GetCommissionerDataset,
                    vec![ScriptedResponse::content(Vec::new())],
                ),
                (
                    CommissionerOperation::SetCommissionerDataset,
                    vec![ScriptedResponse::accept()],
                ),
                // enableall -> wildcard steering set
                (
                    CommissionerOperation::SetCommissionerDataset,
                    vec![ScriptedResponse::accept()],
                ),
                // disableall -> cleared steering set
                (
                    CommissionerOperation::SetCommissionerDataset,
                    vec![ScriptedResponse::accept()],
                ),
                // getport
                (
                    CommissionerOperation::GetCommissionerDataset,
                    vec![ScriptedResponse::content(vec![
                        meshcop::meshcop::TLV_JOINER_UDP_PORT,
                        2,
                        0x03,
                        0xea,
                    ])],
                ),
                // setport
                (
                    CommissionerOperation::SetCommissionerDataset,
                    vec![ScriptedResponse::accept()],
                ),
            ],
            [],
        )
        .await;
        assert_eq!(
            run_line(
                &mut interpreter,
                "joiner enable meshcop 0xdead00beef00cafe J01ABC"
            )
            .await,
            "[done]"
        );
        assert_eq!(
            run_line(&mut interpreter, "joiner enableall meshcop PSKDALL").await,
            "[done]"
        );
        // disable only rewrites local state; no exchange.
        assert_eq!(
            run_line(
                &mut interpreter,
                "joiner disable meshcop 0xdead00beef00cafe"
            )
            .await,
            "[done]"
        );
        assert_eq!(
            run_line(&mut interpreter, "joiner disableall meshcop").await,
            "[done]"
        );
        assert_eq!(
            run_line(&mut interpreter, "joiner getport meshcop").await,
            ok(1002)
        );
        assert_eq!(
            run_line(&mut interpreter, "joiner setport meshcop 1002").await,
            "[done]"
        );
        // Validation failures need no exchanges.
        assert!(
            run_line(&mut interpreter, "joiner enable ae 0x1 PSKD")
                .await
                .contains("(CCM) is not implemented")
        );
        assert!(
            run_line(&mut interpreter, "joiner enable zigbee 0x1 PSKD")
                .await
                .contains("is not a valid joiner type")
        );
        assert!(
            run_line(&mut interpreter, "joiner enable meshcop noteui PSKD")
                .await
                .contains("invalid EUI-64")
        );
        assert!(
            run_line(&mut interpreter, "joiner setport meshcop 70000")
                .await
                .contains("invalid port")
        );
        assert!(
            run_line(&mut interpreter, "joiner bogus meshcop")
                .await
                .contains("is not a valid sub-command")
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn commdataset_get_and_set_round_trip_json() {
    with_paused_test_deadline(async {
        let mut comm_dataset = Dataset::default();
        comm_dataset.set_raw(
            meshcop::meshcop::TLV_BORDER_AGENT_LOCATOR,
            0x1234u16.to_be_bytes().to_vec(),
        );
        comm_dataset.set_raw(meshcop::meshcop::TLV_STEERING_DATA, vec![0xff]);
        let mut interpreter = active_interpreter(
            [
                (
                    CommissionerOperation::GetCommissionerDataset,
                    vec![ScriptedResponse::content(comm_dataset.to_bytes().unwrap())],
                ),
                (
                    CommissionerOperation::SetCommissionerDataset,
                    vec![ScriptedResponse::accept()],
                ),
            ],
            [],
        )
        .await;
        let got = run_line(&mut interpreter, "commdataset get").await;
        assert!(got.contains("\"BorderAgentLocator\": 4660"), "{got}");
        assert!(got.contains("\"SteeringData\": \"ff\""), "{got}");
        assert_eq!(
            run_line(
                &mut interpreter,
                "commdataset set '{\"SteeringData\":\"ff\",\"JoinerUdpPort\":1000}'"
            )
            .await,
            "[done]"
        );
        let bad = run_line(&mut interpreter, "commdataset set notjson").await;
        assert!(bad.ends_with("[failed]"), "{bad}");
        assert!(
            run_line(&mut interpreter, "commdataset bogus")
                .await
                .contains("is not a valid sub-command")
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn bbrdataset_get_renders_raw_tlvs() {
    with_paused_test_deadline(async {
        let mut interpreter = scripted_interpreter(
            [(
                CommissionerOperation::GetBbrDataset,
                vec![ScriptedResponse::content(vec![1, 2, 0xab, 0xcd])],
            )],
            [],
        )
        .await;
        let got = run_line(&mut interpreter, "bbrdataset get").await;
        assert!(got.contains("\"Tlv1\": \"abcd\""), "{got}");
        assert!(
            run_line(&mut interpreter, "bbrdataset set")
                .await
                .contains("not yet modeled")
        );
        assert!(
            run_line(&mut interpreter, "bbrdataset bogus")
                .await
                .contains("is not a valid sub-command")
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn opdataset_get_projects_every_field_like_the_cpp_cli() {
    with_paused_test_deadline(async {
        let full = full_dataset_bytes();
        let mut pending_dataset = Dataset::default();
        pending_dataset.set_raw(meshcop::dataset::TLV_NETWORK_NAME, b"cli-net".to_vec());
        pending_dataset.set_raw(
            meshcop::dataset::TLV_PENDING_TIMESTAMP,
            (2u64 << 16).to_be_bytes().to_vec(),
        );
        pending_dataset.set_raw(
            meshcop::dataset::TLV_DELAY_TIMER,
            60000u32.to_be_bytes().to_vec(),
        );
        let minimal = {
            let mut d = Dataset::default();
            d.set_raw(meshcop::dataset::TLV_NETWORK_NAME, b"min".to_vec());
            d.to_bytes().unwrap()
        };

        let mut exchanges: Vec<(CommissionerOperation, Vec<ScriptedResponse>)> = (0..12)
            .map(|_| {
                (
                    CommissionerOperation::GetActiveDataset,
                    vec![ScriptedResponse::content(full.clone())],
                )
            })
            .collect();
        exchanges.push((
            CommissionerOperation::GetPendingDataset,
            vec![ScriptedResponse::content(
                pending_dataset.to_bytes().unwrap(),
            )],
        ));
        exchanges.push((
            CommissionerOperation::GetActiveDataset,
            vec![ScriptedResponse::content(minimal)],
        ));
        let mut interpreter = scripted_interpreter(exchanges, []).await;

        let active = run_line(&mut interpreter, "opdataset get active").await;
        for key in [
            "ActiveTimestamp",
            "Channel",
            "ChannelMask",
            "ExtendedPanId",
            "MeshLocalPrefix",
            "NetworkMasterKey",
            "NetworkName",
            "PanId",
            "PSKc",
            "SecurityPolicy",
        ] {
            assert!(active.contains(key), "missing {key} in {active}");
        }

        let expect_json = |value: &serde_json::Value| ok(json::dump(value));
        assert_eq!(
            run_line(&mut interpreter, "opdataset get activetimestamp").await,
            expect_json(&json!({ "Seconds": 1, "Ticks": 0, "U": 0 }))
        );
        assert_eq!(
            run_line(&mut interpreter, "opdataset get channel").await,
            expect_json(&json!({ "Page": 0, "Number": 19 }))
        );
        assert_eq!(
            run_line(&mut interpreter, "opdataset get channelmask").await,
            expect_json(&json!([{ "Page": 0, "Masks": "001fffc0" }]))
        );
        assert_eq!(
            run_line(&mut interpreter, "opdataset get xpanid").await,
            ok("a6391357b4751d8a")
        );
        assert_eq!(
            run_line(&mut interpreter, "opdataset get meshlocalprefix").await,
            ok("fd00:db8::/64")
        );
        assert_eq!(
            run_line(&mut interpreter, "opdataset get networkmasterkey").await,
            ok("42".repeat(16))
        );
        assert_eq!(
            run_line(&mut interpreter, "opdataset get networkname").await,
            ok("cli-net")
        );
        assert_eq!(
            run_line(&mut interpreter, "opdataset get panid").await,
            ok("0xface")
        );
        assert_eq!(
            run_line(&mut interpreter, "opdataset get pskc").await,
            ok("24".repeat(16))
        );
        assert_eq!(
            run_line(&mut interpreter, "opdataset get securitypolicy").await,
            expect_json(&json!({ "RotationTime": 672, "Flags": "fff8" }))
        );
        // Unknown fields still fetch the dataset first, then report.
        assert_eq!(
            run_line(&mut interpreter, "opdataset get bogus").await,
            "bogus is not a valid property\n[failed]"
        );
        let pending = run_line(&mut interpreter, "opdataset get pending").await;
        assert!(pending.contains("PendingTimestamp"), "{pending}");
        assert!(pending.contains("\"Delay\": 60000"), "{pending}");
        assert_eq!(
            run_line(&mut interpreter, "opdataset get pskc").await,
            "pskc is not present in the active dataset\n[failed]"
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn opdataset_set_builds_field_and_json_updates() {
    with_paused_test_deadline(async {
    // Each per-field set first fetches the current Active Timestamp (to
    // bump it) and then issues the MGMT_ACTIVE_SET.
    let mut with_timestamp = Dataset::default();
    with_timestamp.set_raw(
        meshcop::dataset::TLV_ACTIVE_TIMESTAMP,
        (7u64 << 16).to_be_bytes().to_vec(),
    );
    let timestamp_bytes = with_timestamp.to_bytes().unwrap();
    let mut exchanges: Vec<(CommissionerOperation, Vec<ScriptedResponse>)> = Vec::new();
    for index in 0..8 {
        // One get answers without a timestamp to cover the
        // first-ever-update fallback.
        let get_payload = if index == 7 {
            Vec::new()
        } else {
            timestamp_bytes.clone()
        };
        exchanges.push((
            CommissionerOperation::GetActiveDataset,
            vec![ScriptedResponse::content(get_payload)],
        ));
        exchanges.push((
            CommissionerOperation::SetActiveDataset,
            vec![ScriptedResponse::accept()],
        ));
    }
    // The full-JSON forms send the user's dataset as-is (no bump).
    exchanges.push((
        CommissionerOperation::SetActiveDataset,
        vec![ScriptedResponse::accept()],
    ));
    exchanges.push((
        CommissionerOperation::SetPendingDataset,
        vec![ScriptedResponse::accept()],
    ));
    let mut interpreter = active_interpreter(exchanges, []).await;

    for line in [
        "opdataset set channel 0 19",
        "opdataset set xpanid a6391357b4751d8a",
        "opdataset set networkmasterkey 00112233445566778899aabbccddeeff",
        "opdataset set networkname new-name",
        "opdataset set panid 0xface",
        "opdataset set pskc 00112233445566778899aabbccddeeff",
        "opdataset set meshlocalprefix fd00:db8::/64",
        "opdataset set securitypolicy 672 fff8",
        "opdataset set active '{\"ActiveTimestamp\":{\"Seconds\":8,\"Ticks\":0,\"U\":0},\"NetworkName\":\"json-net\"}'",
        "opdataset set pending '{\"ActiveTimestamp\":{\"Seconds\":8,\"Ticks\":0,\"U\":0},\"PendingTimestamp\":{\"Seconds\":9,\"Ticks\":0,\"U\":0},\"Delay\":60000,\"NetworkName\":\"json-pend\"}'",
    ] {
        assert_eq!(run_line(&mut interpreter, line).await, "[done]", "{line}");
    }

    // Validation failures consume no exchanges.
    assert_eq!(
        run_line(&mut interpreter, "opdataset set bogusfield v").await,
        "bogusfield cannot be set\n[failed]"
    );
    assert_eq!(
        run_line(&mut interpreter, "opdataset set channel zero nineteen").await,
        "invalid page\n[failed]"
    );
    assert!(
        run_line(&mut interpreter, "opdataset set xpanid zz")
            .await
            .ends_with("[failed]")
    );
    assert_eq!(
        run_line(&mut interpreter, "opdataset set securitypolicy notnum fff8").await,
        "invalid rotation time\n[failed]"
    );
    assert!(
        run_line(&mut interpreter, "opdataset set securitypolicy 672")
            .await
            .contains("flags must not be empty")
    );
    assert!(
        run_line(&mut interpreter, "opdataset bogus active")
            .await
            .contains("is not a valid sub-command")
    );
    let bad_json = run_line(&mut interpreter, "opdataset set active notjson").await;
    assert!(bad_json.ends_with("[failed]"), "{bad_json}");
})
    .await
}

#[tokio::test(start_paused = true)]
async fn managed_commands_mlr_and_announce_route_through_the_proxy() {
    with_paused_test_deadline(async {
        let mut interpreter = active_interpreter(
            [
                (
                    CommissionerOperation::Reenroll,
                    vec![ScriptedResponse::changed_without_state()],
                ),
                (
                    CommissionerOperation::DomainReset,
                    vec![ScriptedResponse::changed_without_state()],
                ),
                (
                    CommissionerOperation::Migrate,
                    vec![ScriptedResponse::changed_without_state()],
                ),
                (
                    CommissionerOperation::RegisterMulticastListener,
                    vec![ScriptedResponse::content(vec![
                        meshcop::meshcop::THREAD_TLV_STATUS,
                        1,
                        0,
                    ])],
                ),
                (
                    CommissionerOperation::AnnounceBegin,
                    vec![ScriptedResponse::changed_without_state()],
                ),
            ],
            [],
        )
        .await;
        assert_eq!(
            run_line(&mut interpreter, "reenroll fd00::1").await,
            "[done]"
        );
        assert_eq!(
            run_line(&mut interpreter, "domainreset fd00::1").await,
            "[done]"
        );
        assert_eq!(
            run_line(&mut interpreter, "migrate fd00::1 target-net").await,
            "[done]"
        );
        assert_eq!(run_line(&mut interpreter, "mlr ff05::1 300").await, ok(0));
        assert_eq!(
            run_line(&mut interpreter, "announce 0x7fff800 2 100 fd00::1").await,
            "[done]"
        );
        // Argument validation happens before any exchange.
        assert!(
            run_line(&mut interpreter, "reenroll notaddr")
                .await
                .contains("invalid device address")
        );
        assert_eq!(
            run_line(&mut interpreter, "mlr ff05::1 forever").await,
            "invalid timeout\n[failed]"
        );
        assert_eq!(
            run_line(&mut interpreter, "announce nope 2 100 fd00::1").await,
            "invalid announce arguments\n[failed]"
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn panid_query_and_energy_scan_collect_reports() {
    with_paused_test_deadline(async {
        let mut interpreter = active_interpreter(
            [
                (
                    CommissionerOperation::PanIdQuery,
                    vec![ScriptedResponse::changed_without_state()],
                ),
                (
                    CommissionerOperation::EnergyScan,
                    vec![ScriptedResponse::changed_without_state()],
                ),
            ],
            [
                CommissionerEvent::PanIdConflict {
                    peer_addr: "fd00::9".to_string(),
                    channel_mask: 0x07fff800,
                    pan_id: 0xface,
                },
                CommissionerEvent::EnergyReport {
                    peer_addr: "fd00::9".to_string(),
                    channel_mask: 0x07fff800,
                    energy_list: vec![0x9c, 0x80],
                },
            ],
        )
        .await;
        assert_eq!(
            run_line(&mut interpreter, "panid query 0x7fff800 0xface fd00::1").await,
            "[done]"
        );
        let conflicts = run_line(&mut interpreter, "panid conflict 0xface").await;
        assert!(conflicts.contains("\"Peer\": \"fd00::9\""), "{conflicts}");
        assert!(conflicts.contains("\"PanId\": \"0xface\""), "{conflicts}");
        assert_eq!(
            run_line(&mut interpreter, "panid conflict 0xbeef").await,
            ok("[]")
        );
        assert_eq!(
            run_line(&mut interpreter, "energy scan 0x7fff800 2 100 50 fd00::1").await,
            "[done]"
        );
        let reports = run_line(&mut interpreter, "energy report").await;
        assert!(reports.contains("\"Peer\": \"fd00::9\""), "{reports}");
        assert!(reports.contains("-100"), "{reports}");
        assert!(
            run_line(&mut interpreter, "energy report fd00::9")
                .await
                .contains("fd00::9")
        );
        assert_eq!(
            run_line(&mut interpreter, "energy report fd00::8").await,
            ok("[]")
        );
        // Invalid arguments and sub-commands.
        assert_eq!(
            run_line(&mut interpreter, "panid query nope 0xface fd00::1").await,
            "invalid panid query arguments\n[failed]"
        );
        assert_eq!(
            run_line(&mut interpreter, "panid conflict nope").await,
            "invalid panid\n[failed]"
        );
        assert!(
            run_line(&mut interpreter, "panid bogus x")
                .await
                .contains("is not a valid sub-command")
        );
        assert_eq!(
            run_line(&mut interpreter, "energy scan nope 2 100 50 fd00::1").await,
            "invalid energy scan arguments\n[failed]"
        );
        assert!(
            run_line(&mut interpreter, "energy bogus")
                .await
                .contains("is not a valid sub-command")
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn netdiag_query_and_reset_render_diagnostics() {
    with_paused_test_deadline(async {
        // MAC Address (1) = 0x8000 and Leader Data (6); then an Ext MAC
        // Address (0) answer; then a reset.
        let mut interpreter = active_interpreter(
            [
                (
                    CommissionerOperation::DiagnosticGetUnicast,
                    vec![ScriptedResponse::content(vec![
                        1, 2, 0x80, 0x00, 6, 8, 0, 0, 0, 1, 64, 10, 9, 5,
                    ])],
                ),
                (
                    CommissionerOperation::DiagnosticGetUnicast,
                    vec![ScriptedResponse::content(vec![
                        0, 8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                    ])],
                ),
                (
                    CommissionerOperation::DiagnosticReset,
                    vec![ScriptedResponse::changed_without_state()],
                ),
            ],
            [],
        )
        .await;
        let queried = run_line(&mut interpreter, "netdiag query fd00::1").await;
        assert!(queried.contains("\"Rloc16\": \"0x8000\""), "{queried}");
        assert!(queried.contains("LeaderData"), "{queried}");
        let ext = run_line(&mut interpreter, "netdiag query extaddr fd00::1").await;
        assert!(
            ext.contains("\"ExtAddress\": \"1122334455667788\""),
            "{ext}"
        );
        assert_eq!(
            run_line(&mut interpreter, "netdiag reset maccounters fd00::1").await,
            "[done]"
        );
        // Validation failures need no exchanges.
        assert!(
            run_line(&mut interpreter, "netdiag query bogus fd00::1")
                .await
                .contains("is not a valid type")
        );
        assert!(
            run_line(&mut interpreter, "netdiag query notaddr")
                .await
                .contains("invalid address")
        );
        assert!(
            run_line(&mut interpreter, "netdiag reset other fd00::1")
                .await
                .contains("only 'netdiag reset maccounters <addr>' supported")
        );
        assert!(
            run_line(&mut interpreter, "netdiag bogus fd00::1")
                .await
                .contains("is not a valid sub-command")
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn protocol_errors_surface_as_failed_output() {
    with_paused_test_deadline(async {
        // A 4.04-coded response fails the exchange and the CLI reports it.
        let mut interpreter = active_interpreter(
            [
                (
                    CommissionerOperation::GetActiveDataset,
                    vec![ScriptedResponse::Coded {
                        code: meshcop::meshcop::CoapCode(0x84),
                        payload: Vec::new(),
                    }],
                ),
                (
                    CommissionerOperation::SetActiveDataset,
                    vec![ScriptedResponse::reject()],
                ),
            ],
            [],
        )
        .await;
        let active = run_line(&mut interpreter, "opdataset get active").await;
        assert!(active.ends_with("[failed]"), "{active}");
        // A State=Reject answer to a set surfaces as a rejection.
        let set = run_line(
            &mut interpreter,
            "opdataset set active '{\"ActiveTimestamp\":{\"Seconds\":8,\"Ticks\":0,\"U\":0}}'",
        )
        .await;
        assert!(set.contains("rejected"), "{set}");
        assert!(set.ends_with("[failed]"), "{set}");
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn lost_events_are_reported_while_waiting_and_after_a_scan() {
    with_paused_test_deadline(async {
        const WARNING: &str =
            "missed 2 commissioner events; energy and PAN ID reports may be incomplete";
        let lagged = CommissionerEvent::Lagged { missed: 2 };
        let mut interpreter = scripted_interpreter([], [lagged.clone()]).await;

        assert_eq!(
            interpreter.handle_background_event(lagged),
            Some(WARNING.to_string())
        );
        let scanned = interpreter.pump_events(Duration::from_millis(50)).await;
        assert_eq!(scanned.rendered().as_str(), format!("{WARNING}\n[done]"));
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn shutdown_resigns_a_running_session() {
    with_paused_test_deadline(async {
        let mut interpreter = active_interpreter(
            [(
                CommissionerOperation::KeepAlive,
                vec![ScriptedResponse::accept()],
            )],
            [],
        )
        .await;
        let transport = interpreter
            .commissioner
            .as_ref()
            .unwrap()
            .scripted_transport()
            .unwrap()
            .clone();

        interpreter.shutdown().await;
        let resignation = transport.observed_requests().pop().unwrap();
        assert_eq!(resignation.operation, CommissionerOperation::KeepAlive);
        assert!(interpreter.commissioner.is_none());
        // Without a session there is nothing to resign.
        interpreter.shutdown().await;
        assert_eq!(transport.observed_requests().len(), 2);
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn shutdown_leaves_a_lost_session_alone() {
    with_paused_test_deadline(async {
        let mut interpreter = active_interpreter(
            [(
                CommissionerOperation::KeepAlive,
                vec![ScriptedResponse::reject()],
            )],
            [],
        )
        .await;
        let commissioner = interpreter.commissioner.clone().unwrap();
        assert!(commissioner.keep_alive().await.is_ok());
        assert!(matches!(
            commissioner.status(),
            meshcop::commissioner::SessionStatus::Closed { .. }
        ));

        interpreter.shutdown().await;
        assert!(interpreter.commissioner.is_some());
    })
    .await
}
