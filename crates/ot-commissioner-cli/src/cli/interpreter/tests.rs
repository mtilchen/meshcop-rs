use super::*;
use meshcop::commissioner::harness::{
    ScriptedExchange, ScriptedMeshcopTransport, ScriptedResponse,
};
use meshcop::commissioner::{CommissionerConfig, JoinerHandler};
use meshcop::meshcop::CommissionerOperation;

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
    let mut commissioner = Commissioner::connect_scripted(
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
    let mut interpreter = scripted_interpreter_with_config(config, all, initial_events).await;
    interpreter
        .commissioner
        .as_mut()
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

#[test]
fn keepalive_preflight_classifies_network_backed_command_forms() {
    for command in [
        "start 127.0.0.1 49191",
        "borderagent get locator",
        "joiner enable meshcop 1 PSKD",
        "joiner enableall meshcop PSKD",
        "joiner disableall meshcop",
        "joiner getport meshcop",
        "joiner setport meshcop 1000",
        "commdataset get",
        "commdataset set {}",
        "opdataset get active",
        "opdataset set active {}",
        "bbrdataset get",
        "reenroll fd00::1",
        "domainreset fd00::1",
        "migrate fd00::1 network",
        "mlr ff05::1 300",
        "announce 1 1 1 fd00::1",
        "panid query 1 1 fd00::1",
        "energy scan 1 1 1 1 fd00::1",
        "netdiag query fd00::1",
        "netdiag reset maccounters fd00::1",
    ] {
        assert!(
            command_may_wait_for_commissioner(&tokenize(command).unwrap()),
            "expected network-backed command: {command}"
        );
    }

    for command in [
        "",
        "stop",
        "state",
        "borderagent discover",
        "borderagent invalid",
        "joiner disable meshcop 1",
        "joiner invalid meshcop",
        "commdataset invalid",
        "opdataset invalid active",
        "bbrdataset set {}",
        "bbrdataset invalid",
        "panid conflict 1",
        "panid invalid",
        "energy report",
        "energy invalid",
        "netdiag invalid fd00::1",
    ] {
        assert!(
            !command_may_wait_for_commissioner(&tokenize(command).unwrap()),
            "expected local or invalid command: {command}"
        );
    }
}

#[tokio::test]
async fn state_is_disabled_and_active_is_false_before_start() {
    assert_eq!(dispatch_line("state").await, "disabled\n[done]");
    assert_eq!(dispatch_line("active").await, "false\n[done]");
}

#[tokio::test]
async fn invalid_command_reports_the_cpp_help_hint() {
    assert_eq!(
        dispatch_line("bogus").await,
        "'bogus' is not a valid command, type 'help' to list all commands\n[failed]"
    );
}

#[tokio::test]
async fn session_commands_require_a_started_commissioner() {
    assert_eq!(
        dispatch_line("opdataset get active").await,
        format!("{NOT_CONNECTED}\n[failed]")
    );
    assert_eq!(
        dispatch_line("commdataset get").await,
        format!("{NOT_CONNECTED}\n[failed]")
    );
}

#[tokio::test]
async fn out_of_scope_features_fail_with_an_explanation() {
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
}

#[tokio::test]
async fn help_lists_every_command_sorted_with_the_footer() {
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
}

#[tokio::test]
async fn config_set_then_get_pskc_round_trips() {
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
}

#[tokio::test]
async fn too_few_arguments_are_rejected() {
    assert_eq!(
        dispatch_line("config get").await,
        format!("{SYNTAX_FEW_ARGS}\n[failed]")
    );
    assert_eq!(
        dispatch_line("start 127.0.0.1").await,
        format!("{SYNTAX_FEW_ARGS}\n[failed]")
    );
}

#[tokio::test]
async fn evaluate_and_print_handles_blank_bad_and_multi_network_lines() {
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
}

#[tokio::test]
async fn start_validates_address_and_config_before_any_network_use() {
    let mut interpreter = Interpreter::new(CliConfig::default());
    assert_eq!(
        run_line(&mut interpreter, "start nothost nope").await,
        "invalid border-agent address 'nothost:nope'\n[failed]"
    );
    // The default configuration has no PSKc, so start fails before
    // connecting anywhere.
    let no_pskc = run_line(&mut interpreter, "start 127.0.0.1 49191").await;
    assert!(no_pskc.ends_with("[failed]"), "{no_pskc}");
}

#[tokio::test]
async fn start_connect_only_binds_without_petitioning() {
    let mut interpreter = Interpreter::new(CliConfig::default());
    let set = run_line(
        &mut interpreter,
        "config set pskc 00112233445566778899aabbccddeeff",
    )
    .await;
    assert_eq!(set, "[done]");
    // --connect-only binds the UDP socket but defers DTLS and petitioning,
    // so it succeeds without a border agent.
    assert_eq!(
        run_line(&mut interpreter, "start 127.0.0.1 49191 --connect-only").await,
        "[done]"
    );
    assert_eq!(run_line(&mut interpreter, "state").await, ok("connected"));
    assert_eq!(run_line(&mut interpreter, "active").await, ok("false"));
    assert_eq!(
        run_line(&mut interpreter, "sessionid").await,
        "commissioner session is not active\n[failed]"
    );
    // stop resigns; without an active session that fails fast (offline)
    // but still drops the session.
    let stopped = run_line(&mut interpreter, "stop").await;
    assert!(stopped.ends_with("[failed]"), "{stopped}");
    assert_eq!(run_line(&mut interpreter, "state").await, ok("disabled"));
    // stop with no session is a no-op success.
    assert_eq!(run_line(&mut interpreter, "stop").await, "[done]");
}

#[tokio::test]
async fn scripted_session_reports_state_sessionid_and_stops() {
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
}

#[tokio::test]
async fn keepalive_schedule_requires_an_active_session() {
    let mut interpreter = scripted_interpreter([], []).await;
    interpreter.schedule_keepalive();
    assert_eq!(interpreter.keepalive_deadline(), None);

    interpreter = active_interpreter([], []).await;
    interpreter.schedule_keepalive();
    assert!(interpreter.keepalive_deadline().is_some());
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
async fn scheduled_keepalive_uses_the_configured_cadence_and_rearms() {
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
    interpreter.schedule_keepalive();

    let interval = Duration::from_secs(37);
    let first_deadline = interpreter.keepalive_deadline().unwrap();
    assert_eq!(
        first_deadline.saturating_duration_since(tokio::time::Instant::now()),
        interval
    );
    assert_eq!(
        interpreter
            .commissioner
            .as_ref()
            .unwrap()
            .scripted_transport()
            .unwrap()
            .observed_requests()
            .len(),
        1
    );

    tokio::time::advance(interval - Duration::from_secs(1)).await;
    assert!(tokio::time::Instant::now() < first_deadline);
    tokio::time::advance(Duration::from_secs(1)).await;
    interpreter.handle_scheduled_keepalive().await.unwrap();

    let second_deadline = interpreter.keepalive_deadline().unwrap();
    assert_eq!(
        second_deadline.saturating_duration_since(tokio::time::Instant::now()),
        interval
    );
    assert_eq!(
        interpreter
            .commissioner
            .as_ref()
            .unwrap()
            .scripted_transport()
            .unwrap()
            .observed_requests()
            .len(),
        2
    );

    tokio::time::advance(interval).await;
    interpreter.handle_scheduled_keepalive().await.unwrap();
    assert_eq!(
        interpreter
            .commissioner
            .as_ref()
            .unwrap()
            .scripted_transport()
            .unwrap()
            .observed_requests()
            .len(),
        3
    );
    assert!(matches!(
        interpreter
            .commissioner
            .as_mut()
            .unwrap()
            .next_event()
            .await
            .unwrap_err(),
        meshcop::Error::InvalidState("DTLS session is not established")
    ));
}

#[tokio::test(start_paused = true)]
async fn command_that_could_cross_the_deadline_refreshes_keepalive_first() {
    let mut config = CommissionerConfig::pskc("ot-commissioner-rs", [0x11; 16]);
    config.keepalive_interval = Duration::from_secs(30);
    let mut interpreter = active_interpreter_with_config(
        config,
        [
            (
                CommissionerOperation::KeepAlive,
                vec![ScriptedResponse::accept()],
            ),
            (
                CommissionerOperation::GetCommissionerDataset,
                vec![ScriptedResponse::content(Vec::new())],
            ),
            (
                CommissionerOperation::SetCommissionerDataset,
                vec![ScriptedResponse::accept()],
            ),
            (
                CommissionerOperation::KeepAlive,
                vec![ScriptedResponse::accept()],
            ),
            (
                CommissionerOperation::GetBbrDataset,
                vec![ScriptedResponse::content(Vec::new())],
            ),
        ],
        [],
    )
    .await;
    interpreter.schedule_keepalive();

    // Enabling one joiner performs two serial MeshCoP exchanges. With only
    // nine seconds remaining, their receive windows could cross the old
    // deadline, so evaluation must refresh before dispatching either one.
    tokio::time::advance(Duration::from_secs(21)).await;
    interpreter
        .evaluate_and_print("joiner enable meshcop 0x0011223344556677 J01NU5")
        .await;

    let observed_operations: Vec<_> = interpreter
        .commissioner
        .as_ref()
        .unwrap()
        .scripted_transport()
        .unwrap()
        .observed_requests()
        .iter()
        .map(|request| request.operation)
        .collect();
    assert_eq!(
        observed_operations,
        [
            CommissionerOperation::Petition,
            CommissionerOperation::KeepAlive,
            CommissionerOperation::GetCommissionerDataset,
            CommissionerOperation::SetCommissionerDataset,
        ]
    );
    assert_eq!(
        interpreter
            .keepalive_deadline()
            .unwrap()
            .saturating_duration_since(tokio::time::Instant::now()),
        Duration::from_secs(30)
    );

    // The guard is inclusive: dispatch at exactly 28 seconds remaining
    // also refreshes, preserving the documented processing margin.
    tokio::time::advance(Duration::from_secs(2)).await;
    interpreter.evaluate_and_print("bbrdataset get").await;
    let observed_operations: Vec<_> = interpreter
        .commissioner
        .as_ref()
        .unwrap()
        .scripted_transport()
        .unwrap()
        .observed_requests()
        .iter()
        .map(|request| request.operation)
        .collect();
    assert_eq!(
        observed_operations,
        [
            CommissionerOperation::Petition,
            CommissionerOperation::KeepAlive,
            CommissionerOperation::GetCommissionerDataset,
            CommissionerOperation::SetCommissionerDataset,
            CommissionerOperation::KeepAlive,
            CommissionerOperation::GetBbrDataset,
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn command_with_sufficient_headroom_does_not_refresh_early() {
    let mut interpreter = active_interpreter(
        [(
            CommissionerOperation::GetBbrDataset,
            vec![ScriptedResponse::content(Vec::new())],
        )],
        [],
    )
    .await;
    interpreter.schedule_keepalive();
    let deadline = interpreter.keepalive_deadline();

    interpreter.evaluate_and_print("bbrdataset get").await;

    assert_eq!(interpreter.keepalive_deadline(), deadline);
    let observed_operations: Vec<_> = interpreter
        .commissioner
        .as_ref()
        .unwrap()
        .scripted_transport()
        .unwrap()
        .observed_requests()
        .iter()
        .map(|request| request.operation)
        .collect();
    assert_eq!(
        observed_operations,
        [
            CommissionerOperation::Petition,
            CommissionerOperation::GetBbrDataset,
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn replacement_start_refreshes_the_current_session_with_full_headroom() {
    let mut interpreter = active_interpreter(
        [(
            CommissionerOperation::KeepAlive,
            vec![ScriptedResponse::accept()],
        )],
        [],
    )
    .await;
    interpreter.schedule_keepalive();

    interpreter
        .refresh_keepalive_before_command(&tokenize("start 127.0.0.1 49191").unwrap())
        .await
        .unwrap();

    let observed_operations: Vec<_> = interpreter
        .commissioner
        .as_ref()
        .unwrap()
        .scripted_transport()
        .unwrap()
        .observed_requests()
        .iter()
        .map(|request| request.operation)
        .collect();
    assert_eq!(
        observed_operations,
        [
            CommissionerOperation::Petition,
            CommissionerOperation::KeepAlive,
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn rejected_scheduled_keepalive_disarms_the_timer() {
    let mut interpreter = active_interpreter(
        [(
            CommissionerOperation::KeepAlive,
            vec![ScriptedResponse::reject()],
        )],
        [],
    )
    .await;
    interpreter.schedule_keepalive();
    tokio::time::advance(Duration::from_secs(40)).await;

    assert!(matches!(
        interpreter.handle_scheduled_keepalive().await.unwrap_err(),
        meshcop::Error::InvalidState("scheduled keep-alive was rejected")
    ));
    assert_eq!(interpreter.keepalive_deadline(), None);
    assert_eq!(
        interpreter.commissioner.as_ref().unwrap().state(),
        CommissionerState::Disabled
    );
}

#[tokio::test(start_paused = true)]
async fn pending_scheduled_keepalive_disconnects_and_disarms() {
    let mut interpreter = active_interpreter(
        [(
            CommissionerOperation::KeepAlive,
            vec![ScriptedResponse::pending()],
        )],
        [],
    )
    .await;
    interpreter.schedule_keepalive();
    tokio::time::advance(Duration::from_secs(40)).await;

    assert!(matches!(
        interpreter.handle_scheduled_keepalive().await.unwrap_err(),
        meshcop::Error::InvalidState("scheduled keep-alive response is pending")
    ));
    assert_eq!(interpreter.keepalive_deadline(), None);
    assert_eq!(
        interpreter.commissioner.as_ref().unwrap().state(),
        CommissionerState::Disabled
    );
}

#[tokio::test(start_paused = true)]
async fn failed_scheduled_keepalive_disconnects_and_disarms() {
    let mut interpreter =
        active_interpreter([(CommissionerOperation::KeepAlive, Vec::new())], []).await;
    interpreter.schedule_keepalive();
    tokio::time::advance(Duration::from_secs(40)).await;

    assert!(matches!(
        interpreter.handle_scheduled_keepalive().await.unwrap_err(),
        meshcop::Error::InvalidState("scripted MeshCoP exchange did not produce a response")
    ));
    assert_eq!(interpreter.keepalive_deadline(), None);
    assert_eq!(
        interpreter.commissioner.as_ref().unwrap().state(),
        CommissionerState::Disabled
    );
}

#[tokio::test]
async fn borderagent_get_locator_renders_present_and_missing() {
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
}

#[tokio::test]
async fn joiner_commands_drive_steering_and_port_exchanges() {
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
}

#[tokio::test]
async fn commdataset_get_and_set_round_trip_json() {
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
}

#[tokio::test]
async fn bbrdataset_get_renders_raw_tlvs() {
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
}

#[tokio::test]
async fn opdataset_get_projects_every_field_like_the_cpp_cli() {
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
}

#[tokio::test]
async fn opdataset_set_builds_field_and_json_updates() {
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
}

#[tokio::test]
async fn managed_commands_mlr_and_announce_route_through_the_proxy() {
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
}

#[tokio::test(start_paused = true)]
async fn panid_query_and_energy_scan_collect_reports() {
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
}

#[tokio::test]
async fn netdiag_query_and_reset_render_diagnostics() {
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
}

#[tokio::test]
async fn protocol_errors_surface_as_failed_output() {
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
}
