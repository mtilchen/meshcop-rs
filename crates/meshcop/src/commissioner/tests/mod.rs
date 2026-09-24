use std::{
    net::{Ipv6Addr, SocketAddr},
    time::Duration,
};

use super::{
    harness::{ScriptedExchange, ScriptedMeshcopTransport, ScriptedResponse, run_with_deadline},
    *,
};
use crate::{
    Error,
    dataset::{
        Dataset, TLV_NETWORK_NAME as DATASET_TLV_NETWORK_NAME,
        TLV_PENDING_TIMESTAMP as DATASET_TLV_PENDING_TIMESTAMP,
    },
    meshcop::{
        CoapCode, CoapMessage, CoapType, CommissionerOperation, NETWORK_DIAG_TLV_TYPE_LIST,
        THREAD_TLV_COMMISSIONER_SESSION_ID, THREAD_TLV_STATUS, TLV_BORDER_AGENT_LOCATOR,
        TLV_COMMISSIONER_ID, TLV_COMMISSIONER_SESSION_ID, TLV_GET, TLV_JOINER_DTLS_ENCAPSULATION,
        TLV_JOINER_IID, TLV_JOINER_UDP_PORT, TLV_NETWORK_NAME, TLV_SECURE_DISSEMINATION, TLV_STATE,
        TLV_STEERING_DATA,
    },
    tlv::TlvSet,
};

mod api;
mod driver;
mod duplicates;
mod joiner_sessions;
mod lifecycle;
mod matching;
mod more;
mod routing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublicCommissionerMethod {
    Connect,
    Status,
    SessionId,
    BorderAgent,
    Config,
    Subscribe,
    Petition,
    KeepAlive,
    Resign,
    GetActiveDataset,
    GetRawActiveDataset,
    GetPendingDataset,
    SetActiveDataset,
    SetPendingDataset,
    SetSecurePendingDataset,
    GetCommissionerDataset,
    SetCommissionerDataset,
    GetBbrDataset,
    SetBbrDataset,
    AnnounceBegin,
    PanIdQuery,
    EnergyScan,
    RegisterMulticastListener,
    CommandReenroll,
    CommandDomainReset,
    CommandMigrate,
    DiagnosticGet,
    DiagnosticReset,
    SendToJoiner,
    Request,
    RequestToken,
    SetToken,
    Events,
}

impl PublicCommissionerMethod {
    async fn assert_covered(self) {
        if self == Self::Connect {
            self.assert_connect_method_covered().await;
            return;
        }

        let script = ScriptedMeshcopTransport::new(self.script());
        let initial_events = if self == Self::Events {
            vec![CommissionerEvent::DatasetChanged]
        } else {
            Vec::new()
        };
        let (commissioner, mut events) = scripted_commissioner(script, initial_events).await;

        if self.needs_active_session() {
            commissioner.petition().await.unwrap();
            assert_eq!(commissioner.session_id(), Some(0xcafe), "{self:?}");
        }

        self.call(&commissioner, &mut events).await;
        self.assert_observed(&commissioner);
    }

    async fn assert_connect_method_covered(self) {
        let pskc = [0x11; 16];
        let server = meshcop_dtls::DtlsServer::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr();
        let accept = async move { server.accept(&pskc, Duration::from_secs(10)).await };
        let (session, connected) = tokio::join!(
            accept,
            Commissioner::connect_only(CommissionerConfig::pskc("test", pskc), addr)
        );
        session.unwrap();
        let (commissioner, _events) = connected.unwrap();

        assert_eq!(commissioner.status(), SessionStatus::Connected, "{self:?}");
        assert_eq!(commissioner.border_agent(), addr, "{self:?}");
    }

    fn script(self) -> Vec<ScriptedExchange> {
        let mut script = Vec::new();
        if self.needs_active_session() {
            script.push(exchange(
                CommissionerOperation::Petition,
                [ScriptedResponse::petition_accept(0xcafe)],
            ));
        }
        if let Some(operation) = self.expected_operation() {
            script.push(exchange(operation, [self.response()]));
        }
        script
    }

    fn needs_active_session(self) -> bool {
        matches!(
            self,
            Self::KeepAlive
                | Self::Resign
                | Self::GetActiveDataset
                | Self::GetRawActiveDataset
                | Self::GetPendingDataset
                | Self::SetActiveDataset
                | Self::SetPendingDataset
                | Self::SetSecurePendingDataset
                | Self::GetCommissionerDataset
                | Self::SetCommissionerDataset
                | Self::GetBbrDataset
                | Self::SetBbrDataset
                | Self::AnnounceBegin
                | Self::PanIdQuery
                | Self::EnergyScan
                | Self::RegisterMulticastListener
                | Self::CommandReenroll
                | Self::CommandDomainReset
                | Self::CommandMigrate
                | Self::DiagnosticGet
                | Self::DiagnosticReset
                | Self::SendToJoiner
        )
    }

    fn expected_operation(self) -> Option<CommissionerOperation> {
        match self {
            Self::Petition => Some(CommissionerOperation::Petition),
            Self::KeepAlive => Some(CommissionerOperation::KeepAlive),
            Self::Resign => Some(CommissionerOperation::KeepAlive),
            Self::GetActiveDataset | Self::GetRawActiveDataset => {
                Some(CommissionerOperation::GetActiveDataset)
            }
            Self::GetPendingDataset => Some(CommissionerOperation::GetPendingDataset),
            Self::SetActiveDataset => Some(CommissionerOperation::SetActiveDataset),
            Self::SetPendingDataset => Some(CommissionerOperation::SetPendingDataset),
            Self::SetSecurePendingDataset => Some(CommissionerOperation::SetSecurePendingDataset),
            Self::GetCommissionerDataset => Some(CommissionerOperation::GetCommissionerDataset),
            Self::SetCommissionerDataset => Some(CommissionerOperation::SetCommissionerDataset),
            Self::GetBbrDataset => Some(CommissionerOperation::GetBbrDataset),
            Self::SetBbrDataset => Some(CommissionerOperation::SetBbrDataset),
            Self::AnnounceBegin => Some(CommissionerOperation::AnnounceBegin),
            Self::PanIdQuery => Some(CommissionerOperation::PanIdQuery),
            Self::EnergyScan => Some(CommissionerOperation::EnergyScan),
            Self::RegisterMulticastListener => {
                Some(CommissionerOperation::RegisterMulticastListener)
            }
            Self::CommandReenroll => Some(CommissionerOperation::Reenroll),
            Self::CommandDomainReset => Some(CommissionerOperation::DomainReset),
            Self::CommandMigrate => Some(CommissionerOperation::Migrate),
            Self::DiagnosticGet => Some(CommissionerOperation::DiagnosticGet),
            Self::DiagnosticReset => Some(CommissionerOperation::DiagnosticReset),
            Self::SendToJoiner => Some(CommissionerOperation::SendToJoiner),
            Self::Request => Some(CommissionerOperation::GetActiveDataset),
            Self::Connect
            | Self::Status
            | Self::SessionId
            | Self::BorderAgent
            | Self::Config
            | Self::Subscribe
            | Self::RequestToken
            | Self::SetToken
            | Self::Events => None,
        }
    }

    fn response(self) -> ScriptedResponse {
        match self {
            Self::Petition => ScriptedResponse::petition_accept(0xcafe),
            Self::KeepAlive => ScriptedResponse::accept(),
            Self::Resign => ScriptedResponse::reject(),
            Self::GetActiveDataset | Self::GetRawActiveDataset | Self::Request => {
                ScriptedResponse::content(dataset_with_name("active").to_bytes().unwrap())
            }
            Self::GetPendingDataset => {
                ScriptedResponse::content(pending_dataset_with_name("pending").to_bytes().unwrap())
            }
            Self::GetCommissionerDataset => {
                ScriptedResponse::content(dataset_with_name("commissioner").to_bytes().unwrap())
            }
            Self::GetBbrDataset => {
                ScriptedResponse::content(dataset_with_name("bbr").to_bytes().unwrap())
            }
            Self::RegisterMulticastListener => {
                ScriptedResponse::content(vec![THREAD_TLV_STATUS, 1, 0])
            }
            Self::SetActiveDataset
            | Self::SetPendingDataset
            | Self::SetSecurePendingDataset
            | Self::SetCommissionerDataset
            | Self::SetBbrDataset => ScriptedResponse::accept(),
            Self::AnnounceBegin
            | Self::PanIdQuery
            | Self::EnergyScan
            | Self::CommandReenroll
            | Self::CommandDomainReset
            | Self::CommandMigrate
            | Self::DiagnosticGet
            | Self::DiagnosticReset
            | Self::SendToJoiner => ScriptedResponse::changed_without_state(),
            Self::Connect
            | Self::Status
            | Self::SessionId
            | Self::BorderAgent
            | Self::Config
            | Self::Subscribe
            | Self::RequestToken
            | Self::SetToken
            | Self::Events => ScriptedResponse::changed_without_state(),
        }
    }

    async fn call(self, commissioner: &Commissioner, events: &mut Events) {
        match self {
            Self::Connect => unreachable!("connect is covered before a Commissioner exists"),
            Self::Status => {
                assert_eq!(commissioner.status(), SessionStatus::Connected);
            }
            Self::SessionId => {
                assert_eq!(commissioner.session_id(), None);
            }
            Self::BorderAgent => {
                assert_eq!(commissioner.border_agent(), border_agent());
            }
            Self::Config => {
                assert_eq!(commissioner.config().commissioner_id, "meshcop");
            }
            Self::Subscribe => {
                let mut subscriber = commissioner.subscribe();
                commissioner.resign().await.unwrap();
                assert_eq!(next_event(&mut subscriber).await, None);
            }
            Self::Petition => {
                let petition = commissioner.petition().await.unwrap();
                assert_eq!(petition.session_id, 0xcafe);
            }
            Self::KeepAlive => {
                assert_eq!(commissioner.keep_alive().await.unwrap(), ResultCode::Accept);
                assert_eq!(
                    next_event(events).await,
                    Some(CommissionerEvent::KeepAliveResponse(ResultCode::Accept))
                );
            }
            Self::Resign => {
                commissioner.resign().await.unwrap();
                assert_eq!(
                    commissioner.status(),
                    SessionStatus::Closed {
                        reason: CloseReason::Resigned
                    }
                );
                assert!(matches!(
                    commissioner.petition().await.unwrap_err(),
                    Error::SessionClosed
                ));
            }
            Self::GetActiveDataset => {
                let dataset = commissioner
                    .get_active_dataset(DatasetFlags::NETWORK_NAME)
                    .await
                    .unwrap();
                assert_eq!(dataset.network_name().unwrap(), Some("active"));
            }
            Self::GetRawActiveDataset => {
                let bytes = commissioner
                    .get_raw_active_dataset(DatasetFlags::EMPTY)
                    .await
                    .unwrap();
                assert_eq!(
                    Dataset::from_bytes(&bytes).unwrap().network_name().unwrap(),
                    Some("active")
                );
            }
            Self::GetPendingDataset => {
                let dataset = commissioner
                    .get_pending_dataset(DatasetFlags::PENDING_TIMESTAMP)
                    .await
                    .unwrap();
                assert_eq!(dataset.network_name().unwrap(), Some("pending"));
            }
            Self::SetActiveDataset => {
                commissioner
                    .set_active_dataset(&active_dataset_with_name("active-set"))
                    .await
                    .unwrap();
            }
            Self::SetPendingDataset => {
                commissioner
                    .set_pending_dataset(&pending_dataset_with_name("pending-set"))
                    .await
                    .unwrap();
            }
            Self::SetSecurePendingDataset => {
                commissioner
                    .set_secure_pending_dataset(120, &pending_dataset_with_name("secure-pending"))
                    .await
                    .unwrap();
            }
            Self::GetCommissionerDataset => {
                let dataset = commissioner
                    .get_commissioner_dataset(CommissionerDatasetFlags::STEERING_DATA)
                    .await
                    .unwrap();
                assert_eq!(dataset.network_name().unwrap(), Some("commissioner"));
            }
            Self::SetCommissionerDataset => {
                commissioner
                    .set_commissioner_dataset(&dataset_with_name("commissioner-set"))
                    .await
                    .unwrap();
            }
            Self::GetBbrDataset => {
                let dataset = commissioner
                    .get_bbr_dataset(CommissionerDatasetFlags::BORDER_AGENT_LOCATOR)
                    .await
                    .unwrap();
                assert_eq!(dataset.network_name().unwrap(), Some("bbr"));
            }
            Self::SetBbrDataset => {
                commissioner
                    .set_bbr_dataset(&dataset_with_name("bbr-set"))
                    .await
                    .unwrap();
            }
            Self::AnnounceBegin => {
                commissioner
                    .announce_begin(0x07fff800, 2, 100, multicast_destination())
                    .await
                    .unwrap();
            }
            Self::PanIdQuery => {
                commissioner
                    .pan_id_query(0x07fff800, 0xface, unicast_destination())
                    .await
                    .unwrap();
            }
            Self::EnergyScan => {
                commissioner
                    .energy_scan(0x07fff800, 2, 100, 50, multicast_destination())
                    .await
                    .unwrap();
            }
            Self::RegisterMulticastListener => {
                assert_eq!(
                    commissioner
                        .register_multicast_listener(&["ff05::1".to_string()], 300)
                        .await
                        .unwrap(),
                    0
                );
            }
            Self::CommandReenroll => commissioner
                .command_reenroll(unicast_destination())
                .await
                .unwrap(),
            Self::CommandDomainReset => commissioner
                .command_domain_reset(unicast_destination())
                .await
                .unwrap(),
            Self::CommandMigrate => {
                commissioner
                    .command_migrate(unicast_destination(), "designated-net")
                    .await
                    .unwrap();
            }
            Self::DiagnosticGet => commissioner
                .diagnostic_get(Some(unicast_destination()), 0b101)
                .await
                .unwrap(),
            Self::DiagnosticReset => commissioner
                .diagnostic_reset(Some(unicast_destination()), 0b101)
                .await
                .unwrap(),
            Self::SendToJoiner => {
                commissioner
                    .send_to_joiner(&[1, 2, 3, 4, 5, 6, 7, 8], 1000, b"dtls")
                    .await
                    .unwrap();
            }
            Self::Request => {
                let request = CoapMessage::post_request(
                    CoapType::Confirmable,
                    0,
                    Vec::new(),
                    crate::meshcop::uri::MGMT_ACTIVE_GET,
                    Vec::new(),
                )
                .unwrap();
                let response = commissioner
                    .request(Destination::BorderAgent, request)
                    .await
                    .unwrap();
                assert_eq!(response.code, CoapCode::CONTENT);
                assert_eq!(
                    Dataset::from_bytes(&response.payload)
                        .unwrap()
                        .network_name()
                        .unwrap(),
                    Some("active")
                );
            }
            Self::RequestToken => assert!(matches!(
                commissioner
                    .request_token("127.0.0.1:49156".parse().unwrap())
                    .await
                    .unwrap_err(),
                Error::Unsupported("CCM token request is deferred")
            )),
            Self::SetToken => assert!(matches!(
                commissioner.set_token(b"token").unwrap_err(),
                Error::Unsupported("CCM token support is deferred")
            )),
            Self::Events => {
                assert_eq!(
                    next_event(events).await,
                    Some(CommissionerEvent::DatasetChanged)
                );
            }
        }
    }

    fn assert_observed(self, commissioner: &Commissioner) {
        let harness = commissioner.scripted_transport().unwrap();
        let requests = harness.observed_requests();
        if let Some(expected) = self.expected_operation() {
            let request = requests
                .last()
                .expect("scripted operation was not observed");
            assert_eq!(request.operation, expected, "{self:?}");
            self.assert_request_shape(&logical_message(request));
        } else if self.needs_active_session() {
            assert_eq!(requests.len(), 1, "{self:?}");
            assert_eq!(
                requests[0].operation,
                CommissionerOperation::Petition,
                "{self:?}"
            );
        } else {
            assert!(requests.is_empty(), "{self:?}");
        }
    }

    fn assert_request_shape(self, request: &CoapMessage) {
        match self {
            Self::Petition => assert_eq!(
                tlv_value(request, TLV_COMMISSIONER_ID),
                Some(b"meshcop".to_vec())
            ),
            Self::Resign => {
                assert_eq!(tlv_value(request, TLV_STATE), Some(vec![0xff]));
                assert_meshcop_session_id(request);
            }
            Self::KeepAlive => {
                assert_eq!(tlv_value(request, TLV_STATE), Some(vec![0x01]));
                assert_meshcop_session_id(request);
            }
            Self::GetActiveDataset => assert_eq!(
                tlv_value(request, TLV_GET),
                Some(vec![DATASET_TLV_NETWORK_NAME])
            ),
            Self::GetRawActiveDataset | Self::Request => {
                assert_eq!(tlv_value(request, TLV_GET), None);
            }
            Self::GetPendingDataset => assert_eq!(
                tlv_value(request, TLV_GET),
                Some(vec![DATASET_TLV_PENDING_TIMESTAMP])
            ),
            Self::GetCommissionerDataset => {
                assert_eq!(tlv_value(request, TLV_GET), Some(vec![TLV_STEERING_DATA]));
            }
            Self::GetBbrDataset => {
                assert_eq!(
                    tlv_value(request, TLV_GET),
                    Some(vec![TLV_BORDER_AGENT_LOCATOR])
                );
            }
            Self::SetSecurePendingDataset => {
                assert_meshcop_session_id(request);
                assert!(tlv_value(request, TLV_SECURE_DISSEMINATION).is_some());
            }
            Self::SetActiveDataset
            | Self::SetPendingDataset
            | Self::SetCommissionerDataset
            | Self::SetBbrDataset
            | Self::AnnounceBegin
            | Self::PanIdQuery
            | Self::EnergyScan
            | Self::CommandReenroll
            | Self::CommandDomainReset
            | Self::CommandMigrate => assert_meshcop_session_id(request),
            Self::RegisterMulticastListener => assert_eq!(
                tlv_value(request, THREAD_TLV_COMMISSIONER_SESSION_ID),
                Some(0xcafeu16.to_be_bytes().to_vec())
            ),
            Self::DiagnosticGet | Self::DiagnosticReset => {
                assert!(tlv_value(request, NETWORK_DIAG_TLV_TYPE_LIST).is_some());
            }
            Self::SendToJoiner => {
                assert_eq!(
                    tlv_value(request, TLV_JOINER_IID),
                    Some(vec![1, 2, 3, 4, 5, 6, 7, 8])
                );
                assert_eq!(
                    tlv_value(request, TLV_JOINER_DTLS_ENCAPSULATION),
                    Some(b"dtls".to_vec())
                );
            }
            Self::Connect
            | Self::Status
            | Self::SessionId
            | Self::BorderAgent
            | Self::Config
            | Self::Subscribe
            | Self::RequestToken
            | Self::SetToken
            | Self::Events => {}
        }
    }
}

fn prefixed_dataset() -> Dataset {
    let mut dataset = Dataset::default();
    dataset.set_raw(
        crate::dataset::TLV_MESH_LOCAL_PREFIX,
        TEST_MESH_LOCAL_PREFIX,
    );
    dataset
}

const SESSION_ID: u16 = 0xcafe;

fn petition_exchange() -> ScriptedExchange {
    exchange(
        CommissionerOperation::Petition,
        [ScriptedResponse::petition_accept(SESSION_ID)],
    )
}

fn active_get(name: &str) -> ScriptedExchange {
    exchange(
        CommissionerOperation::GetActiveDataset,
        [ScriptedResponse::content(
            dataset_with_name(name).to_bytes().unwrap(),
        )],
    )
}

/// The operations the session has sent, in order.
fn operations(commissioner: &Commissioner) -> Vec<CommissionerOperation> {
    commissioner
        .scripted_transport()
        .unwrap()
        .observed_requests()
        .iter()
        .map(|request| request.operation)
        .collect()
}

/// The `index`th request the session sent, as its recipient sees it.
fn sent_request(transport: &ScriptedMeshcopTransport, index: usize) -> CoapMessage {
    logical_message(&transport.observed_requests()[index])
}

/// A piggybacked answer to `request`.
fn answer(request: &CoapMessage, code: CoapCode, payload: Vec<u8>) -> CoapMessage {
    CoapMessage {
        ty: CoapType::Acknowledgement,
        code,
        message_id: request.message_id,
        token: request.token.clone(),
        options: Vec::new(),
        payload,
    }
}

fn exchange(
    operation: CommissionerOperation,
    responses: impl IntoIterator<Item = ScriptedResponse>,
) -> ScriptedExchange {
    ScriptedExchange::new(operation, responses)
}

fn border_agent() -> SocketAddr {
    "127.0.0.1:49156".parse().unwrap()
}

/// Mesh-local prefix used to pre-seed proxied tests (fd00:db8::/64).
const TEST_MESH_LOCAL_PREFIX: [u8; 8] = [0xfd, 0x00, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00];

/// Starts a scripted session with manual keep-alives, so a script sees only
/// the exchanges the test drives. Automatic keep-alives have dedicated tests.
async fn scripted_commissioner(
    script: ScriptedMeshcopTransport,
    initial_events: impl IntoIterator<Item = CommissionerEvent>,
) -> (Commissioner, Events) {
    let mut config = CommissionerConfig::pskc("meshcop", [0x11; 16]);
    config.keep_alive = KeepAlive::Manual;
    let (commissioner, events) =
        Commissioner::connect_scripted(config, border_agent(), script, initial_events)
            .await
            .unwrap();
    // Most scripted tests exercise the MeshCoP exchanges themselves; the
    // mesh-local prefix fetch backing ALOC routing has dedicated tests.
    commissioner.set_cached_mesh_local_prefix(Some(TEST_MESH_LOCAL_PREFIX));
    (commissioner, events)
}

fn multicast_destination() -> Ipv6Addr {
    "ff03::1".parse().unwrap()
}

fn unicast_destination() -> Ipv6Addr {
    "fd00::1".parse().unwrap()
}

/// Returns the request a Thread device would observe: the UDP_TX inner
/// request for proxied operations, the message itself otherwise.
fn logical_message(request: &super::harness::ObservedRequest) -> CoapMessage {
    request
        .inner_message()
        .unwrap_or_else(|| request.message.clone())
}

fn dataset_with_name(name: &str) -> Dataset {
    let mut dataset = Dataset::default();
    dataset.set_raw(DATASET_TLV_NETWORK_NAME, name.as_bytes());
    dataset
}

fn active_dataset_with_name(name: &str) -> Dataset {
    let mut dataset = dataset_with_name(name);
    dataset.set_raw(crate::dataset::TLV_ACTIVE_TIMESTAMP, 1u64.to_be_bytes());
    dataset
}

fn pending_dataset_with_name(name: &str) -> Dataset {
    let mut dataset = active_dataset_with_name(name);
    dataset.set_raw(DATASET_TLV_PENDING_TIMESTAMP, 1u64.to_be_bytes());
    dataset.set_raw(crate::dataset::TLV_DELAY_TIMER, 30_000u32.to_be_bytes());
    dataset
}

fn tlv_value(message: &CoapMessage, ty: u8) -> Option<Vec<u8>> {
    TlvSet::parse(&message.payload)
        .unwrap()
        .last_value(ty)
        .map(<[u8]>::to_vec)
}

fn dataset_changed_notification(message_id: u16, confirmable: bool) -> CoapMessage {
    let mut message = CoapMessage {
        ty: if confirmable {
            CoapType::Confirmable
        } else {
            CoapType::NonConfirmable
        },
        code: CoapCode::POST,
        message_id,
        token: vec![0x99],
        options: Vec::new(),
        payload: Vec::new(),
    };
    message
        .set_uri_path(crate::meshcop::uri::MGMT_DATASET_CHANGED)
        .unwrap();
    message
}

fn assert_meshcop_session_id(request: &CoapMessage) {
    assert_eq!(
        tlv_value(request, TLV_COMMISSIONER_SESSION_ID),
        Some(0xcafeu16.to_be_bytes().to_vec())
    );
}

fn observed(
    requests: &[super::harness::ObservedRequest],
    operation: CommissionerOperation,
) -> &super::harness::ObservedRequest {
    requests
        .iter()
        .find(|request| request.operation == operation)
        .unwrap()
}

/// Upper bound on waiting for an expected event or state change in a
/// real-time test, so a broken session fails the test instead of hanging it.
const EVENT_WAIT: Duration = Duration::from_secs(5);

/// Waits up to [`EVENT_WAIT`] for the next event.
async fn next_event(events: &mut Events) -> Option<CommissionerEvent> {
    next_event_within(events, EVENT_WAIT).await
}

/// Waits up to `bound` for the next event; paused-time tests pass bounds
/// longer than the virtual time they expect to elapse.
async fn next_event_within(events: &mut Events, bound: Duration) -> Option<CommissionerEvent> {
    tokio::time::timeout(bound, events.next())
        .await
        .expect("no event arrived in time")
}

/// Waits up to [`EVENT_WAIT`] until `condition` holds.
async fn wait_until(mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(EVENT_WAIT, async {
        while !condition() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("condition did not hold in time");
}

/// Asserts that no event reaches `events` within a short window.
async fn assert_no_event(events: &mut Events) {
    const NO_EVENT_WINDOW: Duration = Duration::from_millis(100);
    let next = tokio::time::timeout(NO_EVENT_WINDOW, events.next()).await;
    assert!(next.is_err(), "unexpected event {next:?}");
}

/// Bound on a real-time test's run time. A mutation that stalls the session
/// then fails the test well inside the mutation-testing timeout instead of
/// hanging it; baseline tests finish in a fraction of this.
const TEST_DEADLINE: Duration = Duration::from_secs(3);
/// Bound on a paused-time test's virtual run time: longer than any test waits,
/// and elapsed instantly when a stalled session leaves nothing else to run.
const PAUSED_TEST_DEADLINE: Duration = Duration::from_secs(3600);

/// Runs a real-time test body, failing it if it exceeds [`TEST_DEADLINE`].
async fn with_test_deadline(body: impl std::future::Future<Output = ()>) {
    run_with_deadline(TEST_DEADLINE, body).await;
}

/// Bound for the real-DTLS retransmission tests, which wait out CoAP timers
/// (2-4 s) on real time to prove a retransmission does or does not happen.
const SLOW_TEST_DEADLINE: Duration = Duration::from_secs(8);

/// Runs a real-time test body that waits out CoAP timers, failing it if it
/// exceeds [`SLOW_TEST_DEADLINE`].
async fn with_slow_test_deadline(body: impl std::future::Future<Output = ()>) {
    run_with_deadline(SLOW_TEST_DEADLINE, body).await;
}

/// Runs a paused-time test body, failing it if it exceeds
/// [`PAUSED_TEST_DEADLINE`] of virtual time.
async fn with_paused_test_deadline(body: impl std::future::Future<Output = ()>) {
    run_with_deadline(PAUSED_TEST_DEADLINE, body).await;
}
