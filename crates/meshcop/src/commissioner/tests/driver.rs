//! Session-driver behavior: automatic keep-alives, session loss, request
//! queueing, event delivery, and connect-only reopening. Timing tests run on
//! paused Tokio time, so deadlines elapse instantly and exactly.

use super::*;

const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
/// Event wait bound for paused-time tests: longer than any virtual wait they
/// expect, and elapsed instantly when a broken session never answers.
const PAUSED_EVENT_WAIT: Duration = Duration::from_secs(300);

/// Starts a scripted session that sends keep-alives on its own every
/// [`KEEPALIVE_INTERVAL`].
async fn automatic_commissioner(script: ScriptedMeshcopTransport) -> (Commissioner, Events) {
    let config = CommissionerConfig::builder("meshcop")
        .pskc([0x11; 16].into())
        .keepalive_interval(KEEPALIVE_INTERVAL)
        .build()
        .unwrap();
    Commissioner::connect_scripted(config, border_agent(), script, [])
        .await
        .unwrap()
}

#[tokio::test(start_paused = true)]
async fn automatic_keep_alives_run_without_the_application() {
    with_paused_test_deadline(async {
        let script = ScriptedMeshcopTransport::new([
            petition_exchange(),
            exchange(
                CommissionerOperation::KeepAlive,
                [ScriptedResponse::accept()],
            ),
            exchange(
                CommissionerOperation::KeepAlive,
                [ScriptedResponse::accept()],
            ),
        ]);
        let (commissioner, mut events) = automatic_commissioner(script).await;
        commissioner.petition().await.unwrap();
        let petitioned_at = tokio::time::Instant::now();

        for expected_at in [KEEPALIVE_INTERVAL, KEEPALIVE_INTERVAL * 2] {
            assert_eq!(
                next_event_within(&mut events, PAUSED_EVENT_WAIT).await,
                Some(CommissionerEvent::KeepAliveResponse(ResultCode::Accept))
            );
            assert_eq!(petitioned_at.elapsed(), expected_at);
        }
        let keep_alive = &commissioner
            .scripted_transport()
            .unwrap()
            .observed_requests()[1];
        assert_eq!(tlv_value(&keep_alive.message, TLV_STATE), Some(vec![0x01]));
        assert_meshcop_session_id(&keep_alive.message);
        assert!(commissioner.status().is_active());
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn manual_keep_alive_mode_never_sends_one_on_its_own() {
    with_paused_test_deadline(async {
        let script = ScriptedMeshcopTransport::new([petition_exchange()]);
        let transport = script.clone();
        // `scripted_commissioner` selects `KeepAlive::Manual`.
        let (commissioner, _events) = scripted_commissioner(script, []).await;
        commissioner.petition().await.unwrap();

        tokio::time::sleep(KEEPALIVE_INTERVAL * 4).await;
        assert_eq!(transport.observed_requests().len(), 1);
        assert!(commissioner.status().is_active());
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_keep_alive_is_sent_on_time_while_application_requests_are_stalled() {
    with_paused_test_deadline(async {
        // Each unanswered request holds the only application slot until its
        // 12-second exchange deadline, so three queued requests keep the slot
        // busy from 0 to 36 seconds. The keep-alive due at 30 seconds must not
        // wait for them: it goes out between the third and fourth requests.
        let unanswered = || exchange(CommissionerOperation::GetActiveDataset, []);
        let script = ScriptedMeshcopTransport::new([
            petition_exchange(),
            unanswered(),
            unanswered(),
            unanswered(),
            exchange(
                CommissionerOperation::KeepAlive,
                [ScriptedResponse::accept()],
            ),
            unanswered(),
        ]);
        let (commissioner, _events) = automatic_commissioner(script).await;
        commissioner.petition().await.unwrap();

        let requests = (0..4)
            .map(|_| {
                let commissioner = commissioner.clone();
                tokio::spawn(async move {
                    commissioner
                        .get_raw_active_dataset(DatasetFlags::EMPTY)
                        .await
                })
            })
            .collect::<Vec<_>>();
        for request in requests {
            assert!(matches!(
                request.await.unwrap().unwrap_err(),
                Error::Timeout("MeshCoP exchange timed out")
            ));
        }

        assert_eq!(
            operations(&commissioner),
            [
                CommissionerOperation::Petition,
                CommissionerOperation::GetActiveDataset,
                CommissionerOperation::GetActiveDataset,
                CommissionerOperation::GetActiveDataset,
                CommissionerOperation::KeepAlive,
                CommissionerOperation::GetActiveDataset,
            ]
        );
        assert!(commissioner.status().is_active());
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn an_outstanding_keep_alive_does_not_hold_back_application_requests() {
    with_paused_test_deadline(async {
        let script = ScriptedMeshcopTransport::new([
            petition_exchange(),
            exchange(CommissionerOperation::KeepAlive, []),
            active_get("prompt"),
        ]);
        let transport = script.clone();
        let (commissioner, _events) = scripted_commissioner(script, []).await;
        commissioner.petition().await.unwrap();
        let keep_alive = {
            let commissioner = commissioner.clone();
            tokio::spawn(async move { commissioner.keep_alive().await })
        };
        wait_until(|| transport.observed_requests().len() == 2).await;

        let started = tokio::time::Instant::now();
        let dataset = commissioner
            .get_active_dataset(DatasetFlags::NETWORK_NAME)
            .await
            .unwrap();
        assert_eq!(dataset.network_name().unwrap(), Some("prompt"));
        assert_eq!(started.elapsed(), Duration::ZERO);
        keep_alive.abort();
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn requests_from_clones_take_turns_and_each_gets_its_own_answer() {
    with_paused_test_deadline(async {
        let script = ScriptedMeshcopTransport::new([
            petition_exchange(),
            active_get("first"),
            active_get("second"),
        ]);
        let (commissioner, _events) = scripted_commissioner(script, []).await;
        commissioner.petition().await.unwrap();

        let first = {
            let commissioner = commissioner.clone();
            tokio::spawn(async move { commissioner.get_active_dataset(DatasetFlags::EMPTY).await })
        };
        let second = {
            let commissioner = commissioner.clone();
            tokio::spawn(async move { commissioner.get_active_dataset(DatasetFlags::EMPTY).await })
        };
        let mut received = Vec::new();
        for task in [first, second] {
            let dataset = task.await.unwrap().unwrap();
            received.push(dataset.network_name().unwrap().unwrap().to_owned());
        }
        received.sort();
        assert_eq!(received, ["first", "second"]);
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_rejected_keep_alive_ends_the_session_and_fails_outstanding_requests() {
    with_paused_test_deadline(async {
        let script = ScriptedMeshcopTransport::new([
            petition_exchange(),
            exchange(CommissionerOperation::GetActiveDataset, []),
            exchange(
                CommissionerOperation::KeepAlive,
                [ScriptedResponse::reject()],
            ),
        ]);
        let (commissioner, mut events) = scripted_commissioner(script, []).await;
        commissioner.petition().await.unwrap();

        let stalled = {
            let commissioner = commissioner.clone();
            tokio::spawn(async move {
                commissioner
                    .get_raw_active_dataset(DatasetFlags::EMPTY)
                    .await
            })
        };
        // Wait until the request is on the wire before the keep-alive.
        let transport = commissioner.scripted_transport().unwrap();
        wait_until(|| transport.observed_requests().len() >= 2).await;
        assert_eq!(commissioner.keep_alive().await.unwrap(), ResultCode::Reject);

        assert!(matches!(
            stalled.await.unwrap().unwrap_err(),
            Error::SessionLost(CloseReason::KeepAliveRejected)
        ));
        assert_eq!(
            commissioner.status(),
            SessionStatus::Closed {
                reason: CloseReason::KeepAliveRejected
            }
        );
        assert_eq!(
            next_event(&mut events).await,
            Some(CommissionerEvent::KeepAliveResponse(ResultCode::Reject))
        );
        assert_eq!(
            next_event(&mut events).await,
            Some(CommissionerEvent::SessionLost {
                reason: CloseReason::KeepAliveRejected
            })
        );
        assert_eq!(next_event(&mut events).await, None);
        assert!(matches!(
            commissioner
                .get_raw_active_dataset(DatasetFlags::EMPTY)
                .await
                .unwrap_err(),
            Error::SessionClosed
        ));
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn an_unanswered_automatic_keep_alive_ends_the_session() {
    with_paused_test_deadline(async {
        let script = ScriptedMeshcopTransport::new([
            petition_exchange(),
            exchange(CommissionerOperation::KeepAlive, []),
        ]);
        let (commissioner, mut events) = automatic_commissioner(script).await;
        commissioner.petition().await.unwrap();

        let lost = CloseReason::KeepAliveFailed {
            error: "timeout: MeshCoP exchange timed out".to_string(),
        };
        assert_eq!(
            next_event_within(&mut events, PAUSED_EVENT_WAIT).await,
            Some(CommissionerEvent::SessionLost {
                reason: lost.clone()
            })
        );
        assert_eq!(
            commissioner.status(),
            SessionStatus::Closed { reason: lost }
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn an_unconfirmed_resignation_is_reported_and_still_ends_the_session() {
    with_paused_test_deadline(async {
        let script = ScriptedMeshcopTransport::new([
            petition_exchange(),
            exchange(
                CommissionerOperation::KeepAlive,
                [ScriptedResponse::pending()],
            ),
        ]);
        let (commissioner, _events) = scripted_commissioner(script, []).await;
        commissioner.petition().await.unwrap();

        assert!(matches!(
            commissioner.resign().await.unwrap_err(),
            Error::InvalidState("resign response is pending")
        ));
        assert_eq!(
            commissioner.status(),
            SessionStatus::Closed {
                reason: CloseReason::Resigned
            }
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn dropping_every_handle_resigns_the_session() {
    with_paused_test_deadline(async {
        let script = ScriptedMeshcopTransport::new([
            petition_exchange(),
            exchange(
                CommissionerOperation::KeepAlive,
                [ScriptedResponse::reject()],
            ),
        ]);
        let observer = script.clone();
        let (commissioner, mut events) = scripted_commissioner(script, []).await;
        commissioner.petition().await.unwrap();
        let clone = commissioner.clone();
        drop(commissioner);
        assert_eq!(
            observer.observed_requests().len(),
            1,
            "a clone is still alive"
        );
        drop(clone);

        // The stream ends once the driver has resigned and stopped.
        assert_eq!(next_event(&mut events).await, None);
        let requests = observer.observed_requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].operation, CommissionerOperation::KeepAlive);
        assert_eq!(tlv_value(&requests[1].message, TLV_STATE), Some(vec![0xff]));
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_subscriber_that_falls_behind_is_told_how_many_events_it_missed() {
    with_paused_test_deadline(async {
        let mut config = CommissionerConfig::pskc("meshcop", [0x11; 16]);
        config.event_capacity = 2;
        let (_commissioner, mut events) = Commissioner::connect_scripted(
            config,
            border_agent(),
            ScriptedMeshcopTransport::new([]),
            [
                CommissionerEvent::DatasetChanged,
                CommissionerEvent::KeepAliveResponse(ResultCode::Accept),
                CommissionerEvent::KeepAliveResponse(ResultCode::Pending),
                CommissionerEvent::KeepAliveResponse(ResultCode::Reject),
            ],
        )
        .await
        .unwrap();

        assert_eq!(
            next_event(&mut events).await,
            Some(CommissionerEvent::Lagged { missed: 2 })
        );
        assert_eq!(
            next_event(&mut events).await,
            Some(CommissionerEvent::KeepAliveResponse(ResultCode::Pending))
        );
        assert_eq!(
            next_event(&mut events).await,
            Some(CommissionerEvent::KeepAliveResponse(ResultCode::Reject))
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_connect_only_session_closed_by_the_peer_goes_idle_and_reopens_on_demand() {
    with_paused_test_deadline(async {
        let script = ScriptedMeshcopTransport::new([
            exchange(
                CommissionerOperation::GetActiveDataset,
                [
                    ScriptedResponse::content(dataset_with_name("before").to_bytes().unwrap()),
                    ScriptedResponse::PeerClosed,
                ],
            ),
            active_get("after"),
        ]);
        let (commissioner, mut events) = scripted_commissioner(script, []).await;

        let before = commissioner
            .get_active_dataset(DatasetFlags::NETWORK_NAME)
            .await
            .unwrap();
        assert_eq!(before.network_name().unwrap(), Some("before"));
        wait_until(|| commissioner.status() == SessionStatus::Idle).await;

        let after = commissioner
            .get_active_dataset(DatasetFlags::NETWORK_NAME)
            .await
            .unwrap();
        assert_eq!(after.network_name().unwrap(), Some("after"));
        assert_eq!(commissioner.status(), SessionStatus::Connected);
        // An expected close of an unpetitioned session is not a lost session.
        assert_no_event(&mut events).await;
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_peer_close_ends_an_active_session() {
    with_paused_test_deadline(async {
        let script = ScriptedMeshcopTransport::new([exchange(
            CommissionerOperation::Petition,
            [
                ScriptedResponse::petition_accept(SESSION_ID),
                ScriptedResponse::PeerClosed,
            ],
        )]);
        let (commissioner, mut events) = scripted_commissioner(script, []).await;
        commissioner.petition().await.unwrap();

        assert_eq!(
            next_event(&mut events).await,
            Some(CommissionerEvent::SessionLost {
                reason: CloseReason::PeerClosed
            })
        );
        assert_eq!(
            commissioner.status(),
            SessionStatus::Closed {
                reason: CloseReason::PeerClosed
            }
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_transport_failure_ends_the_session_and_fails_outstanding_requests() {
    with_paused_test_deadline(async {
        let script = ScriptedMeshcopTransport::new([
            petition_exchange(),
            exchange(
                CommissionerOperation::GetActiveDataset,
                [ScriptedResponse::TransportFailure],
            ),
        ]);
        let (commissioner, mut events) = scripted_commissioner(script, []).await;
        commissioner.petition().await.unwrap();

        let lost = CloseReason::TransportFailed {
            error: "I/O error: scripted transport failure".to_string(),
        };
        assert!(matches!(
            commissioner
                .get_raw_active_dataset(DatasetFlags::EMPTY)
                .await
                .unwrap_err(),
            Error::SessionLost(reason) if reason == lost
        ));
        assert_eq!(
            next_event(&mut events).await,
            Some(CommissionerEvent::SessionLost {
                reason: lost.clone()
            })
        );
        assert_eq!(
            commissioner.status(),
            SessionStatus::Closed { reason: lost }
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_failed_send_ends_the_session() {
    with_paused_test_deadline(async {
        let script = ScriptedMeshcopTransport::new([petition_exchange()]);
        let transport = script.clone();
        let (commissioner, mut events) = scripted_commissioner(script, []).await;
        commissioner.petition().await.unwrap();
        transport.fail_sends();

        assert!(matches!(
            commissioner
                .get_raw_active_dataset(DatasetFlags::EMPTY)
                .await
                .unwrap_err(),
            Error::Io(_)
        ));
        let lost = CloseReason::TransportFailed {
            error: "I/O error: scripted send failure".to_string(),
        };
        assert_eq!(
            next_event(&mut events).await,
            Some(CommissionerEvent::SessionLost {
                reason: lost.clone()
            })
        );
        assert_eq!(
            commissioner.status(),
            SessionStatus::Closed { reason: lost }
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn an_unanswered_confirmable_request_backs_off_between_retransmissions() {
    with_paused_test_deadline(async {
        let script = ScriptedMeshcopTransport::new([
            petition_exchange(),
            exchange(CommissionerOperation::GetActiveDataset, []),
        ]);
        let transport = script.clone();
        let (commissioner, _events) = scripted_commissioner(script, []).await;
        commissioner.petition().await.unwrap();
        let started = tokio::time::Instant::now();
        let request = {
            let commissioner = commissioner.clone();
            tokio::spawn(async move {
                commissioner
                    .get_raw_active_dataset(DatasetFlags::EMPTY)
                    .await
            })
        };
        let retransmissions = || {
            let request = &transport.observed_requests()[1].message;
            transport
                .sent_messages()
                .iter()
                .filter(|sent| sent.message_id == request.message_id)
                .count()
        };

        // The first timeout is randomized within 2-3 s and doubles after
        // each retransmission, so the second retransmission comes 4-6 s
        // after the first, and no third one fits the 12 s exchange budget.
        for (at_millis, expected) in [(1_900, 0), (3_100, 1), (5_900, 1), (9_100, 2), (11_900, 2)] {
            tokio::time::sleep_until(started + Duration::from_millis(at_millis)).await;
            assert_eq!(retransmissions(), expected, "at {at_millis} ms");
        }
        assert!(matches!(
            request.await.unwrap().unwrap_err(),
            Error::Timeout("MeshCoP exchange timed out")
        ));
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_request_that_fails_without_a_transport_error_fails_alone() {
    with_paused_test_deadline(async {
        let script = ScriptedMeshcopTransport::new([
            petition_exchange(),
            // Scripted for a different operation, so sending the next
            // request fails inside the harness rather than on the wire.
            exchange(CommissionerOperation::GetPendingDataset, []),
            active_get("after"),
        ]);
        let (commissioner, _events) = scripted_commissioner(script, []).await;
        commissioner.petition().await.unwrap();

        assert!(matches!(
            commissioner
                .get_raw_active_dataset(DatasetFlags::EMPTY)
                .await
                .unwrap_err(),
            Error::InvalidState("scripted MeshCoP operation mismatch")
        ));
        assert!(commissioner.status().is_active());
        let after = commissioner
            .get_active_dataset(DatasetFlags::NETWORK_NAME)
            .await
            .unwrap();
        assert_eq!(after.network_name().unwrap(), Some("after"));
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn connect_returns_a_petition_rejection_and_stops_the_session() {
    with_paused_test_deadline(async {
        let pskc = [0x11; 16];
        let server = meshcop_dtls::DtlsServer::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr();
        let border_agent = async move {
            let mut session = server.accept(&pskc, Duration::from_secs(10)).await.unwrap();
            let request = CoapMessage::decode(
                &session
                    .recv_application_data(Duration::from_secs(10))
                    .await
                    .unwrap(),
            )
            .unwrap();
            let mut payload = vec![TLV_STATE, 1, 0xff];
            payload.extend_from_slice(&[TLV_COMMISSIONER_ID, 5]);
            payload.extend_from_slice(b"other");
            let response = CoapMessage {
                ty: CoapType::Acknowledgement,
                code: CoapCode::CHANGED,
                message_id: request.message_id,
                token: request.token,
                options: Vec::new(),
                payload,
            };
            session
                .send_application_data(&response.encode().unwrap())
                .await
                .unwrap();
        };

        let ((), connected) = tokio::join!(
            border_agent,
            Commissioner::connect(CommissionerConfig::pskc("meshcop", pskc), addr)
        );
        assert!(matches!(
            connected.unwrap_err(),
            Error::PetitionRejected {
                existing_commissioner_id: Some(id)
            } if id == "other"
        ));
    })
    .await
}
