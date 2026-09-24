//! Request and session lifecycle: withdrawn requests, the limits on
//! session-control exchanges, send failures, and a session task that stops.

use super::*;

/// Past an unanswered request's 12-second exchange deadline.
const PAST_EXCHANGE_DEADLINE: Duration = Duration::from_secs(20);

fn unanswered(operation: CommissionerOperation) -> ScriptedExchange {
    exchange(operation, [])
}

#[tokio::test(start_paused = true)]
async fn a_request_dropped_while_queued_is_never_sent() {
    with_paused_test_deadline(async {
        let script = ScriptedMeshcopTransport::new([
            petition_exchange(),
            unanswered(CommissionerOperation::GetActiveDataset),
            active_get("waited"),
        ]);
        let transport = script.clone();
        let (commissioner, _events) = scripted_commissioner(script, []).await;
        commissioner.petition().await.unwrap();
        let read = |flags| {
            let commissioner = commissioner.clone();
            tokio::spawn(async move { commissioner.get_active_dataset(flags).await })
        };
        let holding_the_slot = read(DatasetFlags::EMPTY);
        wait_until(|| transport.observed_requests().len() == 2).await;
        let waiting = read(DatasetFlags::NETWORK_NAME);

        // Queued behind `waiting`; withdrawing it must leave `waiting` queued.
        let abandoned = tokio::time::timeout(
            Duration::from_secs(1),
            commissioner.get_raw_active_dataset(DatasetFlags::EMPTY),
        )
        .await;
        assert!(abandoned.is_err());
        assert!(matches!(
            holding_the_slot.await.unwrap().unwrap_err(),
            Error::Timeout(_)
        ));
        let dataset = waiting.await.unwrap().unwrap();
        assert_eq!(dataset.network_name().unwrap(), Some("waited"));

        tokio::time::sleep(PAST_EXCHANGE_DEADLINE).await;
        assert_eq!(
            operations(&commissioner),
            [
                CommissionerOperation::Petition,
                CommissionerOperation::GetActiveDataset,
                CommissionerOperation::GetActiveDataset,
            ]
        );
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_request_dropped_in_flight_frees_its_slot_and_is_not_retransmitted() {
    with_paused_test_deadline(async {
        const GIVE_UP_AFTER: Duration = Duration::from_secs(1);
        let script = ScriptedMeshcopTransport::new([
            petition_exchange(),
            unanswered(CommissionerOperation::GetActiveDataset),
            active_get("next"),
        ]);
        let transport = script.clone();
        let (commissioner, _events) = scripted_commissioner(script, []).await;
        commissioner.petition().await.unwrap();
        let started = tokio::time::Instant::now();

        let abandoned = tokio::time::timeout(
            GIVE_UP_AFTER,
            commissioner.get_raw_active_dataset(DatasetFlags::EMPTY),
        )
        .await;
        assert!(abandoned.is_err());
        let dataset = commissioner
            .get_active_dataset(DatasetFlags::NETWORK_NAME)
            .await
            .unwrap();
        assert_eq!(dataset.network_name().unwrap(), Some("next"));
        assert_eq!(started.elapsed(), GIVE_UP_AFTER);

        tokio::time::sleep(PAST_EXCHANGE_DEADLINE).await;
        assert_eq!(transport.sent_messages(), []);
    })
    .await
}

#[tokio::test]
async fn only_one_keep_alive_is_outstanding_at_a_time() {
    with_test_deadline(async {
        let script = ScriptedMeshcopTransport::new([
            petition_exchange(),
            unanswered(CommissionerOperation::KeepAlive),
        ]);
        let transport = script.clone();
        let (commissioner, _events) = scripted_commissioner(script, []).await;
        commissioner.petition().await.unwrap();
        let outstanding = {
            let commissioner = commissioner.clone();
            tokio::spawn(async move { commissioner.keep_alive().await })
        };
        wait_until(|| transport.observed_requests().len() == 2).await;

        assert!(matches!(
            commissioner.keep_alive().await.unwrap_err(),
            Error::InvalidState("a keep-alive is already outstanding")
        ));
        assert_eq!(transport.observed_requests().len(), 2);
        outstanding.abort();
    })
    .await
}

#[tokio::test]
async fn a_resigning_session_refuses_new_work() {
    with_test_deadline(async {
        const RESIGNING: &str = "commissioner is resigning";
        let script = ScriptedMeshcopTransport::new([
            petition_exchange(),
            // The resignation, left unanswered.
            unanswered(CommissionerOperation::KeepAlive),
        ]);
        let transport = script.clone();
        let (commissioner, _events) = scripted_commissioner(script, []).await;
        commissioner.petition().await.unwrap();
        let resigning = {
            let commissioner = commissioner.clone();
            tokio::spawn(async move { commissioner.resign().await })
        };
        wait_until(|| transport.observed_requests().len() == 2).await;

        assert!(matches!(
            commissioner
                .get_raw_active_dataset(DatasetFlags::EMPTY)
                .await
                .unwrap_err(),
            Error::InvalidState(RESIGNING)
        ));
        assert!(matches!(
            commissioner.keep_alive().await.unwrap_err(),
            Error::InvalidState(RESIGNING)
        ));
        assert!(matches!(
            commissioner.resign().await.unwrap_err(),
            Error::InvalidState(RESIGNING)
        ));
        assert_eq!(transport.observed_requests().len(), 2);
        resigning.abort();
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn dropping_every_handle_during_a_resignation_does_not_resign_twice() {
    with_paused_test_deadline(async {
        let script = ScriptedMeshcopTransport::new([
            petition_exchange(),
            unanswered(CommissionerOperation::KeepAlive),
        ]);
        let transport = script.clone();
        let (commissioner, _events) = scripted_commissioner(script, []).await;
        commissioner.petition().await.unwrap();
        let resigning = tokio::spawn(async move { commissioner.resign().await });
        wait_until(|| transport.observed_requests().len() == 2).await;

        // Aborting the only caller drops the last handle mid-resignation.
        resigning.abort();
        tokio::time::sleep(PAST_EXCHANGE_DEADLINE).await;
        assert_eq!(transport.observed_requests().len(), 2);
    })
    .await
}

#[tokio::test(start_paused = true)]
async fn a_send_failure_fails_queued_requests_with_the_session() {
    with_paused_test_deadline(async {
        // Past the unanswered request's last retransmission (at most 9 s),
        // before its 12-second deadline.
        const AFTER_RETRANSMISSIONS: Duration = Duration::from_secs(10);
        let script = ScriptedMeshcopTransport::new([
            petition_exchange(),
            unanswered(CommissionerOperation::GetActiveDataset),
        ]);
        let transport = script.clone();
        let (commissioner, _events) = scripted_commissioner(script, []).await;
        commissioner.petition().await.unwrap();
        let request = || {
            let commissioner = commissioner.clone();
            tokio::spawn(async move {
                commissioner
                    .get_raw_active_dataset(DatasetFlags::EMPTY)
                    .await
            })
        };
        let in_flight = request();
        wait_until(|| transport.observed_requests().len() == 2).await;
        let (next, after_next) = (request(), request());
        tokio::time::sleep(AFTER_RETRANSMISSIONS).await;
        transport.fail_sends();

        // The deadline frees the slot, sending the next request fails, and
        // the session ends before the one after it is tried.
        assert!(matches!(
            in_flight.await.unwrap().unwrap_err(),
            Error::Timeout(_)
        ));
        assert!(matches!(next.await.unwrap().unwrap_err(), Error::Io(_)));
        let lost = CloseReason::TransportFailed {
            error: "I/O error: scripted send failure".to_string(),
        };
        assert!(matches!(
            after_next.await.unwrap().unwrap_err(),
            Error::SessionLost(reason) if reason == lost
        ));
    })
    .await
}

#[tokio::test]
async fn concurrent_enable_joiner_calls_keep_every_joiner() {
    with_test_deadline(async {
        let joiner_ids = [[0x1a; 8], [0x2b; 8]];
        let open_steering = {
            let mut dataset = Dataset::default();
            dataset.set_raw(TLV_STEERING_DATA, vec![0x00]);
            dataset.to_bytes().unwrap()
        };
        let read_then_write = || {
            [
                exchange(
                    CommissionerOperation::GetCommissionerDataset,
                    [ScriptedResponse::content(open_steering.clone())],
                ),
                exchange(
                    CommissionerOperation::SetCommissionerDataset,
                    [ScriptedResponse::accept()],
                ),
            ]
        };
        let mut script = vec![petition_exchange()];
        script.extend(read_then_write());
        script.extend(read_then_write());
        let (commissioner, _events) =
            scripted_commissioner(ScriptedMeshcopTransport::new(script), []).await;
        commissioner.petition().await.unwrap();

        let calls = joiner_ids.map(|joiner_id| {
            let commissioner = commissioner.clone();
            tokio::spawn(async move { commissioner.enable_joiner(&joiner_id).await })
        });
        for call in calls {
            call.await.unwrap().unwrap();
        }
        assert_eq!(
            operations(&commissioner),
            [
                CommissionerOperation::Petition,
                CommissionerOperation::GetCommissionerDataset,
                CommissionerOperation::SetCommissionerDataset,
                CommissionerOperation::GetCommissionerDataset,
                CommissionerOperation::SetCommissionerDataset,
            ]
        );
    })
    .await
}

#[tokio::test]
async fn a_dataset_change_during_a_prefix_fetch_leaves_the_cache_empty() {
    with_test_deadline(async {
        let script = ScriptedMeshcopTransport::new([
            petition_exchange(),
            exchange(
                CommissionerOperation::GetActiveDataset,
                [
                    ScriptedResponse::content(prefixed_dataset().to_bytes().unwrap()),
                    // Processed before the fetching caller resumes.
                    ScriptedResponse::Raw(dataset_changed_notification(0x7001, false)),
                ],
            ),
            exchange(
                CommissionerOperation::GetCommissionerDataset,
                [ScriptedResponse::content(Vec::new())],
            ),
        ]);
        let (commissioner, _events) = scripted_commissioner(script, []).await;
        commissioner.set_cached_mesh_local_prefix(None);
        commissioner.petition().await.unwrap();

        commissioner
            .get_commissioner_dataset(CommissionerDatasetFlags::STEERING_DATA)
            .await
            .unwrap();
        assert_eq!(commissioner.cached_mesh_local_prefix(), None);
    })
    .await
}

#[test]
fn status_reports_a_session_task_that_stopped_without_ending_the_session() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut started = None;
    runtime.block_on(with_test_deadline(async {
        let script = ScriptedMeshcopTransport::new([petition_exchange()]);
        let (commissioner, events) = scripted_commissioner(script, []).await;
        commissioner.petition().await.unwrap();
        started = Some((commissioner, events));
    }));
    let (commissioner, _events) = started.unwrap();
    assert!(commissioner.status().is_active());

    // Shutting the runtime down cancels the session task mid-session.
    drop(runtime);
    assert_eq!(
        commissioner.status(),
        SessionStatus::Closed {
            reason: CloseReason::TaskStopped
        }
    );
    assert_eq!(commissioner.session_id(), None);
}

#[tokio::test]
async fn status_keeps_why_a_finished_session_ended() {
    with_test_deadline(async {
        let script = ScriptedMeshcopTransport::new([
            petition_exchange(),
            exchange(
                CommissionerOperation::KeepAlive,
                [ScriptedResponse::accept()],
            ),
        ]);
        let (commissioner, mut events) = scripted_commissioner(script, []).await;
        commissioner.petition().await.unwrap();
        commissioner.resign().await.unwrap();

        // The stream ends once the session task has stopped.
        assert_eq!(next_event(&mut events).await, None);
        assert_eq!(
            commissioner.status(),
            SessionStatus::Closed {
                reason: CloseReason::Resigned
            }
        );
    })
    .await
}

#[test]
fn a_stopped_task_is_described_as_unexpected() {
    assert_eq!(
        CloseReason::TaskStopped.to_string(),
        "the session task stopped unexpectedly"
    );
}
