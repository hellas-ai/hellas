use super::*;

#[tokio::test]
async fn recovered_delivery_returns_durable_status_and_signed_metadata_without_reexecution() {
    use hellas_channel::model::profile::{PreparedWorkInput, WorkContext};
    for (step, expected_state, expected_code) in [
        (0, GrantTerminalState::Released, GrantRefusalCode::Released),
        (
            1,
            GrantTerminalState::Indeterminate,
            GrantRefusalCode::Indeterminate,
        ),
        (
            2,
            GrantTerminalState::Failed,
            GrantRefusalCode::Indeterminate,
        ),
        (
            3,
            GrantTerminalState::Finished,
            GrantRefusalCode::OutputUnavailable,
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (mut store, secret) = setup_with_credential(dir.path()).await;
        let application = execution_caller(&mut store, &secret, GrantId([0; 16])).await;
        let (a, sig, input) = proposal(&store, 1);
        let work = grant_work_id(network(), &a);
        store
            .accept(
                (&application, JOURNAL_AUTHORIZATION),
                a,
                sig,
                &input,
                &principal(2).1,
                UnixMillis(1000),
            )
            .await
            .unwrap();
        if step != 0 {
            store
                .dispatch(
                    (&application, JOURNAL_AUTHORIZATION),
                    a.channel_id,
                    work,
                    UnixMillis(1001),
                )
                .await
                .unwrap();
        }
        let mut signed = None;
        if step == 3 {
            let PreparedWorkInput::Fetch(fetch) = &input else {
                unreachable!()
            };
            let parts = fetch.parts().unwrap();
            let request =
                hellas_rpc::fetch::verify_input_events(&parts.fetch_input_transcript).unwrap();
            let key = principal(2).1;
            let output = hellas_rpc::fetch::FetchOutputTranscriptBuilder::new(
                request.input_commitment,
                request.assurance,
                &key,
            )
            .finish(
                hellas_rpc::fetch::encode_fetch_terminal_payload(
                    &hellas_rpc::output::OutputEvent::Finished {
                        stop_reason: hellas_rpc::output::StopReason::EndOfText,
                        usage: None,
                    },
                )
                .unwrap(),
            )
            .unwrap();
            let result = store
                .state()
                .policy_for(&a)
                .unwrap()
                .work
                .bound_terminal_result(
                    &WorkContext {
                        network: network(),
                        channel: a.channel_id.0,
                        client: hellas_kernel::Key::from_bytes(
                            *hellas_channel::test_support::node_key(1).as_bytes(),
                        ),
                        provider: hellas_kernel::Key::from_bytes(
                            *hellas_channel::test_support::node_key(2).as_bytes(),
                        ),
                    },
                    work,
                    &(&a).into(),
                    &input,
                    &output,
                )
                .unwrap();
            signed = Some(SignedResult {
                signature: key
                    .sign_digest(bound_result_digest(network(), a.channel_id.0, &result))
                    .unwrap(),
                result,
            });
        }
        if step >= 2 {
            store
                .finish(
                    a.channel_id,
                    work,
                    if step == 3 {
                        GrantOutcome::Finished
                    } else {
                        GrantOutcome::Failed
                    },
                    signed.clone(),
                    Usage::Unknown,
                    UnixMillis(1002),
                )
                .await
                .unwrap();
        }
        drop(store);
        let store = NodeStore::open(
            dir.path(),
            network(),
            Some(hellas_channel::test_support::software_enrollment(
                2, [2; 32],
            )),
            UnixMillis(1003),
        )
        .await
        .unwrap();
        let backend = Backend::default();
        let (service, work_service, _credential) = service(store, backend.clone(), &secret).await;
        let delivery = delivery::delivery_request(&a, work);
        let mut forged = delivery.clone();
        forged.route = Some(WorkRoute::grant(
            ChannelId(Digest::hash(b"another channel")).0,
        ));
        let mut stream = work_service.stream(forged);
        let Some(work_stream_event::Outcome::Refused(refused)) =
            stream.next().await.unwrap().unwrap().outcome
        else {
            panic!("foreign channel admitted")
        };
        assert_eq!(
            GrantRefusalCode::try_from(refused.grant.as_ref().unwrap().code).unwrap(),
            GrantRefusalCode::Unauthorized
        );
        assert!(refused.grant.unwrap().terminal.is_none());
        let mut stream = work_service.stream(delivery);
        let Some(work_stream_event::Outcome::Refused(refused)) =
            stream.next().await.unwrap().unwrap().outcome
        else {
            panic!("recovered payload delivered")
        };
        let detail = refused.grant.unwrap();
        assert_eq!(
            GrantRefusalCode::try_from(detail.code).unwrap(),
            expected_code
        );
        let metadata = detail.terminal.unwrap();
        assert_eq!(metadata.work_id, work.as_bytes());
        assert_eq!(
            GrantTerminalState::try_from(metadata.state).unwrap(),
            expected_state
        );
        assert_eq!(
            metadata.result,
            signed.as_ref().map_or_else(Vec::new, |s| s.result.encode())
        );
        assert_eq!(
            metadata.provider_signature,
            signed
                .as_ref()
                .map_or_else(Vec::new, |s| s.signature.bytes().to_vec())
        );
        assert!(stream.next().await.is_none());
        assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
        within(service.drain()).await.unwrap();
    }
}
