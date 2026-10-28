//! Streaming delivery authenticates the caller and the full terminal before payment.
use fixture::serve_work as serve;
use futures::StreamExt as _;
use hellas_auth::Digest;
use hellas_channel::{
    job,
    model::{
        setup::ReadyChannel,
        work::{
            PaidJobAuthorizationV2, decode_transcript, delivery_request_digest, encode_transcript,
            signing_hash, work_id,
        },
    },
    test_support::channel::{self as fixture, *},
    work::{
        Admitted, BackendFault, ClientEndpoint, CloseEndpoint, DeliverError, ProviderEndpoint,
        RunError, RunOutcome, WorkBackend, WorkService, fetch_result_stream, run_accepted_work,
    },
    work_store::{ChannelRecord, ChannelStore, JobPhase, JobState, Role, TerminalOutcome},
};
use hellas_rpc::{
    OutputEventEnvelope,
    pb::work::{StreamResultRequest, WorkRefusalCode, WorkStreamEvent, work_stream_event::Outcome},
    protocol::invocation::{Admission, InvocationPolicy, PreparedInvocation},
    services::work::{StreamResult, WorkClientImpl, WorkHandler as _},
};
use hellas_wire::{StreamTransport, WireCode, WireStatus, mux::MuxTransport};
use prost::Message as _;
use std::{sync::Arc, time::Duration};
mod support;
use support::temp;
const EXPORTER: [u8; 32] = [0x5e; 32];
const LAST_RELEASE: u64 = deadlines().terminal - 2;
fn ready_at(height: u64) -> ReadyChannel {
    ready_of(&descriptor(), height)
}
fn transport_pair() -> (MuxTransport, MuxTransport) {
    let context = hellas_wire::TransportContext {
        open_exporter: Some(EXPORTER),
        ..Default::default()
    };
    hellas_channel::test_support::transport::transport_pair_without_write_authority(
        context.clone(),
        context,
    )
}
async fn accept(
    policy: &InvocationPolicy,
    stores: &mut [&mut ChannelStore],
    nonce: u8,
) -> (Digest, PaidJobAuthorizationV2) {
    let ready = ready_of(&descriptor_with(policy.clone()), CURSOR);
    let mut input = bundle(nonce);
    input.application_policy = hellas_rpc::JsonBytes(policy.canonical_bytes().unwrap());
    accept_input(&ready, &input, stores, nonce).await
}
async fn accept_input(
    ready: &ReadyChannel,
    input: &PreparedInvocation,
    stores: &mut [&mut ChannelStore],
    nonce: u8,
) -> (Digest, PaidJobAuthorizationV2) {
    let a = job::propose(
        ready.channel(),
        ready.invocation_policy(),
        ready.payment_policy(),
        input,
        u64::from(nonce),
        deadlines(),
    )
    .unwrap();
    let id = work_id(ready.channel(), &a);
    for store in stores {
        commit(
            store,
            ChannelRecord::JobProposed {
                authorization: a,
                client_signature: client().sign(signing_hash(id)),
                prepared_input: input.canonical_bytes().unwrap(),
            },
        )
        .await;
        commit(
            store,
            ChannelRecord::JobAccepted {
                work_id: id,
                provider_signature: provider().sign(signing_hash(id)),
            },
        )
        .await;
    }
    (id, a)
}
async fn collect(
    service: &WorkService,
    request: StreamResultRequest,
    exporter: Option<[u8; 32]>,
) -> Vec<WorkStreamEvent> {
    let mut stream = service
        .stream_result(
            request,
            hellas_wire::TransportContext {
                open_exporter: exporter,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let mut frames = Vec::new();
    while let Some(frame) = tokio::time::timeout(Duration::from_secs(5), stream.next())
        .await
        .unwrap()
    {
        frames.push(frame.unwrap());
    }
    frames
}
fn refusal(frames: &[WorkStreamEvent]) -> (&str, WorkRefusalCode) {
    let [
        WorkStreamEvent {
            outcome: Some(Outcome::Refused(r)),
        },
    ] = frames
    else {
        panic!("expected only refusal: {frames:?}")
    };
    (&r.reason, WorkRefusalCode::try_from(r.code).unwrap())
}
fn delivery_request(
    channel: &hellas_channel::model::work::PaidChannel,
    id: Digest,
) -> StreamResultRequest {
    StreamResultRequest {
        route: Some(hellas_rpc::pb::work::WorkRoute::payment(channel.id())),
        work_id: id.as_bytes().to_vec(),
        client_signature: client()
            .sign(signing_hash(delivery_request_digest(
                channel, id, &EXPORTER,
            )))
            .as_bytes()
            .to_vec(),
    }
}
async fn scripted(
    frames: Vec<Result<WorkStreamEvent, WireStatus>>,
    endpoint: &mut ClientEndpoint,
    ready: &ReadyChannel,
    id: Digest,
) -> Result<hellas_channel::work::Delivery, DeliverError> {
    let (transport, server) = transport_pair();
    let serving = tokio::spawn(async move {
        let inbound = server.accept().await.unwrap().unwrap();
        hellas_rpc::call::dispatch_server_streaming::<MuxTransport, StreamResult, _, _, _>(
            inbound,
            move |_| async move {
                Ok(hellas_rpc::call::ResponseStream::new(
                    futures::stream::iter(frames),
                ))
            },
        )
        .await
        .unwrap();
    });
    let result = fetch_result_stream(transport, endpoint, ready, id, |_| Ok(())).await;
    serving.await.unwrap();
    result
}

#[tokio::test]
async fn one_answer_crosses_the_wire_and_is_debited_once() {
    let client_root = temp();
    let provider_root = temp();
    let ready = ready();
    let mut cs = store_at(client_root.path(), &ready, Role::Client, CURSOR).await;
    let mut ps = store_at(provider_root.path(), &ready, Role::Provider, CURSOR).await;
    let (id, a) = accept(&work_policy(), &mut [&mut cs, &mut ps], 1).await;
    let service = WorkService::new(ProviderEndpoint::new(ready.clone(), ps, provider()).unwrap());
    run_to_result(&service, &ready, id).await;
    let mut endpoint = ClientEndpoint::new(ready.clone(), cs, client()).unwrap();
    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let delivered = fetch_result_stream(transport.clone(), &mut endpoint, &ready, id, |_| Ok(()))
        .await
        .unwrap();
    let events = decode_transcript(&delivered.transcript, 1 << 20).unwrap();
    assert_eq!(
        job::paid_terminal_result(ready.channel(), &a, &work_policy(), &bundle(1), &events),
        Ok(delivered.result)
    );
    assert_eq!(delivered.result.work_id, id);
    assert_eq!(
        service
            .with_state(|s| s.job_by_id(id).unwrap().phase())
            .await
            .unwrap(),
        JobPhase::Delivered
    );
    assert_eq!(
        endpoint.state().job_by_id(id).unwrap().phase(),
        JobPhase::Ready
    );
    let checkpoint = service.with_state(|s| s.checkpoint()).await.unwrap();
    let again = fetch_result_stream(transport, &mut endpoint, &ready, id, |_| Ok(()))
        .await
        .unwrap();
    assert_eq!(again, delivered, "the same answer came back");
    assert_eq!(
        service.with_state(|s| s.checkpoint()).await.unwrap(),
        checkpoint,
        "retry does not debit again"
    );
    assert!(
        endpoint.pay(id).await.is_err(),
        "authenticated verification must be journaled before payment"
    );
    serving.abort();
    let _ = serving.await;
    drop(endpoint);
    drop(service);
    let recovered = store_at(client_root.path(), &ready, Role::Client, CURSOR).await;
    let job = recovered.state().job_by_id(id).unwrap();
    assert_eq!(job.phase(), JobPhase::Ready);
    assert_eq!(job.result().map(|(r, _)| *r), Some(delivered.result));
    assert_eq!(job.transcript(), delivered.transcript);
    let mut endpoint = ClientEndpoint::new(ready.clone(), recovered, client()).unwrap();
    endpoint.verified(id).await.unwrap();
    drop(endpoint);
    let recovered = store_at(client_root.path(), &ready, Role::Client, CURSOR).await;
    assert_eq!(
        recovered.state().job_by_id(id).unwrap().phase(),
        JobPhase::Verified
    );
    let mut endpoint = ClientEndpoint::new(ready, recovered, client()).unwrap();
    assert!(endpoint.pay(id).await.is_ok());
}

#[tokio::test]
async fn the_last_height_the_delivery_margin_fits_is_the_last_that_may_release() {
    for (height, may_release) in [(LAST_RELEASE, true), (LAST_RELEASE + 1, false)] {
        let root = temp();
        let early = ready();
        let mut ps = store_at(root.path(), &early, Role::Provider, CURSOR).await;
        let (id, _) = accept(&work_policy(), &mut [&mut ps], 1).await;
        let service =
            WorkService::new(ProviderEndpoint::new(early.clone(), ps, provider()).unwrap());
        run_to_result(&service, &early, id).await;
        drop(service);
        let ready = ready_at(height);
        let mut ps = store_at(root.path(), &ready, Role::Provider, height).await;
        advance(&mut ps, height).await;
        let service =
            WorkService::new(ProviderEndpoint::new(ready.clone(), ps, provider()).unwrap());
        let frames = collect(
            &service,
            delivery_request(ready.channel(), id),
            Some(EXPORTER),
        )
        .await;
        if may_release {
            assert!(matches!(
                frames.last().unwrap().outcome,
                Some(Outcome::Terminal(_))
            ));
        } else {
            assert_eq!(refusal(&frames).1, WorkRefusalCode::Expired);
        }
        assert_eq!(
            service
                .with_state(|s| s.job_by_id(id).unwrap().phase())
                .await
                .unwrap(),
            if may_release {
                JobPhase::Delivered
            } else {
                JobPhase::Ready
            }
        );
    }
}

#[tokio::test]
async fn a_job_with_no_result_releases_nothing_yet() {
    let root = temp();
    let ready = ready();
    let mut ps = store_at(root.path(), &ready, Role::Provider, CURSOR).await;
    let (id, _) = accept(&work_policy(), &mut [&mut ps], 1).await;
    let service = WorkService::new(ProviderEndpoint::new(ready.clone(), ps, provider()).unwrap());
    let mut stream = service
        .stream_result(
            delivery_request(ready.channel(), id),
            hellas_wire::TransportContext {
                open_exporter: Some(EXPORTER),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), stream.next())
            .await
            .is_err()
    );
    assert_eq!(
        service
            .with_state(|s| s.job_by_id(id).unwrap().phase())
            .await
            .unwrap(),
        JobPhase::Accepted
    );
    run_to_result(&service, &ready, id).await;
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap()
            .outcome,
        Some(Outcome::Prefix(_))
    ));
    assert!(matches!(
        stream.next().await.unwrap().unwrap().outcome,
        Some(Outcome::Terminal(_))
    ));
}

#[tokio::test]
async fn a_failed_job_returns_its_terminal_after_authentication() {
    struct FailingBackend;
    impl WorkBackend for FailingBackend {
        fn try_admit(
            &self,
            domain: hellas_channel::work::admission::CapacityDomain,
        ) -> Result<hellas_channel::work::admission::WorkPermit, BackendFault> {
            Err(hellas_channel::work::admission::AdmissionError::Unsupported(domain).into())
        }
        async fn execute(&self, _: Admitted) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
            Err(BackendFault::caused_by(std::io::Error::other(
                "fixture content unavailable",
            )))
        }
    }
    let root = temp();
    let ready = ready();
    let mut ps = store_at(root.path(), &ready, Role::Provider, CURSOR).await;
    let (id, _) = accept(&work_policy(), &mut [&mut ps], 1).await;
    let service = WorkService::new(ProviderEndpoint::new(ready.clone(), ps, provider()).unwrap());
    assert!(matches!(
        run_accepted_work(&service, &ready, &FailingBackend, id).await,
        Err(RunError::Backend(_))
    ));
    drop(service);
    let recovered = store_at(root.path(), &ready, Role::Provider, CURSOR).await;
    assert!(recovered.state().job_by_id(id).is_none());
    assert_eq!(
        recovered.state().terminal_by_id(id).map(|t| &t.outcome),
        Some(&TerminalOutcome::Failed { code: 1 })
    );
    let service = WorkService::close_only(CloseEndpoint::new(recovered, provider()).unwrap());
    let checkpoint = service.with_state(|s| s.checkpoint()).await.unwrap();
    for authenticated in [false, true] {
        let mut request = delivery_request(ready.channel(), id);
        if !authenticated {
            request.client_signature = provider()
                .sign(signing_hash(delivery_request_digest(
                    ready.channel(),
                    id,
                    &EXPORTER,
                )))
                .as_bytes()
                .to_vec();
        }
        let frames = collect(&service, request, Some(EXPORTER)).await;
        assert_eq!(
            refusal(&frames).1,
            if authenticated {
                WorkRefusalCode::Declined
            } else {
                WorkRefusalCode::Invalid
            }
        );
        if authenticated {
            assert_eq!(refusal(&frames).0, "the job ended permanently as failed");
        }
    }
    assert_eq!(
        service.with_state(|s| s.checkpoint()).await.unwrap(),
        checkpoint
    );
}

#[tokio::test]
async fn a_work_id_alone_releases_nothing() {
    let root = temp();
    let ready = ready();
    let mut ps = store_at(root.path(), &ready, Role::Provider, CURSOR).await;
    let (id, _) = accept(&work_policy(), &mut [&mut ps], 1).await;
    let service = WorkService::new(ProviderEndpoint::new(ready.clone(), ps, provider()).unwrap());
    run_to_result(&service, &ready, id).await;
    for fault in ["bare", "provider", "connection", "job", "route"] {
        let mut request = delivery_request(ready.channel(), id);
        match fault {
            "bare" => request.client_signature.clear(),
            "provider" => {
                request.client_signature = provider()
                    .sign(signing_hash(delivery_request_digest(
                        ready.channel(),
                        id,
                        &EXPORTER,
                    )))
                    .as_bytes()
                    .to_vec()
            }
            "connection" => {
                request.client_signature = client()
                    .sign(signing_hash(delivery_request_digest(
                        ready.channel(),
                        id,
                        &[0xa1; 32],
                    )))
                    .as_bytes()
                    .to_vec()
            }
            "job" => request.work_id[0] ^= 1,
            "route" => request.route = None,
            _ => unreachable!(),
        }
        assert_eq!(
            refusal(&collect(&service, request, Some(EXPORTER)).await).1,
            WorkRefusalCode::Invalid,
            "{fault}"
        );
        assert_eq!(
            service
                .with_state(|s| s.job_by_id(id).unwrap().phase())
                .await
                .unwrap(),
            JobPhase::Ready
        );
    }
    assert!(matches!(
        collect(
            &service,
            delivery_request(ready.channel(), id),
            Some(EXPORTER)
        )
        .await
        .last()
        .unwrap()
        .outcome,
        Some(Outcome::Terminal(_))
    ));
}

#[tokio::test]
async fn a_delivery_named_for_another_job_finds_nothing() {
    let root = temp();
    let ready = ready();
    let mut ps = store_at(root.path(), &ready, Role::Provider, CURSOR).await;
    let (id, _) = accept(&work_policy(), &mut [&mut ps], 1).await;
    let service = WorkService::new(ProviderEndpoint::new(ready.clone(), ps, provider()).unwrap());
    run_to_result(&service, &ready, id).await;
    let other = Digest::hash(b"another work id");
    assert_eq!(
        refusal(
            &collect(
                &service,
                delivery_request(ready.channel(), other),
                Some(EXPORTER)
            )
            .await
        )
        .1,
        WorkRefusalCode::Declined
    );
    assert_eq!(
        service
            .with_state(|s| s.job_by_id(id).unwrap().phase())
            .await
            .unwrap(),
        JobPhase::Ready
    );
}

#[tokio::test]
async fn a_transport_without_an_exporter_delivers_nothing() {
    let cr = temp();
    let pr = temp();
    let ready = ready();
    let mut cs = store_at(cr.path(), &ready, Role::Client, CURSOR).await;
    let mut ps = store_at(pr.path(), &ready, Role::Provider, CURSOR).await;
    let (id, _) = accept(&work_policy(), &mut [&mut cs, &mut ps], 1).await;
    let service = WorkService::new(ProviderEndpoint::new(ready.clone(), ps, provider()).unwrap());
    run_to_result(&service, &ready, id).await;
    let (t, s) = hellas_channel::test_support::transport::transport_pair_without_write_authority(
        Default::default(),
        Default::default(),
    );
    let serving = serve(s, service.clone());
    let mut endpoint = ClientEndpoint::new(ready.clone(), cs, client()).unwrap();
    assert!(matches!(
        fetch_result_stream(t, &mut endpoint, &ready, id, |_| Ok(())).await,
        Err(DeliverError::Unbindable)
    ));
    serving.abort();
    let _ = serving.await;
    assert_eq!(
        service
            .with_state(|s| s.job_by_id(id).unwrap().phase())
            .await
            .unwrap(),
        JobPhase::Ready
    );
}

#[tokio::test]
async fn a_transcript_swapped_in_transit_is_not_recorded() {
    let cr = temp();
    let pr = temp();
    let ready = ready();
    let mut cs = store_at(cr.path(), &ready, Role::Client, CURSOR).await;
    let mut ps = store_at(pr.path(), &ready, Role::Provider, CURSOR).await;
    let (id, _) = accept(&work_policy(), &mut [&mut cs, &mut ps], 1).await;
    let service = WorkService::new(ProviderEndpoint::new(ready.clone(), ps, provider()).unwrap());
    run_to_result(&service, &ready, id).await;
    let honest = collect(
        &service,
        delivery_request(ready.channel(), id),
        Some(EXPORTER),
    )
    .await;
    let other = transcript_for(&invocation_request(1), &[7, 7, 7]);
    let mut bad = honest.clone();
    bad[0].outcome = Some(Outcome::Prefix(
        encode_transcript(&other[..other.len() - 1]).unwrap(),
    ));
    let mut endpoint = ClientEndpoint::new(ready.clone(), cs, client()).unwrap();
    assert!(
        scripted(bad.into_iter().map(Ok).collect(), &mut endpoint, &ready, id)
            .await
            .is_err()
    );
    assert_eq!(
        endpoint.state().job_by_id(id).unwrap().phase(),
        JobPhase::Accepted
    );
    assert!(
        scripted(
            honest.into_iter().map(Ok).collect(),
            &mut endpoint,
            &ready,
            id
        )
        .await
        .is_ok()
    );
    assert_eq!(
        endpoint.state().job_by_id(id).unwrap().phase(),
        JobPhase::Ready
    );
}

#[tokio::test]
async fn a_client_behind_its_readiness_records_no_receipt() {
    let cr = temp();
    let pr = temp();
    let ready = ready();
    let mut cs = store_at(cr.path(), &ready, Role::Client, CURSOR).await;
    let mut ps = store_at(pr.path(), &ready, Role::Provider, CURSOR).await;
    let (id, _) = accept(&work_policy(), &mut [&mut cs, &mut ps], 1).await;
    let service = WorkService::new(ProviderEndpoint::new(ready.clone(), ps, provider()).unwrap());
    run_to_result(&service, &ready, id).await;
    let (t, s) = transport_pair();
    let serving = serve(s, service.clone());
    let mut endpoint = ClientEndpoint::new(ready.clone(), cs, client()).unwrap();
    assert!(matches!(
        fetch_result_stream(t.clone(), &mut endpoint, &ready_at(CURSOR + 1), id, |_| Ok(
            ()
        ))
        .await,
        Err(DeliverError::Setup(
            hellas_channel::model::setup::WorkSetupError::CursorBehind {
                cursor: CURSOR,
                height: 11
            }
        ))
    ));
    assert!(
        fetch_result_stream(t, &mut endpoint, &ready, id, |_| Ok(()))
            .await
            .is_ok()
    );
    serving.abort();
    let _ = serving.await;
}

#[tokio::test]
async fn a_client_refuses_a_frame_over_the_bound_it_signed() {
    let cr = temp();
    let ready = ready();
    let mut cs = store_at(cr.path(), &ready, Role::Client, CURSOR).await;
    let (id, _) = accept(&work_policy(), &mut [&mut cs], 1).await;
    let cap = work_policy()
        .classify_manifest(&manifest())
        .unwrap()
        .max_encoded_result_frame;
    let frame = WorkStreamEvent {
        outcome: Some(Outcome::Prefix(vec![0; cap as usize])),
    };
    let actual = frame.encoded_len() as u64;
    let mut endpoint = ClientEndpoint::new(ready.clone(), cs, client()).unwrap();
    assert!(
        matches!(scripted(vec![Ok(frame)],&mut endpoint,&ready,id).await,Err(DeliverError::OverFrame{actual:a,limit}) if a==actual && limit==u64::from(cap))
    );
    assert_eq!(
        endpoint.state().job_by_id(id).unwrap().phase(),
        JobPhase::Accepted
    );
}

#[tokio::test]
async fn a_provider_signs_no_result_the_frame_would_not_carry() {
    struct FetchBackend;
    impl WorkBackend for FetchBackend {
        fn try_admit(
            &self,
            domain: hellas_channel::work::admission::CapacityDomain,
        ) -> Result<hellas_channel::work::admission::WorkPermit, BackendFault> {
            Err(hellas_channel::work::admission::AdmissionError::Unsupported(domain).into())
        }
        async fn execute(&self, input: Admitted) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
            Ok(fetch_transcript(input.invocation()))
        }
    }
    let root = temp();
    let mut policy = fetch_policy();
    let Admission::Fetch { admission } = &mut policy.admissions[0] else {
        unreachable!()
    };
    admission.limits.max_encoded_result_frame = 1;
    let ready = ready_of(&descriptor_with(policy.clone()), CURSOR);
    let cr = temp();
    let service = WorkService::new(
        ProviderEndpoint::new(
            ready.clone(),
            store_at(root.path(), &ready, Role::Provider, CURSOR).await,
            provider(),
        )
        .unwrap(),
    );
    let mut endpoint = ClientEndpoint::new(
        ready.clone(),
        store_at(cr.path(), &ready, Role::Client, CURSOR).await,
        client(),
    )
    .unwrap();
    let mut input = fetch_bundle(1);
    input.application_policy = hellas_rpc::JsonBytes(policy.canonical_bytes().unwrap());
    let request = endpoint
        .propose(&hellas_channel::work::JobProposal {
            prepared_input: input,
            deadlines: deadlines(),
        })
        .await
        .unwrap();
    let response = accept_uploaded_client(&service, &endpoint, &request).await;
    let id = endpoint.accepted(&response).await.unwrap();
    let result = run_accepted_work(&service, &ready, &FetchBackend, id).await;
    // RPC's shared result check enforces the signed frame ceiling before a receipt is made.
    assert!(
        matches!(result,Err(RunError::Transcript(ref error)) if error.to_string().contains("invocation output frame exceeds its bound")),
        "{result:?}"
    );
    assert!(
        service
            .with_state(|s| s.jobs().next().is_none())
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn paid_stream_checks_status_and_terminal_shape_before_recording_delivery() {
    for (count, status) in [
        (0, WireCode::Unavailable),
        (1, WireCode::Unavailable),
        (2, WireCode::Ok),
        (1, WireCode::Ok),
    ] {
        let cr = temp();
        let pr = temp();
        let ready = ready();
        let mut cs = store_at(cr.path(), &ready, Role::Client, CURSOR).await;
        let mut ps = store_at(pr.path(), &ready, Role::Provider, CURSOR).await;
        let (id, _) = accept(&work_policy(), &mut [&mut cs, &mut ps], 1).await;
        let service =
            WorkService::new(ProviderEndpoint::new(ready.clone(), ps, provider()).unwrap());
        run_to_result(&service, &ready, id).await;
        let honest = collect(
            &service,
            delivery_request(ready.channel(), id),
            Some(EXPORTER),
        )
        .await;
        let terminal = honest.last().unwrap().clone();
        let mut frames: Vec<_> = honest[..honest.len() - 1].iter().cloned().map(Ok).collect();
        frames.extend((0..count).map(|_| Ok(terminal.clone())));
        if status != WireCode::Ok {
            frames.push(Err(WireStatus::new(status, "interrupted")));
        }
        let mut endpoint = ClientEndpoint::new(ready.clone(), cs, client()).unwrap();
        let result = scripted(frames, &mut endpoint, &ready, id).await;
        if count == 1 && status == WireCode::Ok {
            assert!(result.is_ok());
            assert_eq!(
                endpoint.state().job_by_id(id).unwrap().phase(),
                JobPhase::Ready
            );
            continue;
        }
        assert!(result.is_err());
        assert_eq!(
            endpoint.state().job_by_id(id).unwrap().phase(),
            JobPhase::Accepted
        );
        assert!(endpoint.pay(id).await.is_err());
        assert!(
            scripted(
                honest.into_iter().map(Ok).collect(),
                &mut endpoint,
                &ready,
                id
            )
            .await
            .is_ok()
        );
    }
}

#[tokio::test]
async fn live_prefix_precedes_terminal_and_reserves_delivery_credit() {
    use hellas_channel::work::{PaidProgress, fetch_result_stream};
    struct PausedBackend {
        release: Arc<tokio::sync::Notify>,
    }
    impl WorkBackend for PausedBackend {
        fn try_admit(
            &self,
            domain: hellas_channel::work::admission::CapacityDomain,
        ) -> Result<hellas_channel::work::admission::WorkPermit, hellas_channel::work::BackendFault>
        {
            Err(hellas_channel::work::admission::AdmissionError::Unsupported(domain).into())
        }

        async fn execute(
            &self,
            input: Admitted,
        ) -> Result<Vec<OutputEventEnvelope>, hellas_channel::work::BackendFault> {
            Ok(transcript_for(&input.invocation().request, &ANSWER))
        }
        async fn execute_stream(
            &self,
            input: Admitted,
            progress: PaidProgress,
        ) -> Result<Vec<OutputEventEnvelope>, hellas_channel::work::BackendFault> {
            let transcript = transcript_for(&input.invocation().request, &ANSWER);
            progress(transcript[0].clone())?;
            // A backend's early terminal cannot escape before the result is durable.
            progress(transcript.last().unwrap().clone())?;
            self.release.notified().await;
            Ok(transcript)
        }
    }
    let client_root = temp();
    let provider_root = temp();
    let ready = ready();
    let mut client_store = store_at(client_root.path(), &ready, Role::Client, CURSOR).await;
    let mut provider_store = store_at(provider_root.path(), &ready, Role::Provider, CURSOR).await;
    let (id, _) = accept(
        &work_policy(),
        &mut [&mut client_store, &mut provider_store],
        1,
    )
    .await;
    let service =
        WorkService::new(ProviderEndpoint::new(ready.clone(), provider_store, provider()).unwrap());
    let release = Arc::new(tokio::sync::Notify::new());
    let backend = PausedBackend {
        release: release.clone(),
    };
    let running_service = service.clone();
    let running_ready = ready.clone();
    let computation = tokio::spawn(async move {
        run_accepted_work(&running_service, &running_ready, &backend, id).await
    });
    let (transport, server_transport) = transport_pair();
    let serving = serve(server_transport, service.clone());
    let mut endpoint = ClientEndpoint::new(ready.clone(), client_store, client()).unwrap();
    let mut prefixes = 0;
    let prefix_seen = tokio::sync::Notify::new();
    let (delivery, ()) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        tokio::join!(
            fetch_result_stream(transport, &mut endpoint, &ready, id, |_| {
                assert!(
                    !computation.is_finished(),
                    "live tokens must not await completion"
                );
                prefixes += 1;
                prefix_seen.notify_one();
                Ok(())
            }),
            async {
                prefix_seen.notified().await;
                assert_eq!(
                    service
                        .with_state(|state| state.job_by_id(id).map(JobState::phase))
                        .await
                        .unwrap(),
                    Some(JobPhase::Streaming)
                );
                release.notify_one();
            }
        )
    })
    .await
    .expect("stream must make progress");
    let delivered = delivery.expect("signed delivery succeeds");
    assert_eq!(prefixes, 1);
    assert!(matches!(
        computation.await.unwrap(),
        Ok(RunOutcome::Completed { .. })
    ));
    assert_eq!(
        endpoint.state().job_by_id(id).unwrap().phase(),
        JobPhase::Ready
    );
    assert_eq!(
        service
            .with_state(|state| state.job_by_id(id).map(JobState::phase))
            .await
            .unwrap(),
        Some(JobPhase::Delivered)
    );
    serving.abort();
    let _ = serving.await;
    drop(service);
    drop(endpoint);
    let recovered = store_at(provider_root.path(), &ready, Role::Provider, CURSOR).await;
    let job = recovered.state().job_by_id(id).unwrap();
    assert_eq!(job.phase(), JobPhase::Delivered);
    assert_eq!(job.transcript(), delivered.transcript);
}

#[tokio::test]
async fn one_channel_runs_fetch_then_compute_with_per_job_retention_and_durable_verification() {
    use hellas_channel::work::admit_payment;
    struct Backend;
    impl WorkBackend for Backend {
        fn try_admit(
            &self,
            domain: hellas_channel::work::admission::CapacityDomain,
        ) -> Result<hellas_channel::work::admission::WorkPermit, BackendFault> {
            Err(hellas_channel::work::admission::AdmissionError::Unsupported(domain).into())
        }
        async fn execute(&self, input: Admitted) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
            if input.capacity_domain() == hellas_channel::work::admission::CapacityDomain::Fetch {
                assert!(input.content().retained_store().is_none());
                Ok(fetch_transcript(input.invocation()))
            } else {
                assert!(input.content().retained_store().is_some());
                Ok(transcript_for(&input.invocation().request, &ANSWER))
            }
        }
    }
    fn assert_absent(root: &std::path::Path, needles: &[Vec<u8>]) {
        for entry in std::fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                assert_absent(&path, needles);
            } else {
                let bytes = std::fs::read(&path).unwrap();
                for needle in needles {
                    assert!(
                        !bytes.windows(needle.len()).any(|window| window == needle),
                        "payload in {}",
                        path.display()
                    );
                }
            }
        }
    }
    let cr = temp();
    let pr = temp();
    let mut policy = work_policy();
    policy.admissions.extend(fetch_policy().admissions);
    let ready = ready_of(&descriptor_with(policy.clone()), CURSOR);
    let mut client_endpoint = ClientEndpoint::new(
        ready.clone(),
        store_at(cr.path(), &ready, Role::Client, CURSOR).await,
        client(),
    )
    .unwrap();
    let service = WorkService::new(
        ProviderEndpoint::new(
            ready.clone(),
            store_at(pr.path(), &ready, Role::Provider, CURSOR).await,
            provider(),
        )
        .unwrap(),
    );
    let (transport, server) = transport_pair();
    let serving = serve(server, service.clone());
    let mut retained_result = None;
    let mut private_needles = Vec::new();
    for (index, mut input) in [fetch_bundle(1), bundle(2)].into_iter().enumerate() {
        input.application_policy = hellas_rpc::JsonBytes(policy.canonical_bytes().unwrap());
        let is_fetch = index == 0;
        if is_fetch {
            private_needles.push(input.canonical_bytes().unwrap());
        }
        let proposal = client_endpoint
            .propose(&hellas_channel::work::JobProposal {
                prepared_input: input.clone(),
                deadlines: deadlines(),
            })
            .await
            .unwrap();
        let reply = accept_uploaded_client(&service, &client_endpoint, &proposal).await;
        let id = client_endpoint.accepted(&reply).await.unwrap();
        run_accepted_work(&service, &ready, &Backend, id)
            .await
            .unwrap();
        let delivered =
            fetch_result_stream(transport.clone(), &mut client_endpoint, &ready, id, |_| {
                Ok(())
            })
            .await
            .unwrap();
        assert!(client_endpoint.pay(id).await.is_err());
        client_endpoint.verified(id).await.unwrap();
        assert_eq!(
            admit_payment(
                &WorkClientImpl::new(transport.clone()),
                &mut client_endpoint,
                id
            )
            .await
            .unwrap(),
            (index as u64 + 1) * PRICE
        );
        if is_fetch {
            private_needles.push(delivered.transcript);
            assert!(!pr.path().join("content").exists());
            assert!(!cr.path().join("content").exists());
        } else {
            retained_result = Some((delivered.result, delivered.transcript));
        }
        assert_absent(pr.path(), &private_needles);
        assert_absent(cr.path(), &private_needles);
    }
    serving.abort();
    let _ = serving.await;
    drop(service);
    drop(client_endpoint);
    for (root, role) in [(pr.path(), Role::Provider), (cr.path(), Role::Client)] {
        let recovered = store_at(root, &ready, role, CURSOR).await;
        assert!(recovered.state().jobs().next().is_none());
        assert_eq!(recovered.state().ledger().credited_cumulative(), 2 * PRICE);
        let (result, transcript) = retained_result.as_ref().unwrap();
        let content = hellas_store::ContentStore::new();
        let path = root
            .join("content/objects")
            .join(result.transcript_content.id().to_string());
        content.index(&path).unwrap();
        let view = hellas_channel::content::InvocationContent::Retained(content);
        assert_eq!(
            view.read(result.transcript_content).unwrap().as_ref(),
            transcript
        );
        assert_absent(root, &private_needles);
    }
}
