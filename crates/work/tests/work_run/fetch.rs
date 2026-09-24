use super::*;
use hellas_rpc::fetch::{
    FetchOutputTranscriptBuilder, build_input_events_with_retention, encode_fetch_event_payload,
    encode_fetch_terminal_payload, verify_input_events,
};
use hellas_rpc::output::{OutputEvent, StopReason, TextChannel};
use hellas_rpc::pb::work::WorkDelivered;
use hellas_rpc::protocol::work::PrivateRecord as _;
use hellas_rpc::protocol::work_fetch::{
    FetchRoutePolicy, PaidFetchPolicyV1, PreparedPaidFetchInputV1, fetch_route_commitment,
};
use hellas_rpc::protocol::work_profile::PaidWorkPolicy;
use hellas_rpc::{FetchEnvironment, Retention};
use hellas_work::work::{
    ClientEndpoint, DeliverError, EndpointError, JobProposal, PreparedFetchInput,
};

const PROMPT: &[u8] = br#"{"input":"private-customer-prompt-never-on-provider-disk"}"#;
const RESPONSE: &str = "private-provider-response-never-on-provider-disk";

#[path = "../support/transport.rs"]
mod transport;

#[tokio::test]
async fn fetch_streams_before_terminal_then_pays_once_with_metadata_only_journals() {
    use hellas_rpc::services::work::{WorkClientImpl, WorkServer};
    use hellas_wire::{Dispatcher, StreamTransport, mux::MuxTransport};
    use hellas_work::work::{PaidProgress, admit_payment, fetch_result_stream};

    struct PausedFetch(Arc<tokio::sync::Notify>);
    impl PaidWorkBackend for PausedFetch {
        async fn fetch_stream(
            &self,
            input: PreparedFetchInput,
            progress: PaidProgress,
        ) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
            let events = FetchBackend::default().fetch(input).await?;
            progress(events[0].clone())?;
            self.0.notified().await;
            Ok(events)
        }
    }
    for assurance in [Assurance::ProducerSigned, Assurance::AppleAppAttest] {
        let provider_dir = temp();
        let client_dir = temp();
        let mut client = client_endpoint(client_dir.path());
        let service = service(provider_dir.path());
        let proposal = JobProposal {
            prepared_input: input_with_assurance(Retention::Ephemeral, assurance).into(),
            deadlines: deadlines(),
        };
        let request = client.propose(&proposal).unwrap();
        let id = client.accepted(&service.accept(&request)).unwrap();
        let release = Arc::new(tokio::sync::Notify::new());
        let worker = {
            let service = service.clone();
            let backend = PausedFetch(release.clone());
            tokio::spawn(
                async move { run_accepted_work(&service, &fetch_ready(), &backend, id).await },
            )
        };
        let (transport, server) = transport::transport_pair();
        let serving = {
            let service = service.clone();
            tokio::spawn(async move {
                let handler = WorkServer(service);
                while let Ok(Some(inbound)) = server.accept().await {
                    let _ = Dispatcher::<MuxTransport>::dispatch(&handler, inbound).await;
                }
            })
        };
        let mut prefixes = 0;
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            fetch_result_stream(
                transport.clone(),
                &mut client,
                &fetch_ready(),
                id,
                |event| {
                    assert!(!worker.is_finished());
                    assert_eq!(
                        service
                            .with_state(|s| s.job_by_id(id).unwrap().phase())
                            .unwrap(),
                        JobPhase::Streaming
                    );
                    assert!(hellas_rpc::fetch::decode_fetch_event_payload(event.payload()).is_ok());
                    prefixes += 1;
                    release.notify_one();
                    Ok(())
                },
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(prefixes, 1);
        assert!(matches!(
            worker.await.unwrap().unwrap(),
            RunOutcome::Completed { .. }
        ));
        let rpc = WorkClientImpl::new(transport);
        assert_eq!(admit_payment(&rpc, &mut client, id).await.unwrap(), PRICE);
        assert_eq!(admit_payment(&rpc, &mut client, id).await.unwrap(), PRICE);
        assert_no_bodies(client_dir.path());
        assert_no_bodies(provider_dir.path());
        serving.abort();
        let _ = serving.await;
    }
}

fn policy() -> PaidWorkPolicy {
    let route = FetchRoutePolicy::sealed_route("openai", "responses").unwrap();
    PaidWorkPolicy::Fetch {
        policy: PaidFetchPolicyV1 {
            allowed_environment: FetchEnvironment::OpenAiResponses.manifest_id(),
            route_commitment: fetch_route_commitment(&route.canonical_body_bytes()).unwrap(),
            max_request_body_bytes: 4096,
            max_output_events: 64,
            max_output_bytes: 16384,
            max_spool_bytes: 65536,
            max_encoded_result_frame: 65536,
            max_encoded_prepared_input: 65536,
            dispatch_margin_blocks: 4,
            delivery_margin_blocks: 2,
            oracle_grace_blocks: 6,
            fixed_price: PRICE,
        },
        route,
    }
}

fn fetch_ready() -> ReadyChannel {
    ready_of(descriptor_with(policy()), CURSOR)
}

#[tokio::test]
async fn invalid_paid_authorizations_never_invoke_fetch() {
    for invalid in ["signature", "price", "deadline"] {
        let provider_dir = temp();
        let client_dir = temp();
        let service = service(provider_dir.path());
        let mut client = client_endpoint(client_dir.path());
        let mut request = client.propose(&proposal()).unwrap();
        let mut authorization = PaidJobAuthorizationV1::decode(&request.authorization).unwrap();
        match invalid {
            "price" => authorization.price += 1,
            "deadline" => authorization.acceptance_deadline = CURSOR - 1,
            _ => {}
        }
        let id = work_id(fetch_ready().channel(), &authorization);
        request.authorization = authorization.encode();
        request.client_signature = super::client().sign(signing_hash(id)).as_bytes().to_vec();
        if invalid == "signature" {
            request.client_signature[0] ^= 1;
        }
        assert!(matches!(
            service.accept(&request).outcome,
            Some(hellas_rpc::pb::work::accept_work_response::Outcome::Refused(_))
        ));
        let backend = FetchBackend::default();
        assert!(matches!(
            run_accepted_work(&service, &fetch_ready(), &backend, id).await,
            Err(RunError::NoSuchJob)
        ));
        assert_eq!(backend.0.load(Ordering::SeqCst), 0);
        assert_no_bodies(provider_dir.path());
        assert_no_bodies(client_dir.path());
    }
}

fn input(retention: Retention) -> PreparedPaidFetchInputV1 {
    input_with_assurance(retention, Assurance::ProducerSigned)
}
fn input_with_assurance(retention: Retention, assurance: Assurance) -> PreparedPaidFetchInputV1 {
    let environment = FetchEnvironment::OpenAiResponses;
    let events = build_input_events_with_retention(
        "openai",
        "responses",
        PROMPT,
        environment.manifest_id(),
        assurance,
        &producer(0x21),
        retention,
    )
    .unwrap();
    PreparedPaidFetchInputV1::new(&events, &environment.manifest()).unwrap()
}

fn proposal() -> JobProposal {
    JobProposal {
        prepared_input: input(Retention::Ephemeral).into(),
        deadlines: deadlines(),
    }
}

fn metadata_store(root: &std::path::Path) -> ChannelStore {
    store_for(root, &fetch_ready(), Role::Provider)
}

fn store_for(root: &std::path::Path, ready: &ReadyChannel, role: Role) -> ChannelStore {
    let mut store = ChannelStore::open_metadata_only(
        root,
        ready.channel().clone(),
        settlement(),
        role,
        origin(),
        &Secp256k1Verifier::new(),
    )
    .unwrap();
    advance(&mut store, CURSOR);
    store
}

fn service(root: &std::path::Path) -> WorkService {
    WorkService::new(
        ProviderEndpoint::new(fetch_ready(), metadata_store(root), provider()).unwrap(),
    )
}

fn client_endpoint(root: &std::path::Path) -> ClientEndpoint {
    let store = store_for(root, &fetch_ready(), Role::Client);
    ClientEndpoint::new(fetch_ready(), store, client()).unwrap()
}

#[tokio::test]
async fn paid_fetch_larger_than_a_wire_frame_streams_and_pays_without_disk_payloads() {
    use hellas_rpc::services::work::{WorkClientImpl, WorkServer};
    use hellas_wire::{Dispatcher, StreamTransport, mux::MuxTransport};
    use hellas_work::work::{admit_payment, fetch_result_stream};
    struct LargeFetch;
    impl PaidWorkBackend for LargeFetch {
        async fn fetch(
            &self,
            input: PreparedFetchInput,
        ) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
            let request = verify_input_events(&input.into_parts().fetch_input_transcript).unwrap();
            let key = provider_producer();
            let mut transcript = FetchOutputTranscriptBuilder::new(
                request.input_commitment,
                request.assurance,
                &key,
            );
            for index in 0..256 {
                transcript
                    .push_event(
                        encode_fetch_event_payload(&OutputEvent::TextDelta {
                            index,
                            delta: RESPONSE.repeat(400),
                            channel: TextChannel::Output,
                        })
                        .unwrap(),
                    )
                    .unwrap();
            }
            Ok(transcript
                .finish(
                    encode_fetch_terminal_payload(&OutputEvent::Finished {
                        stop_reason: StopReason::EndOfText,
                        usage: None,
                    })
                    .unwrap(),
                )
                .unwrap())
        }
    }
    let mut profile = policy();
    let PaidWorkPolicy::Fetch { policy, .. } = &mut profile else {
        unreachable!()
    };
    policy.max_output_events = 512;
    policy.max_output_bytes = 8 << 20;
    policy.max_spool_bytes = 16 << 20;
    policy.max_encoded_result_frame = 64 << 10;
    let ready = ready_of(descriptor_with(profile), CURSOR);
    let client_dir = temp();
    let provider_dir = temp();
    let mut client = ClientEndpoint::new(
        ready.clone(),
        store_for(client_dir.path(), &ready, Role::Client),
        super::client(),
    )
    .unwrap();
    let service = WorkService::new(
        ProviderEndpoint::new(
            ready.clone(),
            store_for(provider_dir.path(), &ready, Role::Provider),
            provider(),
        )
        .unwrap(),
    );
    let request = client.propose(&proposal()).unwrap();
    let id = client.accepted(&service.accept(&request)).unwrap();
    run_accepted_work(&service, &ready, &LargeFetch, id)
        .await
        .unwrap();
    let (transport, server) = transport::transport_pair();
    let serving = tokio::spawn(async move {
        let handler = WorkServer(service);
        while let Ok(Some(inbound)) = server.accept().await {
            let _ = Dispatcher::<MuxTransport>::dispatch(&handler, inbound).await;
        }
    });
    let mut received = 0;
    let delivered = tokio::time::timeout(
        std::time::Duration::from_secs(45),
        fetch_result_stream(transport.clone(), &mut client, &ready, id, |_| {
            received += 1;
            Ok(())
        }),
    )
    .await
    .unwrap_or_else(|error| {
        panic!(
            "{error}: received {received} prefixes, server finished={}",
            serving.is_finished()
        )
    })
    .unwrap();
    assert_eq!(received, 256);
    assert!(delivered.transcript.len() > hellas_wire::frame::MAX_FRAME_BYTES);
    assert_eq!(
        admit_payment(&WorkClientImpl::new(transport), &mut client, id)
            .await
            .unwrap(),
        PRICE
    );
    assert_no_bodies(client_dir.path());
    assert_no_bodies(provider_dir.path());
    serving.abort();
    let _ = serving.await;
}

#[tokio::test]
async fn streamed_fetch_cannot_pay_without_a_complete_authenticated_terminal() {
    use hellas_rpc::pb::work::{WorkStreamEvent, WorkStreamTerminal, work_stream_event::Outcome};
    use hellas_rpc::protocol::work::{decode_transcript, encode_transcript};
    use hellas_rpc::services::work::StreamResult;
    use hellas_wire::{StreamTransport, WireCode, WireStatus, mux::MuxTransport};
    use hellas_work::work::fetch_result_stream;
    for fault in ["missing-prefix", "signature", "duplicate", "status", "none"] {
        let provider_dir = temp();
        let client_dir = temp();
        let mut client = client_endpoint(client_dir.path());
        let service = service(provider_dir.path());
        let request = client.propose(&proposal()).unwrap();
        let id = client.accepted(&service.accept(&request)).unwrap();
        run_accepted_work(&service, &fetch_ready(), &FetchBackend::default(), id)
            .await
            .unwrap();
        let exporter = [0x5e; 32];
        let delivered = service
            .deliver(&client.request_delivery(id, &exporter).unwrap(), &exporter)
            .unwrap();
        let events = decode_transcript(&delivered.transcript, 65536).unwrap();
        let mut terminal = WorkStreamTerminal {
            result: delivered.result.encode(),
            provider_signature: delivered.signature.as_bytes().to_vec(),
            terminal_transcript: encode_transcript(&events[1..]).unwrap(),
        };
        if fault == "signature" {
            terminal.provider_signature[0] ^= 1;
        }
        let end = WorkStreamEvent {
            outcome: Some(Outcome::Terminal(terminal)),
        };
        let mut frames = Vec::new();
        if fault != "missing-prefix" {
            frames.push(Ok(WorkStreamEvent {
                outcome: Some(Outcome::Prefix(encode_transcript(&events[..1]).unwrap())),
            }));
        }
        frames.push(Ok(end.clone()));
        if fault == "duplicate" {
            frames.push(Ok(end));
        }
        if fault == "status" {
            frames.push(Err(WireStatus::new(WireCode::Unavailable, "interrupted")));
        }
        let (transport, server) = transport::transport_pair();
        let serving = tokio::spawn(async move {
            let inbound = server.accept().await.unwrap().unwrap();
            hellas_rpc::call::dispatch_server_streaming::<MuxTransport, StreamResult, _, _, _>(
                inbound,
                move |_| async move { Ok(futures::stream::iter(frames)) },
            )
            .await
            .unwrap();
        });
        let result =
            fetch_result_stream(transport, &mut client, &fetch_ready(), id, |_| Ok(())).await;
        serving.await.unwrap();
        if fault == "none" {
            result.unwrap();
            assert!(client.pay(id).is_ok());
        } else {
            assert!(result.is_err(), "{fault}");
            assert!(
                client.pay(id).is_err(),
                "{fault} must not create payable evidence"
            );
            assert_eq!(
                client.state().job_by_id(id).unwrap().phase(),
                JobPhase::Accepted
            );
        }
        assert_no_bodies(client_dir.path());
    }
}

#[derive(Default)]
struct FetchBackend(AtomicUsize);

impl PaidWorkBackend for FetchBackend {
    async fn fetch(
        &self,
        input: PreparedFetchInput,
    ) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
        self.0.fetch_add(1, Ordering::SeqCst);
        let parts = input.into_parts();
        let request = verify_input_events(&parts.fetch_input_transcript).unwrap();
        assert_eq!(request.body.as_bytes(), PROMPT);
        assert_eq!(request.retention, Retention::Ephemeral);
        let key = provider_producer();
        let mut builder =
            FetchOutputTranscriptBuilder::new(request.input_commitment, request.assurance, &key);
        builder
            .push_event(
                encode_fetch_event_payload(&OutputEvent::TextDelta {
                    index: 0,
                    delta: RESPONSE.into(),
                    channel: TextChannel::Output,
                })
                .unwrap(),
            )
            .unwrap();
        Ok(builder
            .finish(
                encode_fetch_terminal_payload(&OutputEvent::Finished {
                    stop_reason: StopReason::EndOfText,
                    usage: None,
                })
                .unwrap(),
            )
            .unwrap())
    }
}

fn assert_no_bodies(root: &std::path::Path) {
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            assert_no_bodies(&path);
        } else {
            let bytes = std::fs::read(&path).unwrap();
            for body in [PROMPT, RESPONSE.as_bytes()] {
                assert!(
                    !bytes.windows(body.len()).any(|window| window == body),
                    "payload in {}",
                    path.display()
                );
            }
        }
    }
}

#[tokio::test]
async fn fetch_is_run_delivered_and_paid_without_provider_disk_bodies() {
    let provider_dir = temp();
    let client_dir = temp();
    let mut client = client_endpoint(client_dir.path());
    let service = service(provider_dir.path());
    let backend = FetchBackend::default();
    let request = client.propose(&proposal()).unwrap();
    let id = client.accepted(&service.accept(&request)).unwrap();
    assert_no_bodies(provider_dir.path());
    assert!(matches!(
        run_accepted_work(&service, &fetch_ready(), &backend, id)
            .await
            .unwrap(),
        RunOutcome::Completed { .. }
    ));
    assert_no_bodies(provider_dir.path());
    let request = client.request_delivery(id, &[8; 32]).unwrap();
    let delivered = service.deliver(&request, &[8; 32]).unwrap();
    client
        .receive(
            id,
            &fetch_ready(),
            &WorkDelivered {
                result: delivered.result.encode(),
                provider_signature: delivered.signature.as_bytes().to_vec(),
                transcript: delivered.transcript,
            },
        )
        .unwrap();
    assert_no_bodies(provider_dir.path());
    assert_no_bodies(client_dir.path());
    let payment = client.pay(id).unwrap();
    drop(client);
    let mut client = client_endpoint(client_dir.path());
    assert_eq!(client.pay(id).unwrap(), payment);
    assert_no_bodies(client_dir.path());

    // A delivery already happened: restart loses bodies but can still bank the signed payment.
    drop(service);
    let store = metadata_store(provider_dir.path());
    assert!(
        store
            .state()
            .job_by_id(id)
            .unwrap()
            .prepared_input()
            .is_empty()
    );
    assert!(store.state().job_by_id(id).unwrap().transcript().is_empty());
    let mut recovered = ProviderEndpoint::new(fetch_ready(), store, provider()).unwrap();
    assert!(matches!(
        recovered.deliver(&request, &fetch_ready(), &[8; 32]),
        Err(DeliverError::NoResult { .. })
    ));
    assert_eq!(recovered.admit(&payment).unwrap(), PRICE);
    assert_eq!(recovered.admit(&payment).unwrap(), PRICE);
    assert_eq!(backend.0.load(Ordering::SeqCst), 1);
    assert_no_bodies(provider_dir.path());
}

#[tokio::test]
async fn restarting_an_accepted_fetch_never_reinvokes_from_a_missing_payload() {
    let provider_dir = temp();
    let client_dir = temp();
    let mut client = client_endpoint(client_dir.path());
    let service_before = service(provider_dir.path());
    let request = client.propose(&proposal()).unwrap();
    let id = client.accepted(&service_before.accept(&request)).unwrap();
    drop(service_before);
    let backend = FetchBackend::default();
    let outcome = run_accepted_work(&service(provider_dir.path()), &fetch_ready(), &backend, id)
        .await
        .unwrap();
    assert_eq!(outcome, RunOutcome::Indeterminate);
    assert_eq!(backend.0.load(Ordering::SeqCst), 0);
    assert_no_bodies(provider_dir.path());
}

#[test]
fn fetch_refuses_payload_journals_and_retention_requests() {
    let provider_dir = temp();
    assert!(matches!(
        ProviderEndpoint::new(
            fetch_ready(),
            store_at(provider_dir.path(), CURSOR),
            provider()
        ),
        Err(EndpointError::PayloadRetention)
    ));
    let client_dir = temp();
    let mut client = client_endpoint(client_dir.path());
    let retained = JobProposal {
        prepared_input: input(Retention::Retain).into(),
        deadlines: deadlines(),
    };
    assert!(client.propose(&retained).is_err());

    // A peer bypassing the client API cannot obtain a provider acceptance either.
    let provider_dir = temp();
    let channel = fetch_ready();
    let authorization = policy()
        .propose(channel.channel(), &retained.prepared_input, 1, deadlines())
        .unwrap();
    let id = work_id(channel.channel(), &authorization);
    let request = hellas_rpc::pb::work::AcceptWorkRequest {
        authorization: authorization.encode(),
        client_signature: super::client().sign(signing_hash(id)).as_bytes().to_vec(),
        prepared_input: retained.prepared_input.encode().unwrap(),
    };
    assert!(matches!(
        service(provider_dir.path()).accept(&request).outcome,
        Some(hellas_rpc::pb::work::accept_work_response::Outcome::Refused(_))
    ));
    assert_no_bodies(provider_dir.path());
}

#[test]
fn fetch_close_descriptor_round_trips_and_rejects_profile_version_confusion() {
    use hellas_rpc::protocol::work_setup::CloseDescriptor;
    let descriptor = descriptor_with(policy()).close_descriptor();
    let bytes = descriptor.encode();
    assert_eq!(CloseDescriptor::decode(&bytes).unwrap(), descriptor);
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(CloseDescriptor::decode(&trailing).is_err());
    let mut wrong_version = bytes;
    wrong_version[0] = 1;
    assert!(CloseDescriptor::decode(&wrong_version).is_err());
}

#[tokio::test]
async fn fetch_output_limits_include_terminal_and_bad_results_are_never_payable() {
    let provider_dir = temp();
    let client_dir = temp();
    let mut client = client_endpoint(client_dir.path());
    let service = service(provider_dir.path());
    let request = client.propose(&proposal()).unwrap();
    let id = client.accepted(&service.accept(&request)).unwrap();
    let RunAdmission::InvokeFetch(input) = service.begin_run(id, &fetch_ready()).unwrap() else {
        panic!("first Fetch dispatch");
    };
    let transcript = FetchBackend::default().fetch(*input).await.unwrap();
    let PaidWorkPolicy::Fetch { mut policy, .. } = policy() else {
        unreachable!()
    };
    policy.max_output_events = u32::try_from(transcript.len() - 1).unwrap();
    assert!(
        hellas_rpc::protocol::work_fetch::check_fetch_output_limits(&policy, &transcript).is_err()
    );
    policy.max_output_events += 1;
    policy.max_output_bytes = 1;
    assert!(
        hellas_rpc::protocol::work_fetch::check_fetch_output_limits(&policy, &transcript).is_err()
    );
    assert!(
        service
            .record_result(id, &transcript[..transcript.len() - 1])
            .is_err()
    );
    assert!(client.pay(id).is_err());
    assert_no_bodies(provider_dir.path());
}

#[tokio::test]
async fn app_attest_paid_fetch_uses_the_signed_scheme_without_disk_payloads() {
    let provider_dir = temp();
    let client_dir = temp();
    let mut client = client_endpoint(client_dir.path());
    let service = service(provider_dir.path());
    let proposal = JobProposal {
        prepared_input: input_with_assurance(Retention::Ephemeral, Assurance::AppleAppAttest)
            .into(),
        deadlines: deadlines(),
    };
    let request = client.propose(&proposal).unwrap();
    let id = client.accepted(&service.accept(&request)).unwrap();
    let backend = FetchBackend::default();
    assert!(matches!(
        run_accepted_work(&service, &fetch_ready(), &backend, id)
            .await
            .unwrap(),
        RunOutcome::Completed { .. }
    ));
    let request = client.request_delivery(id, &[8; 32]).unwrap();
    let delivered = service.deliver(&request, &[8; 32]).unwrap();
    client
        .receive(
            id,
            &fetch_ready(),
            &WorkDelivered {
                result: delivered.result.encode(),
                provider_signature: delivered.signature.as_bytes().to_vec(),
                transcript: delivered.transcript,
            },
        )
        .unwrap();
    let payment = client.pay(id).unwrap();
    use hellas_rpc::services::work::WorkHandler;
    let response: hellas_rpc::call::WithTrailer<hellas_rpc::pb::work::AdmitCertificateResponse> =
        service
            .admit_certificate(payment, hellas_wire::TransportContext::default())
            .await
            .unwrap()
            .into();
    assert!(matches!(
        response.response.outcome,
        Some(hellas_rpc::pb::work::admit_certificate_response::Outcome::Paid(_))
    ));
    assert_no_bodies(provider_dir.path());
}
