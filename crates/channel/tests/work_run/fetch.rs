use super::*;
use hellas_channel::model::work::PrivateRecord as _;
use hellas_channel::test_support::channel::accept_uploaded_client;
use hellas_channel::work::{Admitted, ClientEndpoint, JobProposal, fetch_result_stream};
use hellas_rpc::fetch::{
    build_input_events_with_retention, encode_fetch_event_payload, encode_fetch_terminal_payload,
    verify_input_events,
};
use hellas_rpc::output::{OutputEvent, StopReason, TextChannel};
use hellas_rpc::protocol::invocation::{
    Admission, Limits, PreparedInvocation,
    fetch::{self as invocation_fetch, FetchAdmission, FetchLimits, FetchRoutePolicy},
    output::OutputStream,
};
use hellas_rpc::{Assurance, Retention};

const PROMPT: &[u8] = br#"{"input":"private-customer-prompt-never-on-provider-disk"}"#;
const RESPONSE: &str = "private-provider-response-never-on-provider-disk";

use hellas_channel::test_support::transport;

#[tokio::test]
async fn fetch_streams_before_terminal_then_pays_once_with_metadata_only_journals() {
    use hellas_channel::work::{PaidProgress, admit_payment, fetch_result_stream};
    use hellas_rpc::services::work::{WorkClientImpl, WorkServer};
    use hellas_wire::{Dispatcher, StreamTransport, mux::MuxTransport};

    struct PausedFetch(Arc<tokio::sync::Notify>);
    impl WorkBackend for PausedFetch {
        fn try_admit(
            &self,
            domain: hellas_channel::work::admission::CapacityDomain,
        ) -> Result<hellas_channel::work::admission::WorkPermit, hellas_channel::work::BackendFault>
        {
            Err(hellas_channel::work::admission::AdmissionError::Unsupported(domain).into())
        }

        async fn execute_stream(
            &self,
            input: Admitted,
            progress: PaidProgress,
        ) -> Result<Vec<hellas_rpc::OutputEventEnvelope>, hellas_channel::work::BackendFault>
        {
            let events = FetchBackend::default().execute(input).await?;
            progress(events[0].clone())?;
            self.0.notified().await;
            Ok(events)
        }
    }
    for assurance in [Assurance::ProducerSigned, Assurance::AppleAppAttest] {
        let provider_dir = temp();
        let client_dir = temp();
        let mut client = client_endpoint(client_dir.path()).await;
        let service = service(provider_dir.path()).await;
        let proposal = JobProposal {
            prepared_input: input_with_assurance(Retention::Ephemeral, assurance),
            deadlines: deadlines(),
        };
        let request = client.propose(&proposal).await.unwrap();
        let id = client
            .accepted(&accept_uploaded_client(&service, &client, &request).await)
            .await
            .unwrap();
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
        let prefix_seen = tokio::sync::Notify::new();
        let ready = fetch_ready();
        let (delivery, ()) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(
                fetch_result_stream(transport.clone(), &mut client, &ready, id, |event| {
                    assert!(!worker.is_finished());
                    assert_eq!(
                        event.event().body().kind(),
                        hellas_rpc::protocol::invocation::output::ARTIFACT_CHUNK
                    );
                    prefixes += 1;
                    prefix_seen.notify_one();
                    Ok(())
                }),
                async {
                    prefix_seen.notified().await;
                    assert_eq!(
                        service
                            .with_state(|s| s.job_by_id(id).unwrap().phase())
                            .await
                            .unwrap(),
                        JobPhase::Streaming
                    );
                    release.notify_one();
                }
            )
        })
        .await
        .unwrap();
        delivery.unwrap();
        assert_eq!(prefixes, 1);
        assert!(matches!(
            worker.await.unwrap().unwrap(),
            RunOutcome::Completed { .. }
        ));
        client.verified(id).await.unwrap();
        let rpc = WorkClientImpl::new(transport);
        assert_eq!(admit_payment(&rpc, &mut client, id).await.unwrap(), PRICE);
        assert_eq!(admit_payment(&rpc, &mut client, id).await.unwrap(), PRICE);
        assert_no_bodies(client_dir.path());
        assert_no_bodies(provider_dir.path());
        serving.abort();
        let _ = serving.await;
    }
}

fn policy() -> InvocationPolicy {
    InvocationPolicy {
        admissions: vec![Admission::Fetch {
            admission: FetchAdmission {
                contract: test_responses_contract(),
                route: FetchRoutePolicy::sealed_route("openai", "responses").unwrap(),
                limits: FetchLimits {
                    max_request_body_bytes: 4096,
                    max_output_events: 64,
                    max_spool_bytes: 65536,
                    max_encoded_result_frame: 65536,
                    max_encoded_prepared_input: 65536,
                },
            },
        }],
        limits: Limits {
            max_upload_bytes: 65536,
            max_output_bytes: 16384,
            max_steps: 1,
            execution_timeout_ms: 60_000,
        },
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
        let service = service(provider_dir.path()).await;
        let mut client = client_endpoint(client_dir.path()).await;
        let mut request = client.propose(&proposal()).await.unwrap();
        let mut authorization = PaidJobAuthorizationV2::decode(&request.authorization).unwrap();
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
            accept_uploaded_client(&service, &client, &request)
                .await
                .outcome,
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

fn input(retention: Retention) -> PreparedInvocation {
    input_with_assurance(retention, Assurance::ProducerSigned)
}
fn input_with_assurance(retention: Retention, assurance: Assurance) -> PreparedInvocation {
    input_under(&policy(), retention, assurance)
}
fn input_under(
    policy: &InvocationPolicy,
    retention: Retention,
    assurance: Assurance,
) -> PreparedInvocation {
    let environment = test_responses_contract();
    let events = build_input_events_with_retention(
        "openai",
        "responses",
        PROMPT,
        environment.manifest_id(),
        assurance,
        &producer(0x21),
        Retention::Ephemeral,
    )
    .unwrap();
    let mut input = invocation_fetch::prepare(
        &events,
        &environment,
        provider_producer().public_key(),
        policy.canonical_bytes().unwrap(),
        [1; 32],
    )
    .unwrap();
    if retention == Retention::Retain {
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
        input.input.artifacts[0].bytes = hellas_rpc::JsonBytes(
            hellas_rpc::protocol::value::canonical_dag_cbor(&events).unwrap(),
        );
        input.request.input = input.input.content_id().unwrap();
        input.request.retain = true;
    }
    input
}
fn request(input: &PreparedInvocation) -> hellas_rpc::fetch::FetchInput {
    let events: Vec<hellas_rpc::InputEventEnvelope> =
        hellas_rpc::protocol::value::decode_canonical_dag_cbor(
            input.input.artifacts[0].bytes.as_bytes(),
        )
        .unwrap();
    verify_input_events(&events).unwrap()
}
fn signed_output(input: &PreparedInvocation, payloads: &[Vec<u8>]) -> Vec<OutputEventEnvelope> {
    let output = invocation_fetch::output(
        payloads,
        &encode_fetch_terminal_payload(&OutputEvent::Finished {
            stop_reason: StopReason::EndOfText,
            usage: None,
        })
        .unwrap(),
    )
    .unwrap();
    let key = provider_producer();
    let mut stream = OutputStream::new(&input.request, &key, 16 << 20).unwrap();
    let mut offset = 0;
    for payload in payloads {
        let bytes = invocation_fetch::frame_event(payload).unwrap();
        stream
            .push(
                invocation_fetch::RESPONSE_EVENTS,
                invocation_fetch::RESPONSE_EVENTS_FORMAT,
                offset,
                &bytes,
            )
            .unwrap();
        offset += bytes.len() as u64;
    }
    stream.finish(&output, 64 << 10).unwrap()
}
async fn receive(
    service: &WorkService,
    client: &mut ClientEndpoint,
    ready: &ReadyChannel,
    id: Digest,
) -> hellas_channel::work::Delivery {
    let (transport, server) = transport::transport_pair();
    let serving = hellas_channel::test_support::channel::serve_work(server, service.clone());
    let result = fetch_result_stream(transport, client, ready, id, |_| Ok(()))
        .await
        .unwrap();
    serving.abort();
    let _ = serving.await;
    client.verified(id).await.unwrap();
    result
}

fn proposal() -> JobProposal {
    JobProposal {
        prepared_input: input(Retention::Ephemeral),
        deadlines: deadlines(),
    }
}

async fn metadata_store(root: &std::path::Path) -> ChannelStore {
    store_for(root, &fetch_ready(), Role::Provider).await
}

async fn store_for(root: &std::path::Path, ready: &ReadyChannel, role: Role) -> ChannelStore {
    let mut store = ChannelStore::open(
        root,
        ready.channel().clone(),
        settlement(),
        role,
        origin(),
        &Secp256k1Verifier::new(),
    )
    .await
    .unwrap();
    advance(&mut store, CURSOR).await;
    store
}

async fn service(root: &std::path::Path) -> WorkService {
    WorkService::new(
        ProviderEndpoint::new(fetch_ready(), metadata_store(root).await, provider()).unwrap(),
    )
}

async fn client_endpoint(root: &std::path::Path) -> ClientEndpoint {
    let store = store_for(root, &fetch_ready(), Role::Client).await;
    ClientEndpoint::new(fetch_ready(), store, client()).unwrap()
}

#[tokio::test]
async fn paid_fetch_larger_than_a_wire_frame_streams_and_pays_without_disk_payloads() {
    use hellas_channel::work::{admit_payment, fetch_result_stream};
    use hellas_rpc::services::work::{WorkClientImpl, WorkServer};
    use hellas_wire::{Dispatcher, StreamTransport, mux::MuxTransport};
    struct LargeFetch;
    impl WorkBackend for LargeFetch {
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
        ) -> Result<Vec<hellas_rpc::OutputEventEnvelope>, hellas_channel::work::BackendFault>
        {
            let _request = request(input.invocation());
            let payloads: Vec<_> = (0..256)
                .map(|index| {
                    encode_fetch_event_payload(&OutputEvent::TextDelta {
                        index,
                        delta: RESPONSE.repeat(400),
                        channel: TextChannel::Output,
                    })
                    .unwrap()
                })
                .collect();
            Ok(signed_output(input.invocation(), &payloads))
        }
    }
    let mut profile = policy();
    profile.limits.max_output_bytes = 8 << 20;
    let Admission::Fetch { admission } = &mut profile.admissions[0] else {
        unreachable!()
    };
    admission.limits.max_output_events = 512;
    admission.limits.max_spool_bytes = 16 << 20;
    admission.limits.max_encoded_result_frame = 64 << 10;
    let ready = ready_of(descriptor_with(profile.clone()), CURSOR);
    let client_dir = temp();
    let provider_dir = temp();
    let mut client = ClientEndpoint::new(
        ready.clone(),
        store_for(client_dir.path(), &ready, Role::Client).await,
        super::client(),
    )
    .unwrap();
    let service = WorkService::new(
        ProviderEndpoint::new(
            ready.clone(),
            store_for(provider_dir.path(), &ready, Role::Provider).await,
            provider(),
        )
        .unwrap(),
    );
    let request = client
        .propose(&JobProposal {
            prepared_input: input_under(&profile, Retention::Ephemeral, Assurance::ProducerSigned),
            deadlines: deadlines(),
        })
        .await
        .unwrap();
    let id = client
        .accepted(&accept_uploaded_client(&service, &client, &request).await)
        .await
        .unwrap();
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
    client.verified(id).await.unwrap();
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
    use hellas_channel::model::work::{decode_transcript, encode_transcript};
    use hellas_channel::work::fetch_result_stream;
    use hellas_rpc::pb::work::{WorkStreamEvent, WorkStreamTerminal, work_stream_event::Outcome};
    use hellas_rpc::services::work::StreamResult;
    use hellas_wire::{StreamTransport, WireCode, WireStatus, mux::MuxTransport};
    for fault in ["missing-prefix", "signature", "duplicate", "status", "none"] {
        let provider_dir = temp();
        let client_dir = temp();
        let mut client = client_endpoint(client_dir.path()).await;
        let service = service(provider_dir.path()).await;
        let request = client.propose(&proposal()).await.unwrap();
        let id = client
            .accepted(&accept_uploaded_client(&service, &client, &request).await)
            .await
            .unwrap();
        run_accepted_work(&service, &fetch_ready(), &FetchBackend::default(), id)
            .await
            .unwrap();
        let exporter = [0x5e; 32];
        use futures::StreamExt as _;
        use hellas_rpc::services::work::WorkHandler as _;
        let mut source = service
            .stream_result(
                client.request_delivery(id, &exporter).unwrap(),
                hellas_wire::TransportContext {
                    open_exporter: Some(exporter),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let mut source_prefix = Vec::new();
        let mut source_terminal = None;
        while let Some(frame) = source.next().await {
            match frame.unwrap().outcome.unwrap() {
                Outcome::Prefix(bytes) => {
                    source_prefix.extend(decode_transcript(&bytes, 65536).unwrap())
                }
                Outcome::Terminal(terminal) => {
                    source_prefix
                        .extend(decode_transcript(&terminal.terminal_transcript, 65536).unwrap());
                    source_terminal = Some(terminal);
                }
                other => panic!("unexpected source frame {other:?}"),
            }
        }
        let source_terminal = source_terminal.unwrap();
        let delivered = hellas_channel::work::Delivery {
            result: hellas_channel::model::work::PaidJobResultV1::decode(&source_terminal.result)
                .unwrap(),
            signature: hellas_kernel::Sig::from_bytes(
                source_terminal.provider_signature.try_into().unwrap(),
            ),
            transcript: encode_transcript(&source_prefix).unwrap(),
        };
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
                move |_| async move {
                    Ok(hellas_rpc::call::ResponseStream::new(
                        futures::stream::iter(frames),
                    ))
                },
            )
            .await
            .unwrap();
        });
        let result =
            fetch_result_stream(transport, &mut client, &fetch_ready(), id, |_| Ok(())).await;
        serving.await.unwrap();
        if fault == "none" {
            result.unwrap();
            client.verified(id).await.unwrap();
            assert!(client.pay(id).await.is_ok());
        } else {
            assert!(result.is_err(), "{fault}");
            assert!(
                client.pay(id).await.is_err(),
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

impl WorkBackend for FetchBackend {
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
    ) -> Result<Vec<hellas_rpc::OutputEventEnvelope>, hellas_channel::work::BackendFault> {
        self.0.fetch_add(1, Ordering::SeqCst);
        let request = request(input.invocation());
        assert_eq!(request.body.as_bytes(), PROMPT);
        assert_eq!(request.retention, Retention::Ephemeral);
        Ok(signed_output(
            input.invocation(),
            &[encode_fetch_event_payload(&OutputEvent::TextDelta {
                index: 0,
                delta: RESPONSE.into(),
                channel: TextChannel::Output,
            })
            .unwrap()],
        ))
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
    let mut client = client_endpoint(client_dir.path()).await;
    let service = service(provider_dir.path()).await;
    let backend = FetchBackend::default();
    let request = client.propose(&proposal()).await.unwrap();
    let id = client
        .accepted(&accept_uploaded_client(&service, &client, &request).await)
        .await
        .unwrap();
    assert_no_bodies(provider_dir.path());
    assert!(matches!(
        run_accepted_work(&service, &fetch_ready(), &backend, id)
            .await
            .unwrap(),
        RunOutcome::Completed { .. }
    ));
    assert_no_bodies(provider_dir.path());
    let request = client.request_delivery(id, &[8; 32]).unwrap();
    receive(&service, &mut client, &fetch_ready(), id).await;
    assert_no_bodies(provider_dir.path());
    assert_no_bodies(client_dir.path());
    let payment = client.pay(id).await.unwrap();
    drop(client);
    let mut client = client_endpoint(client_dir.path()).await;
    assert_eq!(client.pay(id).await.unwrap(), payment);
    assert_no_bodies(client_dir.path());

    // A delivery already happened: restart loses bodies but can still bank the signed payment.
    drop(service);
    let store = metadata_store(provider_dir.path()).await;
    assert!(
        store
            .state()
            .job_by_id(id)
            .unwrap()
            .prepared_input()
            .is_empty()
    );
    assert!(store.state().job_by_id(id).unwrap().transcript().is_empty());
    let recovered =
        WorkService::new(ProviderEndpoint::new(fetch_ready(), store, provider()).unwrap());
    use futures::StreamExt as _;
    use hellas_rpc::services::work::WorkHandler as _;
    let mut frames = recovered
        .stream_result(
            request,
            hellas_wire::TransportContext {
                open_exporter: Some([8; 32]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), frames.next())
        .await
        .expect("a restarted ephemeral result promptly refuses missing bodies")
        .unwrap()
        .unwrap();
    assert!(matches!(
        first.outcome,
        Some(hellas_rpc::pb::work::work_stream_event::Outcome::Refused(_))
    ));
    drop(frames);
    drop(recovered);
    let mut recovered = ProviderEndpoint::new(
        fetch_ready(),
        metadata_store(provider_dir.path()).await,
        provider(),
    )
    .unwrap();
    assert_eq!(recovered.admit(&payment).await.unwrap(), PRICE);
    assert_eq!(recovered.admit(&payment).await.unwrap(), PRICE);
    assert_eq!(backend.0.load(Ordering::SeqCst), 1);
    assert_no_bodies(provider_dir.path());
}

#[tokio::test]
async fn restarting_an_accepted_fetch_never_reinvokes_from_a_missing_payload() {
    let provider_dir = temp();
    let client_dir = temp();
    let mut client = client_endpoint(client_dir.path()).await;
    let service_before = service(provider_dir.path()).await;
    let request = client.propose(&proposal()).await.unwrap();
    let id = client
        .accepted(&accept_uploaded_client(&service_before, &client, &request).await)
        .await
        .unwrap();
    drop(service_before);
    let backend = FetchBackend::default();
    let outcome = run_accepted_work(
        &service(provider_dir.path()).await,
        &fetch_ready(),
        &backend,
        id,
    )
    .await
    .unwrap();
    assert_eq!(outcome, RunOutcome::Indeterminate);
    assert_eq!(backend.0.load(Ordering::SeqCst), 0);
    assert_no_bodies(provider_dir.path());
}

#[tokio::test]
async fn fetch_refuses_payload_journals_and_retention_requests() {
    // Every journal is metadata-only; a signed request cannot opt Fetch into retention.
    let client_dir = temp();
    let mut client = client_endpoint(client_dir.path()).await;
    let retained = JobProposal {
        prepared_input: input(Retention::Retain),
        deadlines: deadlines(),
    };
    assert!(client.propose(&retained).await.is_err());

    // A peer bypassing the client API cannot obtain a provider acceptance either.
    let provider_dir = temp();
    let channel = fetch_ready();
    let authorization = propose_authorization(
        channel.channel(),
        &policy(),
        channel.payment_policy(),
        &retained.prepared_input,
        1,
        deadlines(),
    )
    .unwrap();
    let id = work_id(channel.channel(), &authorization);
    let request = hellas_rpc::pb::work::AcceptWorkRequest {
        route: Some(hellas_rpc::pb::work::WorkRoute::payment(
            authorization.channel_id,
        )),
        authorization: authorization.encode(),
        client_signature: super::client().sign(signing_hash(id)).as_bytes().to_vec(),
        prepared_input: retained.prepared_input.canonical_bytes().unwrap(),
    };
    assert!(matches!(
        service(provider_dir.path())
            .await
            .accept(&request)
            .await
            .outcome,
        Some(hellas_rpc::pb::work::accept_work_response::Outcome::Refused(_))
    ));
    assert_no_bodies(provider_dir.path());
}

#[test]
fn fetch_close_descriptor_round_trips_and_rejects_profile_version_confusion() {
    use hellas_channel::model::setup::CloseDescriptor;
    let descriptor = descriptor_with(policy()).close_descriptor();
    let bytes = descriptor.encode().unwrap();
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
    let mut client = client_endpoint(client_dir.path()).await;
    let service = service(provider_dir.path()).await;
    let request = client.propose(&proposal()).await.unwrap();
    let id = client
        .accepted(&accept_uploaded_client(&service, &client, &request).await)
        .await
        .unwrap();
    let RunAdmission::Invoke(input) = service.begin_run(id, &fetch_ready()).await.unwrap() else {
        panic!("first Fetch dispatch");
    };
    let prepared = input.invocation().clone();
    let transcript = FetchBackend::default().execute(*input).await.unwrap();
    let checked = prepared.verify_output(
        &policy(),
        &producer(0x21).public_key(),
        &provider_producer().public_key(),
        &transcript,
    );
    assert!(checked.is_ok(), "{checked:?}");
    let mut policy = policy();
    let Admission::Fetch { admission } = &mut policy.admissions[0] else {
        unreachable!()
    };
    admission.limits.max_output_events = 1; // one application event plus its terminal
    let mut bounded = prepared.clone();
    bounded.application_policy = hellas_rpc::JsonBytes(policy.canonical_bytes().unwrap());
    assert!(
        bounded
            .verify_output(
                &policy,
                &producer(0x21).public_key(),
                &provider_producer().public_key(),
                &transcript
            )
            .is_err()
    );
    let Admission::Fetch { admission } = &mut policy.admissions[0] else {
        unreachable!()
    };
    admission.limits.max_output_events = 64;
    policy.limits.max_output_bytes = 1;
    let mut bounded = prepared.clone();
    bounded.application_policy = hellas_rpc::JsonBytes(policy.canonical_bytes().unwrap());
    assert!(
        bounded
            .verify_output(
                &policy,
                &producer(0x21).public_key(),
                &provider_producer().public_key(),
                &transcript
            )
            .is_err()
    );
    assert!(
        service
            .record_result(id, &transcript[..transcript.len() - 1])
            .await
            .is_err()
    );
    assert!(client.pay(id).await.is_err());
    assert_no_bodies(provider_dir.path());
}

#[tokio::test]
async fn app_attest_paid_fetch_uses_the_signed_scheme_without_disk_payloads() {
    let provider_dir = temp();
    let client_dir = temp();
    let mut client = client_endpoint(client_dir.path()).await;
    let service = service(provider_dir.path()).await;
    let proposal = JobProposal {
        prepared_input: input_with_assurance(Retention::Ephemeral, Assurance::AppleAppAttest),
        deadlines: deadlines(),
    };
    let request = client.propose(&proposal).await.unwrap();
    let id = client
        .accepted(&accept_uploaded_client(&service, &client, &request).await)
        .await
        .unwrap();
    let backend = FetchBackend::default();
    assert!(matches!(
        run_accepted_work(&service, &fetch_ready(), &backend, id)
            .await
            .unwrap(),
        RunOutcome::Completed { .. }
    ));
    receive(&service, &mut client, &fetch_ready(), id).await;
    let payment = client.pay(id).await.unwrap();
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

use hellas_channel::test_support::test_responses_contract;

#[tokio::test]
async fn the_generic_proposal_helper_ignores_unneeded_cached_root_openings_for_fetch() {
    use hellas_channel::{
        content::{EphemeralContent, InvocationContent},
        work::propose_work,
    };
    for cached in [false, true] {
        let provider_dir = temp();
        let client_dir = temp();
        let service = service(provider_dir.path()).await;
        let mut client = client_endpoint(client_dir.path()).await;
        let mut memory = EphemeralContent::default();
        if cached {
            let reference = memory.insert(test_responses_contract().canonical_bytes());
            assert_eq!(reference.id(), test_responses_contract().manifest().root());
        }
        let content = InvocationContent::Ephemeral(memory);
        let (transport, server) = transport::transport_pair();
        let serving = hellas_channel::test_support::channel::serve_work(server, service.clone());
        let id = propose_work(transport, &mut client, &proposal(), &content)
            .await
            .unwrap();
        assert_eq!(
            client.state().job_by_id(id).unwrap().phase(),
            JobPhase::Accepted
        );
        assert_eq!(
            service
                .with_state(|s| s.job_by_id(id).unwrap().phase())
                .await
                .unwrap(),
            JobPhase::Accepted
        );
        serving.abort();
        let _ = serving.await;
        assert_no_bodies(provider_dir.path());
        assert_no_bodies(client_dir.path());
    }
}
