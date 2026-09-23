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
    let mut store = ChannelStore::open_metadata_only(
        root,
        fetch_ready().channel().clone(),
        settlement(),
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
    let mut store = ChannelStore::open(
        root,
        fetch_ready().channel().clone(),
        settlement(),
        Role::Client,
        origin(),
        &Secp256k1Verifier::new(),
    )
    .unwrap();
    advance(&mut store, CURSOR);
    ClientEndpoint::new(fetch_ready(), store, client()).unwrap()
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
    let payment = client.pay(id).unwrap();

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
