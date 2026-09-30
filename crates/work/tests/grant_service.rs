use futures::StreamExt;
use hellas_rpc::{
    pb::work::*,
    protocol::{
        work::*,
        work_grant::{budget::*, records::*, standing::*, *},
    },
    *,
};
use hellas_wire::{
    AuthLevel, Dispatcher, PeerIdentity, StreamTransport, TransportContext, mux::MuxTransport,
};
use hellas_work::{
    grant_service::GrantService,
    work::{admission::*, *},
    work_store::grant::*,
};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::{Notify, Semaphore};
mod common_grant;
use common_grant::*;
#[path = "support/transport.rs"]
#[allow(dead_code)]
mod transport;

#[derive(Clone)]
struct Backend {
    slots: Arc<Semaphore>,
    calls: Arc<AtomicUsize>,
    queued: Option<Arc<Notify>>,
    started: Arc<Notify>,
    finish: Arc<Notify>,
    http_status: Option<u16>,
}
impl Backend {
    fn new() -> Self {
        Self {
            slots: Arc::new(Semaphore::new(1)),
            calls: Arc::new(AtomicUsize::new(0)),
            queued: None,
            started: Arc::new(Notify::new()),
            finish: Arc::new(Notify::new()),
            http_status: None,
        }
    }
}
impl WorkBackend for Backend {
    fn try_admit(&self, domain: CapacityDomain) -> Result<WorkPermit, BackendFault> {
        Ok(WorkPermit::new(
            domain,
            self.slots
                .clone()
                .try_acquire_owned()
                .map_err(|_| BackendFault::new("full"))?,
        ))
    }
    async fn fetch_stream(
        &self,
        input: PreparedFetchInput,
        progress: PaidProgress,
    ) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
        let (parts, admission) = input.into_parts_and_admission();
        if let Some(queued) = &self.queued {
            queued.notified().await;
        }
        let _running = admission.dispatch()?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        let request =
            hellas_rpc::fetch::verify_input_events(&parts.fetch_input_transcript).unwrap();
        let key = principal(2).1;
        let mut output = hellas_rpc::fetch::FetchOutputTranscriptBuilder::new(
            request.input_commitment,
            request.assurance,
            &key,
        );
        use base64::Engine as _;
        use hellas_rpc::output::{AdaptorEvent, HttpResponseEvent, OutputEvent, TextChannel};
        let events = self.http_status.map_or_else(
            || {
                vec![OutputEvent::TextDelta {
                    index: 0,
                    delta: "private-grant-result".into(),
                    channel: TextChannel::Output,
                }]
            },
            |status| {
                vec![
                    OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Head {
                        status,
                        headers: vec![("content-type".into(), "application/json".into())],
                    })),
                    OutputEvent::Adaptor(AdaptorEvent::Http(HttpResponseEvent::Body {
                        base64: base64::engine::general_purpose::STANDARD
                            .encode(br#"{"usage":{"prompt_tokens":3,"completion_tokens":2}}"#),
                    })),
                ]
            },
        );
        for event in events {
            progress(
                output
                    .push_event(hellas_rpc::fetch::encode_fetch_event_payload(&event).unwrap())
                    .unwrap(),
            )?;
        }
        self.started.notify_one();
        self.finish.notified().await;
        Ok(output
            .finish(
                hellas_rpc::fetch::encode_fetch_terminal_payload(
                    &hellas_rpc::output::OutputEvent::Finished {
                        stop_reason: hellas_rpc::output::StopReason::EndOfText,
                        usage: None,
                    },
                )
                .unwrap(),
            )
            .unwrap())
    }
}
fn context() -> TransportContext {
    TransportContext {
        peer: Some(PeerIdentity([1; 32])),
        auth_level: AuthLevel::Vouched,
        open_exporter: Some([7; 32]),
        ..Default::default()
    }
}
fn request(store: &GrantStore, nonce: u64) -> AcceptWorkRequest {
    let (a, signature, input) = proposal(store, nonce);
    AcceptWorkRequest {
        route: Some(WorkRoute::grant(a.channel_id)),
        authorization: a.encode(),
        client_signature: signature.bytes().to_vec(),
        prepared_input: input.encode().unwrap(),
    }
}
fn accepted_id(response: AcceptWorkResponse) -> Digest {
    let accept_work_response::Outcome::Accepted(accepted) = response.outcome.unwrap() else {
        panic!("refused")
    };
    Digest::from_bytes(accepted.work_id.try_into().unwrap())
}
fn refusal(response: AcceptWorkResponse) -> GrantRefusalCode {
    let accept_work_response::Outcome::Refused(refused) = response.outcome.unwrap() else {
        panic!("accepted")
    };
    GrantRefusalCode::try_from(refused.grant.unwrap().code).unwrap()
}
fn service(store: GrantStore, backend: Backend) -> GrantService {
    GrantService::new(
        store,
        Arc::new(principal(2).1),
        backend,
        vec![],
        Arc::new(|| UnixMillis(1_000)),
    )
    .unwrap()
}

#[tokio::test]
async fn grant_rpc_streams_before_terminal_reserves_once_and_survives_revision() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        use hellas_rpc::services::work::{WorkClientImpl, WorkServer};
        let dir = tempfile::tempdir().unwrap();
        let store = setup(dir.path());
        let first = request(&store, 1);
        let second = request(&store, 2);
        let a = GrantJobAuthorizationV1::decode(&first.authorization).unwrap();
        let backend = Backend::new();
        let service = service(store, backend.clone());
        let (client, server) = transport::transport_pair_with_context(context(), context());
        let serving = {
            let service = service.clone();
            tokio::spawn(async move {
                let handler = Arc::new(WorkServer(service));
                while let Ok(Some(inbound)) = server.accept().await {
                    let handler = handler.clone();
                    tokio::spawn(async move {
                        let _ =
                            Dispatcher::<MuxTransport>::dispatch(handler.as_ref(), inbound).await;
                    });
                }
            })
        };
        let rpc = WorkClientImpl::new(client.clone());
        let locator = StandingLocator {
            provider: principal(2).0.bundle().content_id(),
            grant: a.grant_id,
            client: principal(1).0.id(),
            generation: 0,
        };
        let response = rpc
            .get_standing(GetStandingRequest {
                route: Some(WorkRoute::grant(a.channel_id)),
                locator: locator.encode().to_vec(),
                client_signature: principal(1)
                    .1
                    .sign_digest(locator.digest(network(), &[7; 32]))
                    .unwrap()
                    .bytes()
                    .to_vec(),
            })
            .await
            .unwrap();
        assert!(matches!(
            response.outcome,
            Some(get_standing_response::Outcome::Standing(_))
        ));
        let id = accepted_id(rpc.accept_work(first.clone()).await.unwrap());
        backend.started.notified().await;
        assert_eq!(accepted_id(rpc.accept_work(first).await.unwrap()), id);
        assert_eq!(
            refusal(rpc.accept_work(second).await.unwrap()),
            GrantRefusalCode::QueueCapacity
        );
        let mut stream = rpc
            .stream_result(DeliverResultRequest {
                route: Some(WorkRoute::grant(a.channel_id)),
                work_id: id.as_bytes().to_vec(),
                client_signature: principal(1)
                    .1
                    .sign_digest(bound_delivery_request_digest(
                        network(),
                        a.channel_id.0,
                        id,
                        &[7; 32],
                    ))
                    .unwrap()
                    .bytes()
                    .to_vec(),
            })
            .await
            .unwrap();
        assert!(matches!(
            stream.next().await.unwrap().unwrap().outcome,
            Some(work_stream_event::Outcome::Prefix(_))
        ));
        service
            .administer(|store, now| {
                let mut def = store.state().grant(a.grant_id).unwrap().clone();
                def.revision.0 += 1;
                def.state = GrantState::Paused;
                store.define(def, now)
            })
            .unwrap();
        backend.finish.notify_one();
        assert!(matches!(
            stream.next().await.unwrap().unwrap().outcome,
            Some(work_stream_event::Outcome::Terminal(_))
        ));
        assert!(stream.next().await.is_none());
        stream.finish().unwrap();
        service.drain().await.unwrap();
        assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
        service
            .administer(|store, _| {
                assert_eq!(
                    store
                        .state()
                        .ledger()
                        .node(BudgetNode::Grant(a.grant_id))
                        .unwrap()
                        .counter(Meter::Requests, Window::Total)
                        .used,
                    1
                );
                store.rotate()
            })
            .unwrap();
        for file in std::fs::read_dir(dir.path()).unwrap() {
            let bytes = std::fs::read(file.unwrap().path()).unwrap();
            for secret in [
                b"private-grant-result".as_slice(),
                b"never-journal-this-body",
            ] {
                assert!(!bytes.windows(secret.len()).any(|window| window == secret));
            }
        }
        serving.abort();
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn revoked_queued_grant_never_dispatches_and_wrong_peer_never_reserves() {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        let dir = tempfile::tempdir().unwrap();
        let store = setup(dir.path());
        let request = request(&store, 1);
        let backend = Backend {
            queued: Some(Arc::new(Notify::new())),
            ..Backend::new()
        };
        let service = service(store, backend.clone());
        let wrong = TransportContext {
            peer: Some(PeerIdentity([4; 32])),
            ..context()
        };
        assert_eq!(
            refusal(service.accept(&request, &wrong)),
            GrantRefusalCode::WrongTransport
        );
        accepted_id(service.accept(&request, &context()));
        service
            .administer(|store, now| {
                let mut def = store.state().grant(GrantId([1; 16])).unwrap().clone();
                def.revision.0 += 1;
                def.state = GrantState::Revoked;
                store.define(def, now)
            })
            .unwrap();
        backend.queued.as_ref().unwrap().notify_one();
        service.drain().await.unwrap();
        assert_eq!(backend.calls.load(Ordering::SeqCst), 0);
        assert_eq!(backend.slots.available_permits(), 1);
        service
            .administer(|store, _| {
                assert_eq!(
                    store
                        .state()
                        .ledger()
                        .node(BudgetNode::Machine)
                        .unwrap()
                        .counter(Meter::Requests, Window::Total)
                        .used,
                    0
                );
                Ok(())
            })
            .unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn grant_refusals_preserve_the_typed_reason_without_spending_allowance() {
    use GrantRefusalCode as C;
    use hellas_rpc::{
        http_fetch::{HttpFetchRequest, HttpTls, HttpTrustRoots},
        protocol::{
            work_fetch::PreparedPaidFetchInputV1,
            work_grant::resource::{AccountingProfile, HttpsResource},
            work_profile::{PreparedWorkInput, WorkPolicy},
        },
    };
    for (case, expected) in [
        ("stranger", C::Unauthorized),
        ("forwarded_offer", C::WrongTransport),
        ("wrong_transport", C::WrongTransport),
        ("wrong_producer", C::Unauthorized),
        ("stale_revision", C::StaleRevision),
        ("stale_generation", C::StaleGeneration),
        ("out_of_scope", C::OutOfScope),
        ("origin", C::Origin),
        ("path", C::PathMethod),
        ("tls_roots", C::Tls),
        ("credential", C::Credential),
        ("paused", C::Paused),
        ("revoked", C::Revoked),
        ("expired", C::Expired),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut store = setup(dir.path());
        let grant = GrantId([1; 16]);
        let mut def = store.state().grant(grant).unwrap().clone();
        def.revision = Revision(2);
        if let WorkPolicy::Fetch { policy, .. } = &mut def.policies[0].work {
            policy.allowed_environment = FetchEnvironment::Http.manifest_id();
        }
        let resource = HttpsResource {
            origin: "https://glm.test".into(),
            paths: vec!["/v1/chat/completions".into()],
            methods: vec!["POST".into()],
            credential: None,
            tls: HttpTls {
                roots: HttpTrustRoots::WebPki,
                spki_sha256: vec![],
            },
            accounting: AccountingProfile::OpenaiChat,
            max_output_tokens: 8,
            max_response_bytes: 4096,
        };
        def.policies[0].https = Some(resource.clone());
        match case {
            "paused" => def.state = GrantState::Paused,
            "revoked" => def.state = GrantState::Revoked,
            "expired" => def.expires = Some(UnixMillis(999)),
            _ => {}
        }
        store.define(def.clone(), UnixMillis(1000)).unwrap();
        let (mut auth, _, mut input) = proposal(&store, 1);
        if case == "stale_revision" {
            def.revision = Revision(3);
            store.define(def, UnixMillis(1000)).unwrap();
        } else if case == "stale_generation" {
            store.bump_generation(grant, UnixMillis(1000)).unwrap();
        }
        let mut ctx = context();
        let mut signer = principal(1).1;
        match case {
            "stranger" => auth.channel_id = ChannelId(Digest::hash(b"unknown-channel")),
            "forwarded_offer" => {
                ctx.peer = Some(PeerIdentity([3; 32]));
                signer = principal(3).1;
            }
            "wrong_transport" => ctx.peer = Some(PeerIdentity([3; 32])),
            "wrong_producer" => signer = principal(3).1,
            "out_of_scope" => auth.work_policy_digest = Digest::hash(b"ungranted-policy"),
            "origin" | "path" | "tls_roots" | "credential" => {
                let mut http = HttpFetchRequest {
                    url: "https://glm.test/v1/chat/completions".into(),
                    method: "POST".into(),
                    headers: vec![],
                    body_base64: "eyJtYXhfdG9rZW5zIjo4fQ==".into(),
                    tls: resource.tls,
                    credential: None,
                    max_response_bytes: 4096,
                };
                match case {
                    "origin" => http.url = "https://other.test/v1/chat/completions".into(),
                    "path" => http.url = "https://glm.test/v1/other".into(),
                    // Template comparison precedes certificate installation.
                    "tls_roots" => {
                        http.tls.roots = HttpTrustRoots::Certificates {
                            der_base64: vec!["AQ==".into()],
                        }
                    }
                    "credential" => http.credential = Some("other-account".into()),
                    _ => unreachable!(),
                }
                let events = hellas_rpc::fetch::build_input_events_with_retention(
                    "openai",
                    "responses",
                    &serde_json::to_vec(&http).unwrap(),
                    FetchEnvironment::Http.manifest_id(),
                    Assurance::ProducerSigned,
                    &signer,
                    Retention::Ephemeral,
                )
                .unwrap();
                input = PreparedWorkInput::from(
                    PreparedPaidFetchInputV1::new(&events, &FetchEnvironment::Http.manifest())
                        .unwrap(),
                );
                auth.prepared_input_digest =
                    input.bound_digest(network(), auth.channel_id.0).unwrap();
                auth.request_commitment =
                    RequestCommitment::from_digest(input.input_commitment().unwrap().digest());
            }
            _ => {}
        }
        let request = AcceptWorkRequest {
            route: Some(WorkRoute::grant(auth.channel_id)),
            authorization: auth.encode(),
            client_signature: signer
                .sign_digest(grant_work_id(network(), &auth))
                .unwrap()
                .bytes()
                .to_vec(),
            prepared_input: input.encode().unwrap(),
        };
        let backend = Backend::new();
        let service = service(store, backend.clone());
        let response = service.accept(&request, &ctx);
        if case == "stale_revision" {
            let Some(accept_work_response::Outcome::Refused(ref refused)) = response.outcome else {
                panic!("{case}: accepted")
            };
            assert_eq!(refused.grant.as_ref().unwrap().current_revision, 3);
        }
        assert_eq!(refusal(response), expected, "{case}");
        assert_eq!(backend.calls.load(Ordering::SeqCst), 0, "{case}");
        assert_eq!(backend.slots.available_permits(), 1, "{case}");
        service
            .administer(|store, _| {
                for node in [BudgetNode::Machine, BudgetNode::Grant(grant)] {
                    assert_eq!(
                        store
                            .state()
                            .ledger()
                            .node(node)
                            .unwrap()
                            .counter(Meter::Requests, Window::Total)
                            .used,
                        0,
                        "{case}"
                    );
                    assert_eq!(
                        store.state().ledger().reserved(node, Meter::Requests),
                        0,
                        "{case}"
                    );
                }
                let channel = store.state().channel_id(grant).unwrap();
                assert_eq!(
                    store
                        .state()
                        .channel(channel)
                        .unwrap()
                        .job_book()
                        .proposal_nonce_high_water(),
                    0,
                    "{case}"
                );
                Ok(())
            })
            .unwrap();
        service.drain().await.unwrap();
    }
}

#[tokio::test]
async fn recovered_delivery_returns_durable_status_and_signed_metadata_without_reexecution() {
    use hellas_rpc::protocol::work_profile::{PreparedWorkInput, WorkContext};
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
        let mut store = setup(dir.path());
        let (a, sig, input) = proposal(&store, 1);
        let work = grant_work_id(network(), &a);
        store
            .accept(a, sig, &input, &principal(2).1, UnixMillis(1000))
            .unwrap();
        if step != 0 {
            store
                .dispatch(a.channel_id, work, UnixMillis(1001))
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
                        client: principal(1).0.producer(),
                        provider: principal(2).0.producer(),
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
                .unwrap();
        }
        drop(store);
        let store = GrantStore::open(
            dir.path(),
            network(),
            principal(2).0.bundle().clone(),
            UnixMillis(1003),
        )
        .unwrap();
        let backend = Backend::new();
        let service = service(store, backend.clone());
        let delivery = DeliverResultRequest {
            route: Some(WorkRoute::grant(a.channel_id)),
            work_id: work.as_bytes().to_vec(),
            client_signature: principal(1)
                .1
                .sign_digest(bound_delivery_request_digest(
                    network(),
                    a.channel_id.0,
                    work,
                    &[7; 32],
                ))
                .unwrap()
                .bytes()
                .to_vec(),
        };
        let mut forged = delivery.clone();
        forged.client_signature[0] ^= 1;
        let mut stream = service.stream(forged, context());
        let Some(work_stream_event::Outcome::Refused(refused)) =
            stream.next().await.unwrap().unwrap().outcome
        else {
            panic!("forged proof admitted")
        };
        assert_eq!(
            GrantRefusalCode::try_from(refused.grant.as_ref().unwrap().code).unwrap(),
            GrantRefusalCode::Unauthorized
        );
        assert!(refused.grant.unwrap().terminal.is_none());
        let mut stream = service.stream(delivery, context());
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
        service.drain().await.unwrap();
    }
}

#[tokio::test]
async fn verified_usage_survives_error_status_and_late_settlement_without_faulting_the_route() {
    use hellas_rpc::protocol::{work_grant::resource::*, work_profile::WorkPolicy};
    use std::sync::atomic::AtomicU64;
    for (status, late) in [(200, true), (500, false), (500, true)] {
        let dir = tempfile::tempdir().unwrap();
        let mut store = setup(dir.path());
        let id = GrantId([1; 16]);
        let mut def = store.state().grant(id).unwrap().clone();
        def.revision = Revision(2);
        if let WorkPolicy::Fetch { policy, .. } = &mut def.policies[0].work {
            policy.allowed_environment = FetchEnvironment::Http.manifest_id();
        }
        def.policies[0].https = Some(HttpsResource {
            origin: "https://glm.test".into(),
            paths: vec!["/v1/chat/completions".into()],
            methods: vec!["POST".into()],
            credential: None,
            tls: hellas_rpc::http_fetch::HttpTls {
                roots: hellas_rpc::http_fetch::HttpTrustRoots::WebPki,
                spki_sha256: vec![],
            },
            accounting: AccountingProfile::OpenaiChat,
            max_output_tokens: 8,
            max_response_bytes: 4096,
        });
        let resource = def.policies[0].resource_id().unwrap();
        store.define(def, UnixMillis(1000)).unwrap();
        let request = request(&store, 1);
        let a = GrantJobAuthorizationV1::decode(&request.authorization).unwrap();
        let backend = Backend {
            http_status: Some(status),
            ..Backend::new()
        };
        let clock = Arc::new(AtomicU64::new(1000));
        let source = clock.clone();
        let service = GrantService::new(
            store,
            Arc::new(principal(2).1),
            backend.clone(),
            vec![],
            Arc::new(move || UnixMillis(source.load(Ordering::SeqCst))),
        )
        .unwrap();
        let work = accepted_id(service.accept(&request, &context()));
        backend.started.notified().await;
        if late {
            clock.store(a.terminal_deadline_ms.0 + 1, Ordering::SeqCst);
        }
        backend.finish.notify_one();
        service.drain().await.unwrap();
        service
            .administer(|store, _| {
                assert_eq!(
                    store
                        .state()
                        .ledger()
                        .node(BudgetNode::Machine)
                        .unwrap()
                        .counter(Meter::OutputTokens, Window::Total)
                        .used,
                    2
                );
                let health = store.state().resource_health(resource).unwrap();
                assert!(!health.quarantined);
                assert_eq!(health.consecutive_faults, 0);
                assert_eq!(
                    store
                        .state()
                        .channel(a.channel_id)
                        .unwrap()
                        .job_book()
                        .terminal_by_id(work)
                        .unwrap()
                        .outcome
                        .outcome,
                    if late {
                        GrantOutcome::Failed
                    } else {
                        GrantOutcome::Finished
                    }
                );
                Ok(())
            })
            .unwrap();
        assert_eq!(backend.calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn user_removal_stops_open_result_delivery_without_dropping_running_accounting() {
    use hellas_rpc::protocol::work_grant::admin::{GrantCommand, UserCommand};
    let dir = tempfile::tempdir().unwrap();
    let store = setup(dir.path());
    let request = request(&store, 1);
    let auth = GrantJobAuthorizationV1::decode(&request.authorization).unwrap();
    let backend = Backend::new();
    let service = service(store, backend.clone());
    let id = accepted_id(service.accept(&request, &context()));
    backend.started.notified().await;
    let mut stream = service.stream(
        DeliverResultRequest {
            route: Some(WorkRoute::grant(auth.channel_id)),
            work_id: id.as_bytes().to_vec(),
            client_signature: principal(1)
                .1
                .sign_digest(bound_delivery_request_digest(
                    network(),
                    auth.channel_id.0,
                    id,
                    &[7; 32],
                ))
                .unwrap()
                .bytes()
                .to_vec(),
        },
        context(),
    );
    assert!(matches!(
        stream.next().await.unwrap().unwrap().outcome,
        Some(work_stream_event::Outcome::Prefix(_))
    ));
    service
        .control(
            GrantCommand::Users(UserCommand::Remove {
                id: principal(1).0.id(),
                expected_revision: Revision(1),
            }),
            &[],
            std::num::NonZeroU64::new(1).unwrap(),
        )
        .unwrap();
    let Some(work_stream_event::Outcome::Refused(refusal)) =
        stream.next().await.unwrap().unwrap().outcome
    else {
        panic!("revoked stream must refuse");
    };
    assert_eq!(
        refusal.grant.unwrap().code,
        GrantRefusalCode::Revoked as i32
    );
    assert!(stream.next().await.is_none());
    backend.finish.notify_one();
    tokio::time::timeout(std::time::Duration::from_secs(3), service.drain())
        .await
        .unwrap()
        .unwrap();
    service
        .administer(|store, _| {
            assert_eq!(store.state().ledger().active_count(BudgetNode::Machine), 0);
            assert_eq!(
                store
                    .state()
                    .ledger()
                    .node(BudgetNode::Grant(auth.grant_id))
                    .unwrap()
                    .counter(Meter::Requests, Window::Total)
                    .used,
                1
            );
            Ok(())
        })
        .unwrap();
}
