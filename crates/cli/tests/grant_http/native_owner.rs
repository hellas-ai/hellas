//! CPU fixture for the real owner gateway and signed native Work protocol.
//! The backend emits a deterministic signed token; it does not claim GPU coverage.
use super::*;
use hellas_rpc::{
    evaluate::{
        EvaluateOutputTranscriptBuilder, EvaluateStopReason, EvaluateTerminal, EvaluateUsage,
        input_commitment,
    },
    protocol::{
        artifacts::{BoundTermId, Canonical as _, TextArtifact, TextPolicy},
        work::{EvaluatePolicyV2, generation_policy_digest, identity_source_digest},
        work_grant::{budget::*, grant_network, records::*},
    },
    services::work::{Work, WorkServer},
    *,
};
use hellas_wire::{Dispatcher, ServiceMarker, StreamTransport, iroh::IrohTransport};
use hellas_work::{
    grant_service::{GrantService, wall_clock},
    work::{
        BackendFault, PaidProgress, PreparedEvaluateInput, WorkBackend,
        admission::{CapacityDomain, WorkPermit},
    },
    work_store::grant::GrantStore,
};

struct Native {
    signer: Arc<ProducerSigningKey>,
    calls: Arc<AtomicUsize>,
    slots: Arc<Semaphore>,
}
impl WorkBackend for Native {
    fn try_admit(&self, domain: CapacityDomain) -> Result<WorkPermit, BackendFault> {
        assert_eq!(domain, CapacityDomain::Gpu);
        Ok(WorkPermit::new(
            domain,
            self.slots
                .clone()
                .try_acquire_owned()
                .map_err(|_| BackendFault::new("full"))?,
        ))
    }
    async fn evaluate_stream(
        &self,
        input: PreparedEvaluateInput,
        progress: PaidProgress,
    ) -> Result<Vec<OutputEventEnvelope>, BackendFault> {
        let (parts, admission) = input.into_parts_and_admission();
        let _running = admission.dispatch()?;
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut output = EvaluateOutputTranscriptBuilder::new(
            input_commitment(&parts.evaluate_request),
            parts.evaluate_request.assurance,
            &self.signer,
        );
        progress(output.push_token_delta(vec![0]).unwrap())?;
        let usage = EvaluateUsage {
            input_units: parts.prompt_tokens.as_slice().len() as u64,
            output_units: 1,
        };
        Ok(output
            .finish(EvaluateTerminal {
                final_position: 1,
                stop_reason: EvaluateStopReason::MAX_OUTPUT,
                matched_stop_token_id: None,
                text_artifact: Digest::hash(b"native-owner-fixture"),
                usage,
                billable_units: usage.billable_units().unwrap(),
            })
            .unwrap())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn machine_owner_evaluate_discovers_generation_and_settles_exact_tokens() {
    use hellas_cloud::{
        config::{Credentials, Enrollment},
        wire::{self, Response},
    };
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    hellas_private::restrict_directory(root).unwrap();
    let owner = Cli::new(root, "owner");
    owner.run(&["--software-root", "identity", "init"]).await;
    let export = owner.output(&["contact", "export"]).await;
    assert!(export.status.success());
    let owner_principal = Principal::decode(&export.stdout).unwrap();
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let admin_address = udp.local_addr().unwrap();
    drop(udp);
    let bootstrap = root.join("bootstrap.json");
    owner
        .run(&[
            "machines",
            "prepare",
            "native",
            "--bootstrap-file",
            string(&bootstrap),
            "--admin-addr",
            &admin_address.to_string(),
        ])
        .await;
    let settings: std::collections::BTreeMap<String, String> =
        hellas_cloud::config::read_json(&bootstrap).unwrap();
    let credentials = Credentials {
        admin_secret: settings["HELLAS_REMOTE_KEY"].clone(),
        token: settings["HELLAS_REMOTE_TOKEN"].clone(),
        owner: Some(settings["HELLAS_REMOTE_OWNER"].clone()),
        owner_enrollment: Some(settings["HELLAS_REMOTE_OWNER_ENROLLMENT"].clone()),
    };
    let transport = iroh::SecretKey::generate();
    let signer = Arc::new(ProducerSigningKey::from_secret_bytes([42; 32]).unwrap());
    let statement = ProviderGenesisStatement {
        root_kind: RootKind::Software,
        root_public_key: signer.public_key(),
        producer_public_key: signer.public_key(),
        transport_public_key: PublicKey::Ed25519(*transport.public().as_bytes()),
        installation_nonce: [42; 32],
        platform_credential: PlatformCredential::Absent,
    };
    let proof = signer
        .sign_digest(Digest::hash(&statement.canonical_bytes()))
        .unwrap();
    let provider = Principal::verify(ProviderEnrollmentBundle {
        genesis: SignedProviderGenesis {
            statement,
            root_proof: RootProof::Software(proof),
        },
        platform: PlatformEnrollment::Absent,
    })
    .unwrap();
    let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(transport)
        .alpns(vec![Work::ALPN.as_bytes().to_vec()])
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap();
    let address = *endpoint
        .addr()
        .ip_addrs()
        .find(|addr| addr.is_ipv4())
        .unwrap();
    let admin = iroh::Endpoint::builder(iroh::endpoint::presets::Minimal)
        .secret_key(credentials.secret_key().unwrap())
        .alpns(vec![wire::ALPN.to_vec()])
        .bind_addr(admin_address)
        .unwrap()
        .bind()
        .await
        .unwrap();
    let enrollment = Enrollment {
        node_id: endpoint.id().to_string(),
        enrollment_id: provider.id().0.to_string(),
        bundle: Some(hex::encode(provider.bundle().canonical_bytes())),
    };
    let mut servers = tokio::task::JoinSet::new();
    let admin_server = admin.clone();
    servers.spawn(async move {
        while let Some(incoming) = admin_server.accept().await {
            let connection = incoming.await.unwrap();
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            let request: wire::Request =
                serde_json::from_slice(&recv.read_to_end(wire::MAX_MESSAGE).await.unwrap())
                    .unwrap();
            assert_eq!(Some(connection.remote_id().to_string()), credentials.owner);
            assert_eq!(request.token, credentials.token);
            assert!(matches!(request.operation, wire::Operation::Status));
            send.write_all(
                &serde_json::to_vec(&Response::Status {
                    enrollment: enrollment.clone(),
                    owner: credentials.owner.clone(),
                    running: true,
                })
                .unwrap(),
            )
            .await
            .unwrap();
            send.finish().unwrap();
            connection.closed().await;
        }
    });
    let environment = CausalLmEnvironment::new(
        ContentRef::new(ContentId::from_bytes([8; 32]), 1024),
        "model",
        vec![],
        vec![],
        vec![],
        256,
        1024,
        CausalLmGenerationSchedule {
            fixed_capacity: 1024,
            prefill_chunk_tokens: 64,
        },
    )
    .unwrap();
    let manifest = environment.manifest().content_id();
    let policy = GrantPolicy {
        name: "native".into(),
        https: None,
        work: EvaluatePolicyV2 {
            allowed_environment: manifest,
            generation_policy_digest: generation_policy_digest(
                &TextPolicy::from_u32_stop_tokens(1, vec![]).canonical_bytes(),
            )
            .unwrap(),
            identity_source_digest: identity_source_digest(
                &TextArtifact::identity(BoundTermId::from_digest(manifest.digest()))
                    .canonical_bytes(),
            )
            .unwrap(),
            max_prompt_tokens: 128,
            max_new_tokens: 1,
            max_stop_token_ids: 0,
            max_spool_bytes: 1 << 20,
            max_encoded_result_frame: 1 << 20,
            max_encoded_prepared_input: 1 << 20,
        }
        .into(),
    };
    let mut store = GrantStore::open(
        &root.join("provider"),
        grant_network(),
        provider.bundle().clone(),
        wall_clock(),
    )
    .unwrap();
    store
        .configure_machine(
            vec![Limit {
                meter: Meter::OutputTokens,
                window: Window::Total,
                amount: 2,
            }],
            1,
            wall_clock(),
        )
        .unwrap();
    let owner_id = store
        .initialize_owner(
            owner_principal,
            vec![policy],
            std::num::NonZeroU64::new(10_000).unwrap(),
            wall_clock(),
        )
        .unwrap();
    store.bump_generation(owner_id, wall_clock()).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let service = GrantService::new(
        store,
        signer.clone(),
        Native {
            signer: signer.clone(),
            calls: calls.clone(),
            slots: Arc::new(Semaphore::new(1)),
        },
        vec![address.to_string()],
        Arc::new(wall_clock),
    )
    .unwrap();
    let service_copy = service.clone();
    let work_server = endpoint.clone();
    let provider_bundle = provider.bundle().clone();
    let open_signer = signer.clone();
    servers.spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                Some(_) = connections.join_next(), if !connections.is_empty() => {},
                incoming = work_server.accept() => {
                    let Some(incoming) = incoming else { break; };
                    let service = service_copy.clone();
                    let bundle = provider_bundle.clone();
                    let signer = open_signer.clone();
                    connections.spawn(async move {
                        let connection = incoming.await.unwrap();
                        let transport = IrohTransport::new(connection);
                        let server = hellas_rpc::open::OpenDispatcher::<_, _, hellas_rpc::services::work::Open>::new(
                            WorkServer(service), SoftwareOpen { bundle, signer },
                        );
                        while let Ok(Some(inbound)) = transport.accept().await {
                            Dispatcher::<IrohTransport>::dispatch(&server,inbound).await.unwrap();
                        }
                    });
                }
            }
        }
    });
    let environment_file = root.join("model.environment");
    std::fs::write(&environment_file, environment.canonical_bytes()).unwrap();
    let tokenizer = root.join("tokenizer.json");
    std::fs::write(&tokenizer,br#"{"version":"1.0","truncation":null,"padding":null,"added_tokens":[],"normalizer":null,"pre_tokenizer":{"type":"Whitespace"},"post_processor":null,"decoder":null,"model":{"type":"WordLevel","vocab":{"hello":0,"<unk>":1},"unk_token":"<unk>"}}"#).unwrap();
    let bearer = root.join("bearer");
    hellas_private::write_atomically(&bearer, ".token", "11".repeat(32).as_bytes()).unwrap();
    let mut gateway = owner.spawn(
        &[
            "gateway",
            "--machine",
            "native",
            "--address",
            &address.to_string(),
            "--environment",
            string(&environment_file),
            "--tokenizer",
            string(&tokenizer),
            "--model",
            "fixture",
            "--port",
            "0",
            "--bearer-token-file",
            string(&bearer),
            "--archive-dir",
            string(&root.join("archive")),
            "--zdr",
        ],
        "native-gateway.log",
    );
    let address = gateway.wait_for("gateway listening on ").await;
    let url = format!("http://{address}/v1/completions");
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    let response = post(
        &http,
        &url,
        json!({"model":"fixture","prompt":"hello","max_tokens":1}),
    )
    .await;
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["choices"][0]["text"], "hello");
    assert_eq!(body["usage"]["prompt_tokens"], 1);
    assert_eq!(body["usage"]["completion_tokens"], 1);
    let response = post(
        &http,
        &url,
        json!({"model":"fixture","prompt":"hello","max_tokens":1,"stream":true}),
    )
    .await;
    assert_eq!(response.status(), 200);
    assert!(response.text().await.unwrap().contains("hello"));
    assert_eq!(
        post(
            &http,
            &url,
            json!({"model":"fixture","prompt":"hello","max_tokens":1})
        )
        .await
        .status(),
        429
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    service
        .administer(|store, _| {
            let ledger = store.state().ledger().node(BudgetNode::Machine).unwrap();
            assert_eq!(ledger.counter(Meter::InputTokens, Window::Total).used, 2);
            assert_eq!(ledger.counter(Meter::OutputTokens, Window::Total).used, 2);
            Ok(())
        })
        .unwrap();
    gateway.stop().await;
    service.drain().await.unwrap();
    servers.abort_all();
    while servers.join_next().await.is_some() {}
    admin.close().await;
    endpoint.close().await;
    assert_no_chain(root);
}

struct SoftwareOpen {
    bundle: ProviderEnrollmentBundle,
    signer: Arc<ProducerSigningKey>,
}
impl hellas_rpc::open::OpenHandler for SoftwareOpen {
    async fn open(
        &self,
        request: hellas_rpc::pb::execute::OpenRequest,
        context: hellas_wire::TransportContext,
        alpn: &'static [u8],
    ) -> Result<hellas_rpc::pb::execute::OpenResponse, hellas_wire::WireStatus> {
        let nonce: [u8; 32] = request.nonce.try_into().unwrap();
        let binding = hellas_rpc::open_proof_binding(
            &context.open_exporter.unwrap(),
            &nonce,
            &self.signer.public_key(),
            self.bundle.content_id(),
            alpn,
        );
        Ok(hellas_rpc::pb::execute::OpenResponse {
            provider_genesis: self.bundle.canonical_bytes(),
            proof: Some(
                hellas_rpc::pb::execute::open_response::Proof::ProducerSignature(
                    hellas_rpc::signature_wire::signature_to_pb(
                        &self.signer.sign_digest(binding).unwrap(),
                    ),
                ),
            ),
        })
    }
}
