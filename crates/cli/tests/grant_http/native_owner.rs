//! CPU fixture for the real owner gateway and signed native Work protocol.
//! The backend emits a deterministic signed token; it does not claim GPU coverage.
use super::*;
use hellas_auth::{Digest, ProducerSigningKey};
use hellas_rpc::{
    evaluate::{
        EvaluateOutputTranscriptBuilder, EvaluateStopReason, EvaluateTerminal, EvaluateUsage,
        input_commitment,
    },
    protocol::artifacts::{BoundTermId, Canonical as _, TextArtifact, TextPolicy},
    services::work::Work,
    *,
};
use hellas_wire::{Dispatcher, ServiceMarker, StreamTransport, iroh::IrohTransport};
use hellas_work::model::{
    grant::{budget::*, grant_network, records::*},
    work::{EvaluatePolicyV2, generation_policy_digest, identity_source_digest},
};
use hellas_work::{
    grant_service::GrantService,
    work::{
        BackendFault, PaidProgress, WorkBackend,
        admission::{CapacityDomain, WorkPermit},
    },
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
            self.slots.clone().try_acquire_owned().map_err(|_| {
                BackendFault::from(hellas_work::work::admission::AdmissionError::Capacity)
            })?,
        ))
    }
    async fn execute_stream(
        &self,
        prepared: hellas_work::work::PreparedWorkInput,
        progress: PaidProgress,
    ) -> Result<Vec<hellas_rpc::OutputEventEnvelope>, hellas_work::work::BackendFault> {
        let hellas_work::work::PreparedWorkInput::Evaluate(input) = prepared else {
            return Err(hellas_work::work::admission::AdmissionError::Unsupported(
                hellas_work::work::admission::CapacityDomain::Fetch,
            )
            .into());
        };
        let input = *input;
        let (parts, admission) = input.into_parts_and_admission();
        let _running = admission
            .reserve(hellas_work::work::admission::CapacityDomain::Gpu, async {
                self.try_admit(hellas_work::work::admission::CapacityDomain::Gpu)
            })
            .await?
            .dispatch()
            .await?;
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

struct NativeOwner {
    _root: tempfile::TempDir,
    owner: Cli,
    environment_file: PathBuf,
    tokenizer: PathBuf,
    gateway: Process,
    http: reqwest::Client,
    url: String,
    calls: Arc<AtomicUsize>,
    service: GrantService,
    servers: tokio::task::JoinSet<()>,
    endpoint: iroh::Endpoint,
}
impl NativeOwner {
    async fn start() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        hellas_private::restrict_directory(root).unwrap();
        let owner = Cli::new(root, "owner", AGENT_PASSKEY);
        owner.run(&["--software-root", "identity", "init"]).await;
        let owner_principal = owner.principal();
        let owner_holder = owner.holder().await;
        let transport = iroh::SecretKey::generate();
        let signer = Arc::new(ProducerSigningKey::from_secret_bytes([42; 32]).unwrap());
        let provider = hellas_work::test_support::enrollment(
            &ProducerSigningKey::from_secret_bytes([41; 32]).unwrap(),
            &signer,
            *transport.public().as_bytes(),
            [42; 32],
        );
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
        let mut servers = tokio::task::JoinSet::new();
        let (environment, policy, environment_file, tokenizer) =
            native_model(root, "native", 128, 1);
        let (store, secret) = common_node::bootstrap_node_with_credential(
            &root.join("provider"),
            grant_network(),
            Some(provider.clone()),
            hellas_auth::authority::UnixMillis::now().unwrap_or_default(),
        )
        .await
        .unwrap();
        let owner_id = hellas_work::model::grant::owner_grant_id(
            grant_network(),
            provider.content_id(),
            owner_principal,
        );
        let mut definition =
            common_node::allowance(owner_id, owner_principal, vec![policy.clone()]);
        definition.max_job_millis = std::num::NonZeroU64::new(10_000).unwrap();
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
            Arc::new(|| hellas_auth::authority::UnixMillis::now().unwrap_or_default()),
        )
        .unwrap();
        let work_admin = common_node::WorkAdmin::new(service.clone(), &secret, vec![policy]).await;
        work_admin
            .capacity(
                1,
                vec![Limit {
                    meter: Meter::OutputTokens,
                    window: Window::Total,
                    amount: 2,
                }],
            )
            .await;
        work_admin
            .budgets(common_node::POOL, owner_principal, vec![], 256)
            .await;
        work_admin.create(definition).await;
        // The owner's gateway signs its jobs with its own node key.
        let credential = execution_credential(
            &service.node(),
            &secret,
            owner_principal,
            owner_id,
            owner_holder,
        )
        .await;
        let authority = hellas_work::test_support::session(&service.node(), &secret)
            .await
            .authority();
        let work_profile = work_profile(root, authority, &credential);
        work_admin
            .command(
                hellas_work::model::grant::admin::WorkControlCommand::NewGeneration {
                    id: owner_id,
                    expected_generation: 0,
                },
            )
            .await
            .unwrap();
        let service_copy = service.clone();
        let work_server = endpoint.clone();
        let provider_bundle = provider.clone();
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
                        let server = hellas_sdk::work_router::WorkRouter::grants(service).accept_iroh(
                            &transport, SoftwareOpen { bundle, signer },
                        ).await.unwrap();
                        while let Ok(Some(inbound)) = transport.accept().await {
                            Dispatcher::<IrohTransport>::dispatch(&server,inbound).await.unwrap();
                        }
                    });
                }
            }
        }
    });
        let WorkControlReply::Offers(offers) = work_admin
            .command(WorkControlCommand::Offers { id: Some(owner_id) })
            .await
            .unwrap()
        else {
            panic!("offer reply required")
        };
        let [offer] = offers.as_slice() else {
            panic!("one signed offer required")
        };
        let offer_file = root.join("native.offer");
        std::fs::write(&offer_file, offer.encode().unwrap()).unwrap();
        owner
            .run(&["offer", "import", string(&offer_file), "--name", "native"])
            .await;
        let (gateway_profile, gateway_token) = gateway_profile(root).await;
        let trust_root = approve(
            root,
            "native",
            provider.content_id(),
            vec![environment.manifest().content_id()],
        );
        let mut gateway = owner.spawn(
            &[
                "gateway",
                "--offer",
                "native",
                "--trust-store",
                string(&trust_root),
                "--trust-policy",
                "native",
                "--work-profile",
                string(&work_profile),
                "--environment",
                string(&environment_file),
                "--tokenizer",
                string(&tokenizer),
                "--model",
                "fixture",
                "--port",
                "0",
                "--gateway-profile",
                string(&gateway_profile),
                "--archive-dir",
                string(&root.join("archive")),
                "--zdr",
            ],
            "native-gateway.log",
        );
        let address = gateway.wait_for("gateway listening on ").await;
        let url = format!("http://{address}/v1/completions");
        let http = gateway_client(&gateway_token);
        Self {
            _root: directory,
            owner,
            environment_file,
            tokenizer,
            gateway,
            http,
            url,
            calls,
            service,
            servers,
            endpoint,
        }
    }
    async fn shutdown(mut self) {
        self.gateway.stop().await;
        self.service.drain().await.unwrap();
        self.servers.shutdown().await;
        self.endpoint.close().await;
    }
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn owner_offer_gateway_projects_signed_native_work() {
    let fixture = NativeOwner::start().await;
    let before = fixture.calls.load(Ordering::SeqCst);
    let response = post(
        &fixture.http,
        &fixture.url,
        json!({"model":"fixture","prompt":"hello","max_tokens":1}),
    )
    .await;
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["choices"][0]["text"], "hello");
    assert_eq!(body["usage"]["prompt_tokens"], 1);
    assert_eq!(body["usage"]["completion_tokens"], 1);
    let stream = post(
        &fixture.http,
        &fixture.url,
        json!({"model":"fixture","prompt":"hello","max_tokens":1,"stream":true}),
    )
    .await;
    assert_eq!(stream.status(), reqwest::StatusCode::OK);
    assert!(stream.text().await.unwrap().contains("hello"));
    assert_eq!(fixture.calls.load(Ordering::SeqCst) - before, 2);
    fixture.shutdown().await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn token_native_paid_gateway_requires_producer_signed_assurance() {
    let fixture = NativeOwner::start().await;
    // The remote paid path has the same assurance requirement in both CLI builds.
    let refused = fixture
        .owner
        .output(&[
            "gateway",
            "--paid-work-config",
            string(&fixture._root.path().join("absent-paid-pool.json")),
            "--assurance",
            "apple-app-attest",
            "--environment",
            string(&fixture.environment_file),
            "--tokenizer",
            string(&fixture.tokenizer),
        ])
        .await;
    assert!(!refused.status.success());
    assert!(
        String::from_utf8_lossy(&refused.stderr)
            .contains("token-native paid work uses producer-signed assurance")
    );
    fixture.shutdown().await;
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

/// Deterministic one-word model files and the grant policy that admits them.
pub(super) fn native_model(
    root: &Path,
    name: &str,
    max_prompt_tokens: u32,
    max_new_tokens: u32,
) -> (CausalLmEnvironment, GrantPolicy, PathBuf, PathBuf) {
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
        resource: hellas_auth::authority::ResourceId(Digest::hash(b"test resource")),
        account: hellas_auth::authority::ResourceId(Digest::hash(b"test account")),
        revision: hellas_auth::authority::Revision(1),
        name: name.into(),
        https: None,
        pricing: hellas_work::model::grant::pricing::Pricing {
            revision: hellas_auth::authority::Revision(1),
            rates: None,
        },
        responses: None,
        work: EvaluatePolicyV2 {
            allowed_environment: manifest,
            generation_policy_digest: generation_policy_digest(
                &TextPolicy::from_u32_stop_tokens(max_new_tokens, vec![]).canonical_bytes(),
            )
            .unwrap(),
            identity_source_digest: identity_source_digest(
                &TextArtifact::identity(BoundTermId::from_digest(manifest.digest()))
                    .canonical_bytes(),
            )
            .unwrap(),
            max_prompt_tokens,
            max_new_tokens,
            max_stop_token_ids: 0,
            max_spool_bytes: 32 << 20,
            max_encoded_result_frame: 4 << 20,
            max_encoded_prepared_input: 4 << 20,
        }
        .into(),
    };
    let environment_file = root.join("model.environment");
    std::fs::write(&environment_file, environment.canonical_bytes()).unwrap();
    let tokenizer = root.join("tokenizer.json");
    std::fs::write(&tokenizer, br#"{"version":"1.0","truncation":null,"padding":null,"added_tokens":[],"normalizer":null,"pre_tokenizer":{"type":"Whitespace"},"post_processor":null,"decoder":null,"model":{"type":"WordLevel","vocab":{"hello":0,"<unk>":1},"unk_token":"<unk>"}}"#).unwrap();
    (environment, policy, environment_file, tokenizer)
}
