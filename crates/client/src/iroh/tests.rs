use super::*;
use crate::FetchOutcome;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use futures::stream::{self, BoxStream};
use hellas_rpc::pb::courtesy::{EvaluateGenesisStart, EvaluateStart};
use hellas_rpc::pb::execute::{RunTicketRequest, WorkEvent, WorkFinished, work_event};
use hellas_rpc::pb::fetch::FetchRequest;
use hellas_rpc::protocol::artifacts::{
    BoundTermId, InputAddressed, OutputAddressed, SourceRef, TextArtifact, TextExecution,
    TextPolicy, TokenIds,
};
use hellas_rpc::services::execute::{ExecuteHandler, ExecuteServer, RunTicket};
use hellas_rpc::services::fetch::{CreateTicket, FetchHandler, FetchServer};
use hellas_rpc::stream::{input_event_to_pb, output_event_to_pb};
use hellas_rpc::{
    Application, Digest, JobTerms, ProviderEnrollmentBundle, ProviderGenesisStatement,
    RequestCommitment, RootProof, SignedProviderGenesis, pb::execute::open_response,
    run_ticket::signature_to_pb,
};

use hellas_rpc::{call::WithTrailer, open::OpenDispatcher, open::OpenHandler};
use hellas_rpc::{fetch::build_input_events, serve::MethodDispatcher};
use hellas_wire::{Dispatcher, WireCode, WireStatus};
use iroh::{Endpoint, EndpointAddr, SecretKey, TransportAddr, endpoint::presets};
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature as P256Signature, SigningKey as P256SigningKey};
use serde::Serialize;
use serde_bytes::ByteBuf;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::sync::Mutex;

const ALPN: &[u8] = b"/hellas.courtesy.v1.Courtesy/2.0";
const ENROLLED_PEER: PeerIdentity = PeerIdentity([3; 32]);
const OTHER_PEER: PeerIdentity = PeerIdentity([7; 32]);

#[tokio::test]
async fn peer_bootstrap_timeout_cancels_a_silent_attempt() {
    let error = with_peer_timeout(
        Duration::ZERO,
        "silent fixture peer bootstrap timed out",
        std::future::pending::<ClientResult<()>>(),
    )
    .await
    .expect_err("a silent peer cannot park its caller");
    assert!(
        error
            .to_string()
            .contains("silent fixture peer bootstrap timed out")
    );
}

#[test]
fn discovery_feed_errors_consume_the_retry_budget() {
    let mut attempts = 0;
    assert!(!consume_discovery_attempt(&mut attempts, 2));
    assert_eq!(attempts, 1);
    assert!(consume_discovery_attempt(&mut attempts, 2));
    assert_eq!(attempts, 2);
}

#[tokio::test]
async fn terminal_outcome_timeout_bounds_a_withheld_wire_trailer() {
    let mut silent = stream::pending::<()>();
    let error = next_after_terminal(&mut silent, true, Duration::ZERO)
        .await
        .expect_err("a peer cannot withhold End forever after its terminal outcome");
    assert!(error.to_string().contains("withheld the wire trailer"));
}

fn signed_open_response(
    exporter: &[u8; 32],
    nonce: &[u8; 32],
) -> (ProviderTrustAnchor, OpenResponse) {
    let root = ProducerSigningKey::from_secret_bytes([1; 32]).unwrap();
    let producer = ProducerSigningKey::from_secret_bytes([2; 32]).unwrap();
    let statement = ProviderGenesisStatement {
        root_kind: RootKind::Software,
        root_public_key: root.public_key(),
        producer_public_key: producer.public_key(),
        transport_public_key: PublicKey::Ed25519(ENROLLED_PEER.0),
        platform_credential: PlatformCredential::Absent,
        installation_nonce: [4; 32],
    };
    let genesis = SignedProviderGenesis {
        root_proof: RootProof::Software(
            root.sign_digest(Digest::hash(&statement.canonical_bytes()))
                .unwrap(),
        ),
        statement,
    };
    let bundle = ProviderEnrollmentBundle {
        genesis,
        platform: PlatformEnrollment::Absent,
    };
    let provider_genesis = bundle.canonical_bytes();
    let expected_genesis = ContentId::hash(&provider_genesis);
    let binding = hellas_rpc::open_proof_binding(
        exporter,
        nonce,
        &bundle.genesis.statement.producer_public_key,
        expected_genesis,
        ALPN,
    );
    let signature = producer.sign_digest(binding).unwrap();
    (
        ProviderTrustAnchor {
            expected_genesis,
            required_assurance: Assurance::ProducerSigned,
            apple_app_attest: None,
        },
        OpenResponse {
            provider_genesis,
            proof: Some(open_response::Proof::ProducerSignature(signature_to_pb(
                &signature,
            ))),
        },
    )
}

fn valid_token_quote() -> (
    QuoteTokensRequest,
    QuoteResponse,
    ProviderTrustAnchor,
    PublicKey,
    ContentId,
    CausalLmEnvironment,
) {
    let (trust, open) = signed_open_response(&[8; 32], &[9; 32]);
    let enrollment =
        ProviderEnrollmentBundle::from_canonical_bytes(&open.provider_genesis).unwrap();
    let producer_key = enrollment.genesis.statement.producer_public_key;
    let runner = ProducerSigningKey::from_secret_bytes([5; 32]).unwrap();
    let environment = CausalLmEnvironment::new(
        hellas_rpc::ContentRef::new(ContentId::from_bytes([6; 32]), 1_024),
        "model",
        Vec::new(),
        Vec::new(),
        Vec::new(),
        16,
        16,
        hellas_rpc::CausalLmGenerationSchedule {
            fixed_capacity: 16,
            prefill_chunk_tokens: 16,
        },
    )
    .unwrap();
    let manifest = environment.manifest();
    let execution_environment = manifest.content_id();
    let request = QuoteTokensRequest {
        program_manifest: manifest.canonical_bytes(),
        prompt_token_ids: vec![1, 2, 3],
        max_new_tokens: Some(4),
        stop_token_ids: vec![9, 7, 9],
        start: Some(EvaluateStart {
            kind: Some(evaluate_start::Kind::Genesis(EvaluateGenesisStart {})),
        }),
        runner_public_key: Some(hellas_rpc::run_ticket::public_key_to_pb(
            &runner.public_key(),
        )),
        assurance: Assurance::ProducerSigned.to_byte().into(),
        retain: Some(true),
    };
    let identity = TextArtifact::identity(BoundTermId::from_digest(execution_environment.digest()));
    let prompt = TokenIds::from([1, 2, 3]);
    let policy = TextPolicy::from_u32_stop_tokens(4, [9, 7, 9]);
    let text_execution = TextExecution::new(
        SourceRef::output(identity.output_id()),
        prompt.output_id(),
        policy.output_id(),
    );
    let evaluate_request = EvaluateRequest {
        text_execution: text_execution.input_id().digest(),
        runner_public_key: runner.public_key(),
        execution_environment,
        nonce: [4; 32],
        assurance: Assurance::ProducerSigned,
        retain: true,
    };
    let terms = hellas_rpc::JobTerms {
        request: Evaluate::commit_request(&evaluate_request),
        provider_genesis: trust.expected_genesis,
        assurance: Assurance::ProducerSigned,
        amount: 1000,
        ttl_ms: 30_000,
    };
    let ticket = hellas_rpc::run_ticket::ticket_to_pb(terms, open.provider_genesis).unwrap();
    let response = QuoteResponse {
        ticket: Some(ticket),
        prompt_tokens: 3,
        evaluate_request: Some(hellas_rpc::pb::evaluate::EvaluateRequest {
            text_execution: evaluate_request.text_execution.as_bytes().to_vec(),
            runner_public_key: Some(hellas_rpc::run_ticket::public_key_to_pb(
                &evaluate_request.runner_public_key,
            )),
            execution_environment: evaluate_request.execution_environment.as_bytes().to_vec(),
            nonce: evaluate_request.nonce.to_vec(),
            assurance: evaluate_request.assurance.to_byte().into(),
            retain: Some(evaluate_request.retain),
        }),
    };
    (
        request,
        response,
        trust,
        producer_key,
        execution_environment,
        environment,
    )
}

#[test]
fn token_quote_binds_exact_environment_request_ticket_and_producer() {
    let (request, response, trust, producer_key, manifest_id, environment) = valid_token_quote();
    let validated = validate_evaluate_quote_response(
        &request,
        manifest_id,
        &environment,
        response,
        Some(trust.expected_genesis),
    )
    .unwrap();
    assert_eq!(validated.producer_key, producer_key);
}

#[test]
fn token_quote_rejects_a_provider_substituting_the_evaluate_manifest() {
    let (request, mut response, trust, _, manifest_id, environment) = valid_token_quote();
    response
        .evaluate_request
        .as_mut()
        .unwrap()
        .execution_environment = vec![42; 32];
    let error = validate_evaluate_quote_response(
        &request,
        manifest_id,
        &environment,
        response,
        Some(trust.expected_genesis),
    )
    .unwrap_err();
    assert!(error.to_string().contains("does not match the token quote"));
}

#[test]
fn token_quote_rejects_manifest_bytes_outside_the_caller_pin() {
    let (request, response, trust, _, _, environment) = valid_token_quote();
    let error = validate_evaluate_quote_response(
        &request,
        ContentId::from_bytes([42; 32]),
        &environment,
        response,
        Some(trust.expected_genesis),
    )
    .unwrap_err();
    assert!(error.to_string().contains("does not match caller pin"));
}

#[test]
fn token_quote_rejects_noncanonical_or_unbound_application_bodies() {
    let (request, response, trust, _, manifest_id, environment) = valid_token_quote();

    let mut noncanonical = request.clone();
    noncanonical.program_manifest.push(0);
    let error = validate_evaluate_quote_response(
        &noncanonical,
        manifest_id,
        &environment,
        response.clone(),
        Some(trust.expected_genesis),
    )
    .unwrap_err();
    assert!(error.to_string().contains("canonical program manifest"));

    let unbound_environment = CausalLmEnvironment::new(
        hellas_rpc::ContentRef::new(ContentId::from_bytes([42; 32]), 1_024),
        "model",
        Vec::new(),
        Vec::new(),
        Vec::new(),
        16,
        16,
        hellas_rpc::CausalLmGenerationSchedule {
            fixed_capacity: 16,
            prefill_chunk_tokens: 16,
        },
    )
    .unwrap();
    let error = validate_evaluate_quote_response(
        &request,
        manifest_id,
        &unbound_environment,
        response,
        Some(trust.expected_genesis),
    )
    .unwrap_err();
    assert!(error.to_string().contains("does not match manifest root"));
}

#[test]
fn token_quote_rejects_a_non_causal_lm_application() {
    let (mut request, response, trust, _, _, environment) = valid_token_quote();
    let manifest = ProgramManifest::from_canonical_bytes(&request.program_manifest).unwrap();
    let manifest = ProgramManifest::new(
        Application::new(CATENA_GPU_EVALUATOR, "another-adaptor").unwrap(),
        manifest.root(),
    );
    let manifest_id = manifest.content_id();
    request.program_manifest = manifest.canonical_bytes();
    let error = validate_evaluate_quote_response(
        &request,
        manifest_id,
        &environment,
        response,
        Some(trust.expected_genesis),
    )
    .unwrap_err();
    assert!(error.to_string().contains("token Courtesy requires"));
}

#[test]
fn token_quote_provenance_must_name_the_ticket_commitment() {
    let (_, response, _, _, _, _) = valid_token_quote();
    let ticket = response.ticket.unwrap();
    let commitment_id: [u8; 32] = ticket.request_commitment.as_slice().try_into().unwrap();
    let valid = ExecutionProvenance { commitment_id };
    assert_eq!(
        validate_evaluate_quote_provenance(&ticket, valid.clone()).unwrap(),
        valid
    );

    let error = validate_evaluate_quote_provenance(
        &ticket,
        ExecutionProvenance {
            commitment_id: [42; 32],
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("does not match"), "{error}");
}

#[test]
fn token_quote_rejects_a_ticket_for_another_request() {
    let (request, mut response, trust, _, manifest_id, environment) = valid_token_quote();
    response.ticket.as_mut().unwrap().request_commitment = vec![0; 32];
    let error = validate_evaluate_quote_response(
        &request,
        manifest_id,
        &environment,
        response,
        Some(trust.expected_genesis),
    )
    .unwrap_err();
    assert!(error.to_string().contains("not bound"));
}

#[derive(Default)]
struct TestCounterStore {
    counters: Mutex<BTreeMap<[u8; 33], u32>>,
}

impl AssertionCounterStore for TestCounterStore {
    fn advance(
        &self,
        public_key: &[u8; 33],
        counter: u32,
    ) -> Result<(), hellas_attestation::AttestationError> {
        let mut counters = self
            .counters
            .lock()
            .map_err(|_| hellas_attestation::AttestationError::State)?;
        let previous = counters.get(public_key).copied().unwrap_or(0);
        if counter <= previous {
            return Err(hellas_attestation::AttestationError::Counter);
        }
        counters.insert(*public_key, counter);
        Ok(())
    }
}

fn apple_assertion(
    signing_key: &P256SigningKey,
    rp_id_hash: [u8; 32],
    cd_hash: [u8; 32],
    counter: u32,
    client_data_hash: &[u8; 32],
) -> Vec<u8> {
    let mut extensions = BTreeMap::new();
    extensions.insert(
        "apple_cd_hash_hash_01".to_owned(),
        ByteBuf::from(cd_hash.to_vec()),
    );
    extensions.insert("apple_cd_hash_type_01".to_owned(), ByteBuf::from(vec![2]));
    extensions.insert(
        "apple_validation_category_01".to_owned(),
        ByteBuf::from(vec![6, 0, 0, 0]),
    );
    let mut extension_bytes = Vec::new();
    ciborium::into_writer(&extensions, &mut extension_bytes).unwrap();

    let mut authenticator_data = Vec::new();
    authenticator_data.extend_from_slice(&rp_id_hash);
    authenticator_data.push(0x40);
    authenticator_data.extend_from_slice(&counter.to_be_bytes());
    authenticator_data.extend_from_slice(&extension_bytes);
    let digest = Sha256::digest([authenticator_data.as_slice(), client_data_hash].concat());
    let signature: P256Signature = signing_key.sign(&digest);

    #[derive(Serialize)]
    struct Assertion {
        #[serde(rename = "authenticatorData")]
        authenticator_data: ByteBuf,
        signature: ByteBuf,
    }

    let mut encoded = Vec::new();
    ciborium::into_writer(
        &Assertion {
            authenticator_data: ByteBuf::from(authenticator_data),
            signature: ByteBuf::from(signature.to_der().as_bytes().to_vec()),
        },
        &mut encoded,
    )
    .unwrap();
    encoded
}

fn apple_open_response(
    exporter: &[u8; 32],
    nonce: &[u8; 32],
    counter: u32,
    counter_store: Arc<TestCounterStore>,
) -> (ProviderTrustAnchor, OpenResponse, [u8; 33]) {
    let signing_key = P256SigningKey::from_bytes((&[7; 32]).into()).unwrap();
    let public_key = signing_key
        .verifying_key()
        .to_sec1_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    let cd_hash = [8; 32];
    let enrollment = AppleAppAttestEnrollment {
        attestation_object: vec![1],
        client_data_hash: [2; 32],
        validation_time: 3,
    };
    let credential_id = AppleCredential {
        attestation: enrollment.attestation_object.clone(),
        client_data_hash: enrollment.client_data_hash,
    }
    .content_id();
    let producer = ProducerSigningKey::from_secret_bytes([2; 32]).unwrap();
    let statement = ProviderGenesisStatement {
        root_kind: RootKind::SecureEnclave,
        root_public_key: PublicKey::P256(public_key),
        producer_public_key: producer.public_key(),
        transport_public_key: PublicKey::Ed25519(ENROLLED_PEER.0),
        platform_credential: PlatformCredential::Registered(credential_id),
        installation_nonce: [4; 32],
    };
    let genesis = SignedProviderGenesis {
        root_proof: RootProof::AppleAppAttest(Vec::new()),
        statement,
    };
    let bundle = ProviderEnrollmentBundle {
        genesis,
        platform: PlatformEnrollment::AppleAppAttest(enrollment),
    };
    let provider_genesis = bundle.canonical_bytes();
    let expected_genesis = ContentId::hash(&provider_genesis);
    let binding = hellas_rpc::open_proof_binding(
        exporter,
        nonce,
        &bundle.genesis.statement.producer_public_key,
        expected_genesis,
        ALPN,
    );
    let apple = AppleAppAttestTrust::new("TESTTEAM.example.app", vec![cd_hash], counter_store);
    *apple.credential.lock().unwrap() = Some(RegisteredAppleCredential {
        id: credential_id,
        public_key,
    });
    (
        ProviderTrustAnchor {
            expected_genesis,
            required_assurance: Assurance::AppleAppAttest,
            apple_app_attest: Some(apple),
        },
        OpenResponse {
            provider_genesis,
            proof: Some(open_response::Proof::AppleAppAttestAssertion(
                apple_assertion(
                    &signing_key,
                    apple_app_id_hash("TESTTEAM.example.app"),
                    cd_hash,
                    counter,
                    binding.as_bytes(),
                ),
            )),
        },
        public_key,
    )
}

#[test]
fn producer_signed_open_happy_path_verifies() {
    let exporter = [5; 32];
    let nonce = [6; 32];
    let (trust, response) = signed_open_response(&exporter, &nonce);
    let expected = ProviderEnrollmentBundle::from_canonical_bytes(&response.provider_genesis)
        .unwrap()
        .genesis
        .statement
        .producer_public_key;
    let verified =
        verify_open_response(&trust, &exporter, &nonce, ALPN, ENROLLED_PEER, response).unwrap();
    assert_eq!(verified, expected);
}

#[test]
fn apple_assurance_rejects_software_root_downgrade() {
    let exporter = [5; 32];
    let nonce = [6; 32];
    let (mut trust, response) = signed_open_response(&exporter, &nonce);
    trust.required_assurance = Assurance::AppleAppAttest;

    let error =
        verify_open_response(&trust, &exporter, &nonce, ALPN, ENROLLED_PEER, response).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("requires a Secure Enclave provider root")
    );
}

#[test]
fn request_assurance_must_match_trust_anchor_policy() {
    let (trust, _) = signed_open_response(&[5; 32], &[6; 32]);
    let error = validate_provider_trust_assurance(&trust, Assurance::AppleAppAttest).unwrap_err();
    assert!(error.to_string().contains("trust anchor requires"));
}

#[test]
fn apple_enrollment_is_registered_once_per_trust_anchor() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../attestation/tests/fixtures/real-app-attest.json"
    ))
    .unwrap();
    let artifacts = &fixture["artifacts"];
    let attestation_object = STANDARD
        .decode(artifacts["attestationObjectBase64"].as_str().unwrap())
        .unwrap();
    let client_data_hash: [u8; 32] =
        hex::decode(artifacts["attestationClientDataHashHex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
    let counters = Arc::new(TestCounterStore::default());
    let apple = AppleAppAttestTrust::new("2F53L9ZR3N.ai.hellas.app-attest-spike", vec![], counters);
    let enrollment = AppleAppAttestEnrollment {
        attestation_object,
        client_data_hash,
        validation_time: 1_784_384_387,
    };

    let first = apple.registered_credential(&enrollment).unwrap();
    let second = apple
        .registered_credential(&AppleAppAttestEnrollment {
            validation_time: 0,
            ..enrollment
        })
        .unwrap();

    assert_eq!(first, second);
}

#[test]
fn apple_open_rejects_genesis_key_that_differs_from_registered_credential() {
    let exporter = [5; 32];
    let nonce = [6; 32];
    let counters = Arc::new(TestCounterStore::default());
    let (mut trust, mut response, _) = apple_open_response(&exporter, &nonce, 2, counters);
    let mut bundle =
        ProviderEnrollmentBundle::from_canonical_bytes(&response.provider_genesis).unwrap();
    bundle.genesis.statement.root_public_key = PublicKey::P256([4; 33]);
    response.provider_genesis = bundle.canonical_bytes();
    trust.expected_genesis = ContentId::hash(&response.provider_genesis);

    let error =
        verify_open_response(&trust, &exporter, &nonce, ALPN, ENROLLED_PEER, response).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("does not match its chain-verified credential")
    );
}

#[test]
fn proof_for_different_exporter_is_rejected() {
    let nonce = [6; 32];
    let (trust, response) = signed_open_response(&[5; 32], &nonce);
    assert!(verify_open_response(&trust, &[7; 32], &nonce, ALPN, ENROLLED_PEER, response).is_err());
}

#[test]
fn pin_mismatch_aborts_before_prompt_send() {
    let exporter = [5; 32];
    let nonce = [6; 32];
    let (mut trust, response) = signed_open_response(&exporter, &nonce);
    trust.expected_genesis = ContentId::from_bytes([9; 32]);
    let mut prompt_sent = false;

    let result = (|| -> ClientResult<()> {
        verify_open_response(&trust, &exporter, &nonce, ALPN, ENROLLED_PEER, response)?;
        prompt_sent = true;
        Ok(())
    })();

    assert!(result.is_err());
    assert!(!prompt_sent);
}

#[test]
fn live_peer_mismatch_aborts_before_prompt_send() {
    let exporter = [5; 32];
    let nonce = [6; 32];
    let (trust, response) = signed_open_response(&exporter, &nonce);
    let mut prompt_sent = false;

    let result = (|| -> ClientResult<()> {
        verify_open_response(&trust, &exporter, &nonce, ALPN, OTHER_PEER, response)?;
        prompt_sent = true;
        Ok(())
    })();

    let error = result.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("provider transport key mismatch")
    );
    assert!(!prompt_sent);
}

#[test]
fn live_apple_open_advances_counter_and_rejects_lower_replay() {
    let exporter = [5; 32];
    let nonce = [6; 32];
    let counters = Arc::new(TestCounterStore::default());
    let (trust, response, public_key) = apple_open_response(&exporter, &nonce, 2, counters.clone());

    verify_open_response(&trust, &exporter, &nonce, ALPN, ENROLLED_PEER, response).unwrap();
    assert_eq!(counters.counters.lock().unwrap().get(&public_key), Some(&2));

    let (trust, replay, _) = apple_open_response(&exporter, &nonce, 1, counters.clone());
    let error =
        verify_open_response(&trust, &exporter, &nonce, ALPN, ENROLLED_PEER, replay).unwrap_err();
    let ClientError::Source { context, source } = error else {
        panic!("expected counter source error");
    };
    assert_eq!(
        context,
        "provider App Attest open assertion counter advancement failed"
    );
    assert_eq!(
        source.downcast_ref::<hellas_attestation::AttestationError>(),
        Some(&hellas_attestation::AttestationError::Counter)
    );
    assert_eq!(counters.counters.lock().unwrap().get(&public_key), Some(&2));
}

#[derive(Clone)]
struct FetchFixture {
    producer: ProducerSigningKey,
    enrollment: ProviderEnrollmentBundle,
}

impl FetchFixture {
    fn new(transport_key: &SecretKey) -> Self {
        let root = ProducerSigningKey::from_secret_bytes([0x71; 32]).unwrap();
        let producer = ProducerSigningKey::from_secret_bytes([0x72; 32]).unwrap();
        let statement = ProviderGenesisStatement {
            root_kind: RootKind::Software,
            root_public_key: root.public_key(),
            producer_public_key: producer.public_key(),
            transport_public_key: PublicKey::Ed25519(*transport_key.public().as_bytes()),
            platform_credential: PlatformCredential::Absent,
            installation_nonce: [0x73; 32],
        };
        let genesis = SignedProviderGenesis {
            root_proof: RootProof::Software(
                root.sign_digest(Digest::hash(&statement.canonical_bytes()))
                    .unwrap(),
            ),
            statement,
        };
        Self {
            producer,
            enrollment: ProviderEnrollmentBundle {
                genesis,
                platform: PlatformEnrollment::Absent,
            },
        }
    }

    fn trust(&self) -> ProviderTrustAnchor {
        ProviderTrustAnchor {
            expected_genesis: self.enrollment.content_id(),
            required_assurance: Assurance::ProducerSigned,
            apple_app_attest: None,
        }
    }
}

impl OpenHandler for FetchFixture {
    async fn open(
        &self,
        request: OpenRequest,
        context: hellas_wire::TransportContext,
        alpn: &'static [u8],
    ) -> Result<OpenResponse, WireStatus> {
        let nonce: [u8; 32] = request
            .nonce
            .try_into()
            .map_err(|_| WireStatus::internal("invalid fixture nonce"))?;
        let exporter = context
            .open_exporter
            .ok_or_else(|| WireStatus::internal("missing fixture exporter"))?;
        let binding = hellas_rpc::open_proof_binding(
            &exporter,
            &nonce,
            &self.enrollment.genesis.statement.producer_public_key,
            self.enrollment.content_id(),
            alpn,
        );
        let signature = self
            .producer
            .sign_digest(binding)
            .map_err(|_| WireStatus::internal("fixture signing failed"))?;
        Ok(OpenResponse {
            provider_genesis: self.enrollment.canonical_bytes(),
            proof: Some(open_response::Proof::ProducerSignature(signature_to_pb(
                &signature,
            ))),
        })
    }
}

#[allow(refining_impl_trait)]
impl FetchHandler for FetchFixture {
    async fn open(&self, _request: OpenRequest) -> Result<OpenResponse, WireStatus> {
        Err(WireStatus::internal("fixture Open dispatcher was bypassed"))
    }

    async fn create_ticket(
        &self,
        request: FetchRequest,
    ) -> Result<WithTrailer<Ticket>, WireStatus> {
        let input = verified_fetch_input(&request)
            .map_err(|error| WireStatus::new(WireCode::InvalidArgument, error.to_string()))?;
        let ticket = hellas_rpc::run_ticket::ticket_to_pb(
            JobTerms {
                request: RequestCommitment::from_digest(input.input_commitment.digest()),
                provider_genesis: self.enrollment.content_id(),
                assurance: input.assurance,
                amount: 1,
                ttl_ms: 1_000,
            },
            self.enrollment.canonical_bytes(),
        )
        .map_err(|error| WireStatus::internal(error.to_string()))?;
        Ok(ticket.into())
    }
}

#[derive(Clone)]
struct FetchExecuteFixture(ProducerSigningKey);

impl ExecuteHandler for FetchExecuteFixture {
    async fn run_ticket(
        &self,
        request: RunTicketRequest,
    ) -> Result<BoxStream<'static, Result<WorkEvent, WireStatus>>, WireStatus> {
        let ticket = request
            .ticket
            .as_ref()
            .ok_or_else(|| WireStatus::new(WireCode::InvalidArgument, "missing fixture ticket"))?;
        let terms = hellas_rpc::run_ticket::job_terms_from_pb(ticket)
            .map_err(|error| WireStatus::new(WireCode::InvalidArgument, error.to_string()))?;
        let input = InputCommitment::from_digest(terms.request.digest());
        let terminal = hellas_rpc::fetch::encode_fetch_terminal_payload(
            &hellas_rpc::output::OutputEvent::Finished {
                stop_reason: hellas_rpc::output::StopReason::EndOfText,
                usage: None,
            },
        )
        .map_err(|error| WireStatus::internal(error.to_string()))?;
        let output =
            hellas_rpc::fetch::build_output_events(input, terms.assurance, &terminal, &self.0)
                .map_err(|error| WireStatus::internal(error.to_string()))?;
        Ok(Box::pin(stream::iter([Ok(WorkEvent {
            kind: Some(work_event::Kind::Finished(WorkFinished {
                terminal_output_event: output.last().map(output_event_to_pb),
                assurance_evidence: Vec::new(),
            })),
        })])))
    }
}

#[tokio::test]
async fn fetch_open_ticket_and_signed_output_share_one_verified_connection() {
    let server_key = SecretKey::from_bytes(&[0x74; 32]);
    let provider = FetchFixture::new(&server_key);
    let server = Endpoint::builder(presets::Minimal)
        .secret_key(server_key)
        .alpns(vec![Fetch::ALPN.as_bytes().to_vec()])
        .bind_addr("127.0.0.1:0".parse::<std::net::SocketAddr>().unwrap())
        .unwrap()
        .bind()
        .await
        .unwrap();
    let target = EndpointAddr::from_parts(
        server.id(),
        server.bound_sockets().into_iter().map(TransportAddr::Ip),
    );
    let (event_consumed, event_is_consumed) = tokio::sync::oneshot::channel();
    let accepting_server = server.clone();
    let serving_provider = provider.clone();
    let serving = tokio::spawn(async move {
        let incoming = accepting_server.accept().await.expect("one Fetch dial");
        let connection = incoming
            .accept()
            .expect("accept Fetch dial")
            .await
            .expect("complete Fetch handshake");
        assert_eq!(connection.alpn(), Fetch::ALPN.as_bytes());
        let transport = IrohTransport::new(connection);
        let dispatcher = OpenDispatcher::<_, _, FetchOpen>::new(
            MethodDispatcher::<_, _, RunTicket>::new(
                ExecuteServer(FetchExecuteFixture(serving_provider.producer.clone())),
                FetchServer(serving_provider.clone()),
            ),
            serving_provider,
        );
        for expected in [
            FetchOpen::METHOD_ID,
            CreateTicket::METHOD_ID,
            RunTicket::METHOD_ID,
        ] {
            let inbound = transport
                .accept()
                .await
                .expect("Fetch transport remains live")
                .expect("Fetch receives the next method");
            assert_eq!(inbound.method_id, expected);
            Dispatcher::<IrohTransport>::dispatch(&dispatcher, inbound)
                .await
                .expect("Fetch method dispatches");
        }
        let _ = event_is_consumed.await;
    });

    let runner = Arc::new(ProducerSigningKey::from_secret_bytes([0x75; 32]).unwrap());
    assert_ne!(runner.public_key(), provider.producer.public_key());
    let input = build_input_events(
        "codex",
        "responses",
        br#"{"model":"fixture"}"#,
        ContentId::from_bytes([0x76; 32]),
        Assurance::ProducerSigned,
        runner.as_ref(),
    )
    .unwrap();
    let request = FetchRequest {
        input: input.iter().map(input_event_to_pb).collect(),
    };
    let runtime = ExecutionRuntime::<()>::remote(SecretKey::from_bytes(&[0x77; 32]))
        .await
        .unwrap();
    let route = ExecutionRoute::RemoteDirect(RemoteNodeTarget {
        addr: target,
        provider_trust: provider.trust(),
    });
    let stream = fetch_execution_stream(runtime, request, route, runner);
    futures::pin_mut!(stream);
    let event = tokio::time::timeout(std::time::Duration::from_secs(10), stream.next())
        .await
        .expect("Fetch execution completes")
        .expect("Fetch emits a terminal event")
        .expect("the pinned producer signature verifies");
    assert!(matches!(
        event,
        FetchExecutionEvent::Done(FetchOutcome::Completed { .. })
    ));
    assert!(stream.next().await.is_none());
    let _ = event_consumed.send(());
    serving
        .await
        .expect("the one Fetch connection serves all methods");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), server.accept())
            .await
            .is_err(),
        "Fetch must not dial a second connection after confidential Open",
    );
    server.close().await;
}
