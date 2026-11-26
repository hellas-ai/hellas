use super::*;
use hellas_attestation::apple_app_id_hash;
#[path = "../../../attestation/tests/fixtures/apple.rs"]
mod device;
use hellas_auth::authority::{GrantId, Revision, UnixMillis};
use hellas_auth::{Digest, ProducerSigningKey};
use hellas_rpc::{
    ProviderEnrollmentBundle, ProviderGenesisStatement, RootProof, SignedProviderGenesis,
    pb::execute::open_response, signature_wire::signature_to_pb,
};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, signature::Signer as _,
};
use serde::Serialize;
use serde_bytes::ByteBuf;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
const SPIKE_APP_ID: &str = "2F53L9ZR3N.ai.hellas.app-attest-spike";
const ALPN: &[u8] = b"/hellas.work.v1.Work/2.0";
const ENROLLED_PEER: PeerIdentity = PeerIdentity([3; 32]);
const OTHER_PEER: PeerIdentity = PeerIdentity([7; 32]);
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
        ProviderTrustAnchor::new(
            expected_genesis,
            Assurance::ProducerSigned,
            ApplePolicy::default(),
            Arc::new(TestCounterStore::default()),
        ),
        OpenResponse {
            provider_genesis,
            proof: Some(open_response::Proof::ProducerSignature(signature_to_pb(
                &signature,
            ))),
        },
    )
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
    authenticator_data.push(0xc0);
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

// Signing a new Offer needs the producer key, which the recorded device keeps.
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
        root_proof: RootProof::AppleAppAttest(apple_assertion(
            &signing_key,
            apple_app_id_hash("TESTTEAM.example.app"),
            cd_hash,
            1,
            &hellas_attestation::apple_client_data_hash(&statement.canonical_bytes()),
        )),
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
    let trust = ProviderTrustAnchor::new(
        expected_genesis,
        Assurance::AppleAppAttest,
        ApplePolicy::new(
            ["TESTTEAM.example.app".into()].into(),
            Some([cd_hash].into()),
        )
        .unwrap(),
        counter_store,
    );
    *trust.credential.lock().unwrap() = Some(RegisteredAppleCredential {
        id: credential_id,
        rp_id_hash: apple_app_id_hash("TESTTEAM.example.app"),
        public_key,
    });
    (
        trust,
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

fn address_of(response: &OpenResponse) -> ProviderAddress {
    ProviderAddress {
        enrollment: ContentId::hash(&response.provider_genesis),
        node: ::iroh::SecretKey::from_bytes(&[3; 32]).public(),
    }
}

#[test]
fn addressed_software_provider_requires_its_enrollment_and_a_valid_open_from_its_peer() {
    let exporter = [5; 32];
    let nonce = [6; 32];
    let (_, response) = signed_open_response(&exporter, &nonce);
    let address = address_of(&response);
    let trust = address.trust(
        Assurance::ProducerSigned,
        ApplePolicy::default(),
        Arc::new(TestCounterStore::default()),
    );
    verify_open_response(
        &trust,
        &exporter,
        &nonce,
        ALPN,
        ENROLLED_PEER,
        response.clone(),
    )
    .unwrap();
    assert!(
        verify_open_response(
            &trust,
            &exporter,
            &nonce,
            ALPN,
            PeerIdentity([0; 32]),
            response.clone()
        )
        .is_err()
    );
    assert!(
        verify_open_response(
            &trust,
            &[0; 32],
            &nonce,
            ALPN,
            ENROLLED_PEER,
            response.clone()
        )
        .is_err()
    );
    let other = ProviderAddress {
        enrollment: ContentId::from_bytes([9; 32]),
        ..address
    };
    let error = verify_open_response(
        &other.trust(
            Assurance::ProducerSigned,
            ApplePolicy::default(),
            Arc::new(TestCounterStore::default()),
        ),
        &exporter,
        &nonce,
        ALPN,
        ENROLLED_PEER,
        response,
    )
    .unwrap_err();
    assert!(
        error.to_string().contains("genesis pin mismatch"),
        "{error}"
    );
}

fn recorded_bytes(hex: &str) -> [u8; 32] {
    hex::decode(hex).unwrap().try_into().unwrap()
}

fn assert_attestation_error(error: ClientError, expected: hellas_attestation::AttestationError) {
    let ClientError::Source { source, .. } = error else {
        panic!("expected an attestation error, got {error}");
    };
    assert_eq!(source.downcast_ref(), Some(&expected));
}

fn recorded_open() -> (PeerIdentity, OpenResponse, [u8; 32], [u8; 32]) {
    let peer = PeerIdentity(recorded_bytes(
        "c19b5b4a27162ec685aeb6b715d4436827b8b01fe8ebecb3e9f38e7a0b247452",
    ));
    let response = OpenResponse {
        provider_genesis: device::enrollment().canonical_bytes(),
        proof: Some(open_response::Proof::AppleAppAttestAssertion(
            include_bytes!("../../../attestation/tests/fixtures/apple-open.cbor").to_vec(),
        )),
    };
    let exporter =
        recorded_bytes("df4676398cad6e7e1f620ce4f15959fc1015d7c1a384d2f1f766b0ef670e96be");
    let nonce = recorded_bytes("3884ecd401c63ea961c1254d8baf27cfde2b086ab85ca86c07ef3b29cf969466");
    (peer, response, exporter, nonce)
}

fn recorded_trust(policy: ApplePolicy, counters: Arc<TestCounterStore>) -> ProviderTrustAnchor {
    let address = "b714c1ab606aa40d01de47e47eb3d4d7d54c7283d02beac9d3e1d8e17e433f39@c19b5b4a27162ec685aeb6b715d4436827b8b01fe8ebecb3e9f38e7a0b247452".parse::<ProviderAddress>().unwrap();
    address.trust(Assurance::ProducerSigned, policy, counters)
}

#[test]
fn default_policy_rejects_the_recorded_spike_app() {
    let trust = recorded_trust(ApplePolicy::default(), Arc::default());
    assert_attestation_error(
        trust.verify_enrollment(&device::enrollment()).unwrap_err(),
        hellas_attestation::AttestationError::Credential,
    );
}

#[test]
fn different_cdhash_rejects_recorded_open_before_counter_advances() {
    let counters = Arc::new(TestCounterStore::default());
    let policy = ApplePolicy::new([SPIKE_APP_ID.into()].into(), Some([[0; 32]].into())).unwrap();
    let trust = recorded_trust(policy, counters.clone());
    let (peer, response, exporter, nonce) = recorded_open();
    assert_attestation_error(
        verify_open_response(&trust, &exporter, &nonce, ALPN, peer, response).unwrap_err(),
        hellas_attestation::AttestationError::Credential,
    );
    assert!(counters.counters.lock().unwrap().is_empty());
}

#[test]
fn recorded_cdhash_accepts_the_connection_bound_open() {
    let (peer, response, exporter, nonce) = recorded_open();
    let bundle = device::enrollment();
    let cd_hash =
        recorded_bytes("320cb97347ecf28369401a21ba85553008c8d8009ae6f3bffa159a0dede1eab6");
    let policy = ApplePolicy::new([SPIKE_APP_ID.into()].into(), Some([cd_hash].into())).unwrap();
    let approved = recorded_trust(policy, Arc::default());
    let open = |trust: &ProviderTrustAnchor| {
        verify_open_response(trust, &exporter, &nonce, ALPN, peer, response.clone())
    };
    // Before the accepted Open, so a broken binding cannot hide behind the counter.
    for (exporter, nonce, alpn) in [
        ([0; 32], nonce, ALPN),
        (exporter, [0; 32], ALPN),
        (exporter, nonce, b"different-service".as_slice()),
    ] {
        assert!(
            verify_open_response(&approved, &exporter, &nonce, alpn, peer, response.clone())
                .is_err()
        );
    }
    assert_eq!(
        open(&approved).unwrap(),
        bundle.genesis.statement.producer_public_key
    );
    assert_attestation_error(
        open(&approved).unwrap_err(),
        hellas_attestation::AttestationError::Counter,
    );

    let mut changed = bundle;
    changed.genesis.statement.root_public_key = PublicKey::P256([4; 33]);
    let mut trust = approved;
    trust.expected_genesis = changed.content_id();
    let response = OpenResponse {
        provider_genesis: changed.canonical_bytes(),
        ..response
    };
    let error = verify_open_response(&trust, &exporter, &nonce, ALPN, peer, response).unwrap_err();
    assert_attestation_error(error, hellas_attestation::AttestationError::Credential);
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
fn apple_enrollment_is_registered_once_per_trust_anchor() {
    let PlatformEnrollment::AppleAppAttest(enrollment) = device::enrollment().platform else {
        panic!("expected App Attest enrollment");
    };
    let counters = Arc::new(TestCounterStore::default());
    let apple = ProviderAddress::of(&device::enrollment()).unwrap().trust(
        Assurance::AppleAppAttest,
        ApplePolicy::new([SPIKE_APP_ID.into()].into(), None).unwrap(),
        counters,
    );

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

#[cfg(feature = "work")]
#[test]
fn apple_offer_pin_verifies_static_root_policy_then_open_and_result() {
    use crate::UnpinnedOffer;
    use hellas_authority::model::grant::{records::*, *};
    use std::num::NonZeroU64;
    let counters = Arc::new(TestCounterStore::default());
    let (mut trust, response, public_key) =
        apple_open_response(&[5; 32], &[6; 32], 2, counters.clone());
    trust.required_assurance = Assurance::ProducerSigned;
    let bundle =
        ProviderEnrollmentBundle::from_canonical_bytes(&response.provider_genesis).unwrap();
    assert!(
        verify_software_enrollment(&bundle).is_err(),
        "platform roots remain provider-only"
    );
    let client = hellas_channel::test_support::principal(1).0;
    let producer = ProducerSigningKey::from_secret_bytes([2; 32]).unwrap();
    let policy = GrantPolicy {
        backend_evaluator: None,
        config_change: Default::default(),
        resource: hellas_auth::authority::ResourceId(hellas_auth::Digest::hash(b"test resource")),
        account: hellas_auth::authority::ResourceId(hellas_auth::Digest::hash(b"test account")),
        revision: hellas_auth::authority::Revision(1),
        name: "responses".into(),
        https: None,
        pricing: hellas_authority::model::grant::pricing::Pricing {
            revision: hellas_auth::authority::Revision(1),
            rates: None,
        },
        responses: Some(
            hellas_authority::model::grant::responses::ResponsesResource {
                model: "fixture".into(),
                max_output_tokens: 8,
                settings: Default::default(),
            },
        ),
        invocation_policy: hellas_authority::test_support::policy().invocation_policy,
    };
    let offer = SignedOffer::sign(
        Offer {
            network: grant_network(),
            provider: bundle.clone(),
            grant: GrantDef {
                id: GrantId([1; 16]),
                revision: Revision(1),
                policies: vec![policy],
                budget: budget::BudgetNode::Subject {
                    pool: budget::PoolId([1; 16]),
                    subject: client,
                },
                max_job_millis: NonZeroU64::new(1000).unwrap(),
                enabled: true,
                allow_account_backed: true,
            },
            generation: 0,
            sequence: 1,
            valid_until: UnixMillis(2000),
            addresses: vec![],
        },
        &producer,
    )
    .unwrap();
    let import = || UnpinnedOffer::decode(&offer.encode().unwrap(), UnixMillis(1000)).unwrap();
    let pinned = import().pin(&trust).unwrap();
    import().pin(&trust).unwrap();
    assert!(
        counters.counters.lock().unwrap().is_empty(),
        "static enrollment is reusable"
    );
    let verified = verify_open_response(
        pinned.trust(),
        &[5; 32],
        &[6; 32],
        ALPN,
        ENROLLED_PEER,
        response.clone(),
    )
    .unwrap();
    assert_eq!(counters.counters.lock().unwrap().get(&public_key), Some(&2));
    use hellas_rpc::protocol::invocation::{InvocationRequest, output};
    let request = InvocationRequest {
        execution_environment: ContentId::hash(b"grant environment"),
        input: ContentId::hash(b"grant input"),
        runner_public_key: producer.public_key(),
        nonce: [3; 32],
        assurance: Assurance::AppleAppAttest,
        retain: false,
    };
    let (_, events) = output::OutputStream::new(&request, &producer, 65536)
        .unwrap()
        .fail(output::FailureReason::Unavailable)
        .unwrap();
    output::verify(&request, &verified, &events, 65536).unwrap();
    assert!(
        verify_open_response(&trust, &[5; 32], &[6; 32], ALPN, ENROLLED_PEER, response).is_err()
    );
}
