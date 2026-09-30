use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hellas_rpc::{
    Digest, ProducerSigningKey, ProviderEnrollmentBundle, ProviderGenesisStatement, RootProof,
    SignedProviderGenesis, pb::execute::open_response, signature_wire::signature_to_pb,
};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, signature::Signer as _,
};
use serde::Serialize;
use serde_bytes::ByteBuf;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
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
    counters: Arc<TestCounterStore>,
) -> (ProviderTrustAnchor, OpenResponse, [u8; 33]) {
    apple_open_response_for_alpn(exporter, nonce, ALPN, counter, counters)
}

fn apple_open_response_for_alpn(
    exporter: &[u8; 32],
    nonce: &[u8; 32],
    alpn: &[u8],
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
        alpn,
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

#[test]
fn paid_services_app_attest_binds_the_exact_connection_and_service() {
    for alpn in [
        hellas_rpc::services::work::Work::ALPN,
        hellas_rpc::services::work_setup::WorkSetup::ALPN,
    ] {
        let counters = Arc::new(TestCounterStore::default());
        let (trust, response, _) =
            apple_open_response_for_alpn(&[1; 32], &[2; 32], alpn.as_bytes(), 1, counters);
        assert!(
            verify_open_response(
                &trust,
                &[1; 32],
                &[2; 32],
                b"different-service",
                ENROLLED_PEER,
                response.clone()
            )
            .is_err()
        );
        assert!(
            verify_open_response(
                &trust,
                &[3; 32],
                &[2; 32],
                alpn.as_bytes(),
                ENROLLED_PEER,
                response.clone()
            )
            .is_err()
        );
        assert!(
            verify_open_response(
                &trust,
                &[1; 32],
                &[4; 32],
                alpn.as_bytes(),
                ENROLLED_PEER,
                response.clone()
            )
            .is_err()
        );
        assert!(
            verify_open_response(
                &trust,
                &[1; 32],
                &[2; 32],
                alpn.as_bytes(),
                ENROLLED_PEER,
                response.clone()
            )
            .is_ok()
        );
        assert!(
            verify_open_response(
                &trust,
                &[1; 32],
                &[2; 32],
                alpn.as_bytes(),
                ENROLLED_PEER,
                response
            )
            .is_err()
        );
    }
}
