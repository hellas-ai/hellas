#![cfg(feature = "apple-app-attest")]

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hellas_attestation::{
    AnchorTime, AppleCredential, ApplePolicy, AppleVerdict, AttestationError,
    RegisteredAppleCredential, apple_app_attest_root_ca, apple_app_id_hash,
    apple_credential_identity, appraise_apple, register_apple, verify_apple_assertion,
};
use hellas_rpc::ContentId;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde::Serialize;
use serde_bytes::ByteBuf;
use sha2::{Digest as _, Sha256};

const APP_ID: &str = "2F53L9ZR3N.ai.hellas.app-attest-spike";
const FIXTURE_VALIDATION_TIME: u64 = 1_784_384_387;
const REAL_CD_HASH: [u8; 32] = [
    0xcb, 0x92, 0xa8, 0x90, 0x91, 0x54, 0x57, 0xb2, 0x26, 0xfe, 0xa9, 0xbe, 0x77, 0x8f, 0xc6, 0xa2,
    0x99, 0x94, 0xa2, 0xc6, 0x0d, 0xfa, 0xa6, 0x03, 0x71, 0xe9, 0xe2, 0x64, 0xd8, 0x54, 0x13, 0x06,
];

struct Fixture {
    attestation_object_base64: &'static str,
    attestation_client_data_hash_hex: &'static str,
    assertion_object_base64: &'static str,
    assertion_client_data_hash_hex: &'static str,
}

fn fixture() -> Fixture {
    fixture_from_json(include_str!("fixtures/real-app-attest.json"))
}

fn fixture_from_json(json: &'static str) -> Fixture {
    let field = |name: &str| {
        json.lines()
            .find_map(|line| {
                let (key, value) = line.trim().split_once(" : ")?;
                (key.trim_matches('"') == name)
                    .then(|| value.trim_end_matches(',').trim_matches('"'))
            })
            .unwrap()
    };
    Fixture {
        attestation_object_base64: field("attestationObjectBase64"),
        attestation_client_data_hash_hex: field("attestationClientDataHashHex"),
        assertion_object_base64: field("assertionObjectBase64"),
        assertion_client_data_hash_hex: field("assertionClientDataHashHex"),
    }
}

#[test]
fn real_sdk27_evidence_verifies_with_the_extensions_flag() {
    let fixture = fixture_from_json(include_str!("fixtures/real-app-attest-sdk27.json"));
    let credential = fixture_credential(&fixture);
    let identity = apple_credential_identity(&credential.attestation).unwrap();
    let policy = ApplePolicy {
        expected_rp_id_hash: apple_app_id_hash(APP_ID),
        allowed_cd_hashes: vec![decode_hex_32(
            "363140c091e0fa85feeeb4ce515eddcae8cf6db45b93b2ca722391a3a64c1006",
        )],
    };
    let registered = register_apple(
        &credential,
        policy.expected_rp_id_hash,
        apple_app_attest_root_ca(),
        AnchorTime(1_790_996_283),
    )
    .unwrap();
    assert_eq!(identity.public_key, registered.public_key);
    assert_eq!(identity.cd_hash, policy.allowed_cd_hashes[0]);
    let claims = verify_apple_assertion(
        &decode_base64(fixture.assertion_object_base64),
        &decode_hex_32(fixture.assertion_client_data_hash_hex),
        &registered,
        &policy,
    )
    .unwrap();
    assert_eq!(claims.cd_hash, identity.cd_hash);
    assert_eq!(claims.counter, 1);
}

fn decode_base64(value: &str) -> Vec<u8> {
    STANDARD.decode(value).unwrap()
}

fn decode_hex_32(value: &str) -> [u8; 32] {
    hex::decode(value).unwrap().try_into().unwrap()
}

fn fixture_credential(fixture: &Fixture) -> AppleCredential {
    AppleCredential {
        attestation: decode_base64(fixture.attestation_object_base64),
        client_data_hash: decode_hex_32(fixture.attestation_client_data_hash_hex),
    }
}

fn registered_fixture(fixture: &Fixture) -> RegisteredAppleCredential {
    register_apple(
        &fixture_credential(fixture),
        apple_app_id_hash(APP_ID),
        apple_app_attest_root_ca(),
        AnchorTime(FIXTURE_VALIDATION_TIME),
    )
    .unwrap()
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes((&[7; 32]).into()).unwrap()
}

fn registered(signing_key: &SigningKey) -> RegisteredAppleCredential {
    RegisteredAppleCredential {
        id: ContentId::from_bytes([9; 32]),
        public_key: signing_key
            .verifying_key()
            .to_sec1_point(true)
            .as_bytes()
            .try_into()
            .unwrap(),
    }
}

fn assertion(
    signing_key: &SigningKey,
    rp_id_hash: [u8; 32],
    asserted_cd_hash: [u8; 32],
    counter: u32,
    client_data_hash: &[u8; 32],
) -> Vec<u8> {
    let mut extensions = BTreeMap::new();
    extensions.insert(
        "apple_cd_hash_hash_01".to_owned(),
        ByteBuf::from(asserted_cd_hash.to_vec()),
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
    signed_assertion(signing_key, authenticator_data, client_data_hash)
}

fn signed_assertion(
    signing_key: &SigningKey,
    authenticator_data: Vec<u8>,
    client_data_hash: &[u8; 32],
) -> Vec<u8> {
    let digest = Sha256::digest([authenticator_data.as_slice(), client_data_hash].concat());
    let signature: Signature = signing_key.sign(&digest);

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

#[test]
fn real_attestation_registers_against_apple_chain() {
    let fixture = fixture();
    let credential = fixture_credential(&fixture);
    let registered = registered_fixture(&fixture);

    assert_eq!(registered.id, credential.content_id());
    assert_eq!(
        register_apple(
            &credential,
            apple_app_id_hash("WRONGTEAM.ai.hellas.app-attest-spike"),
            apple_app_attest_root_ca(),
            AnchorTime(FIXTURE_VALIDATION_TIME),
        ),
        Err(AttestationError::Credential)
    );
}

#[test]
fn real_assertion_verifies_with_app_rp_id_and_direct_cd_hash_allowlist() {
    let fixture = fixture();
    let registered = registered_fixture(&fixture);
    let client_data_hash = decode_hex_32(fixture.assertion_client_data_hash_hex);
    let assertion = decode_base64(fixture.assertion_object_base64);
    let policy = ApplePolicy {
        expected_rp_id_hash: apple_app_id_hash(APP_ID),
        allowed_cd_hashes: vec![REAL_CD_HASH],
    };

    let claims =
        verify_apple_assertion(&assertion, &client_data_hash, &registered, &policy).unwrap();
    assert_eq!(claims.counter, 1);
    assert_eq!(claims.cd_hash, REAL_CD_HASH);
    assert_eq!(appraise_apple(&claims, &policy), AppleVerdict::Accepted);

    let legacy_hashed_cd_policy = ApplePolicy {
        expected_rp_id_hash: apple_app_id_hash(APP_ID),
        allowed_cd_hashes: vec![Sha256::digest(REAL_CD_HASH).into()],
    };
    assert_eq!(
        verify_apple_assertion(
            &assertion,
            &client_data_hash,
            &registered,
            &legacy_hashed_cd_policy,
        ),
        Err(AttestationError::Credential)
    );
}

#[test]
fn credential_identity_extracts_real_build_identity_without_rp_id_relation() {
    let fixture = fixture();
    let credential = fixture_credential(&fixture);
    let identity = apple_credential_identity(&credential.attestation).unwrap();

    assert_eq!(identity.public_key, registered_fixture(&fixture).public_key);
    assert_eq!(identity.rp_id_hash, apple_app_id_hash(APP_ID));
    assert_eq!(identity.cd_hash, REAL_CD_HASH);
    let legacy_rp_id_hash: [u8; 32] = Sha256::digest(identity.cd_hash).into();
    assert_ne!(apple_app_id_hash(APP_ID), legacy_rp_id_hash);
}

#[test]
fn verifies_assertion_from_an_updated_allowlisted_cd_hash() {
    let signing_key = signing_key();
    let registered = registered(&signing_key);
    let rp_id_hash = apple_app_id_hash(APP_ID);
    let old_cd_hash = [1; 32];
    let updated_cd_hash = [2; 32];
    let policy = ApplePolicy {
        expected_rp_id_hash: rp_id_hash,
        allowed_cd_hashes: vec![old_cd_hash, updated_cd_hash],
    };
    let client_data_hash = [3; 32];
    let assertion = assertion(
        &signing_key,
        rp_id_hash,
        updated_cd_hash,
        1,
        &client_data_hash,
    );
    let claims =
        verify_apple_assertion(&assertion, &client_data_hash, &registered, &policy).unwrap();

    assert_eq!(claims.counter, 1);
    assert_eq!(claims.cd_hash, updated_cd_hash);
}

#[test]
fn rejects_wrong_app_rp_id_and_cd_hash_outside_allowlist() {
    let signing_key = signing_key();
    let registered = registered(&signing_key);
    let rp_id_hash = apple_app_id_hash(APP_ID);
    let allowed_cd_hash = [1; 32];
    let denied_cd_hash = [2; 32];
    let client_data_hash = [3; 32];
    let policy = ApplePolicy {
        expected_rp_id_hash: rp_id_hash,
        allowed_cd_hashes: vec![allowed_cd_hash],
    };

    let wrong_app = assertion(
        &signing_key,
        apple_app_id_hash("OTHERTEAM.example.app"),
        allowed_cd_hash,
        1,
        &client_data_hash,
    );
    assert_eq!(
        verify_apple_assertion(&wrong_app, &client_data_hash, &registered, &policy),
        Err(AttestationError::Binding)
    );

    let denied_build = assertion(
        &signing_key,
        rp_id_hash,
        denied_cd_hash,
        1,
        &client_data_hash,
    );
    assert_eq!(
        verify_apple_assertion(&denied_build, &client_data_hash, &registered, &policy),
        Err(AttestationError::Credential)
    );
}

#[test]
fn rejects_signed_assertion_that_omits_cd_hash_evidence() {
    let signing_key = signing_key();
    let registered = registered(&signing_key);
    let rp_id_hash = apple_app_id_hash(APP_ID);
    let client_data_hash = [3; 32];
    let policy = ApplePolicy {
        expected_rp_id_hash: rp_id_hash,
        allowed_cd_hashes: vec![[1; 32]],
    };
    for flags in [0x40, 0xc0] {
        let mut authenticator_data = Vec::new();
        authenticator_data.extend_from_slice(&rp_id_hash);
        authenticator_data.push(flags);
        authenticator_data.extend_from_slice(&1_u32.to_be_bytes());
        let assertion = signed_assertion(&signing_key, authenticator_data, &client_data_hash);

        assert_eq!(
            verify_apple_assertion(&assertion, &client_data_hash, &registered, &policy),
            Err(AttestationError::AppleCdHashMissing)
        );
    }
}

#[test]
fn repeated_verification_does_not_advance_counter_state() {
    let signing_key = signing_key();
    let registered = registered(&signing_key);
    let rp_id_hash = apple_app_id_hash(APP_ID);
    let cd_hash = [1; 32];
    let client_data_hash = [3; 32];
    let policy = ApplePolicy {
        expected_rp_id_hash: rp_id_hash,
        allowed_cd_hashes: vec![cd_hash],
    };
    let assertion = assertion(&signing_key, rp_id_hash, cd_hash, 2, &client_data_hash);

    let first =
        verify_apple_assertion(&assertion, &client_data_hash, &registered, &policy).unwrap();
    let second =
        verify_apple_assertion(&assertion, &client_data_hash, &registered, &policy).unwrap();

    assert_eq!(first, second);
    assert_eq!(second.counter, 2);
}
