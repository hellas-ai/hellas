#![cfg(feature = "apple-app-attest")]

#[path = "fixtures/apple.rs"]
mod device;

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hellas_attestation::{
    AnchorTime, AppleCredential, ApplePolicy, AttestationError, RegisteredAppleCredential,
    apple_app_attest_root_ca, apple_app_id_hash, apple_credential_identity,
};
use hellas_rpc::ContentId;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde::Serialize;
use serde_bytes::ByteBuf;
use sha2::{Digest as _, Sha256};

const APP_ID: &str = "2F53L9ZR3N.ai.hellas.app-attest-spike";
const FIXTURE_VALIDATION_TIME: u64 = 1_790_996_283;
const REAL_CD_HASH: [u8; 32] = [
    0x36, 0x31, 0x40, 0xc0, 0x91, 0xe0, 0xfa, 0x85, 0xfe, 0xee, 0xb4, 0xce, 0x51, 0x5e, 0xdd, 0xca,
    0xe8, 0xcf, 0x6d, 0xb4, 0x5b, 0x93, 0xb2, 0xca, 0x72, 0x23, 0x91, 0xa3, 0xa6, 0x4c, 0x10, 0x06,
];

struct Fixture {
    attestation_object_base64: &'static str,
    attestation_client_data_hash_hex: &'static str,
    assertion_object_base64: &'static str,
    assertion_client_data_hash_hex: &'static str,
}

fn fixture() -> Fixture {
    let json = include_str!("fixtures/real-app-attest.json");
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
    ApplePolicy::new([APP_ID.to_string()].into(), None)
        .unwrap()
        .register(
            &fixture_credential(fixture),
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
        rp_id_hash: apple_app_id_hash(APP_ID),
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
    authenticator_data.push(0xc0);
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
fn device_genesis_verifies_at_enrollment_time() {
    let mut bundle = device::enrollment();
    let hellas_rpc::PlatformEnrollment::AppleAppAttest(enrollment) = bundle.platform else {
        panic!("expected App Attest enrollment");
    };
    let policy = ApplePolicy::new(
        [APP_ID.to_string()].into(),
        Some(
            [decode_hex_32(
                "320cb97347ecf28369401a21ba85553008c8d8009ae6f3bffa159a0dede1eab6",
            )]
            .into(),
        ),
    )
    .unwrap();
    let credential = policy
        .register(
            &AppleCredential {
                attestation: enrollment.attestation_object,
                client_data_hash: enrollment.client_data_hash,
            },
            apple_app_attest_root_ca(),
            AnchorTime(enrollment.validation_time),
        )
        .unwrap();
    let verify = |genesis: &hellas_rpc::SignedProviderGenesis| {
        hellas_attestation::verify_apple_provider_genesis(genesis, &credential)
            .and_then(|claims| policy.check_build(claims))
    };
    verify(&bundle.genesis).unwrap();
    bundle.genesis.statement.installation_nonce[0] ^= 1;
    assert_eq!(verify(&bundle.genesis), Err(AttestationError::Signature));
}

#[test]
fn real_attestation_registers_against_apple_chain() {
    let fixture = fixture();
    let credential = fixture_credential(&fixture);
    let registered = registered_fixture(&fixture);

    assert_eq!(registered.id, credential.content_id());
    assert_eq!(
        ApplePolicy::default().register(
            &credential,
            apple_app_attest_root_ca(),
            AnchorTime(FIXTURE_VALIDATION_TIME),
        ),
        Err(AttestationError::Credential)
    );
    let mut changed = credential;
    changed.client_data_hash[0] ^= 1;
    assert_eq!(
        ApplePolicy::new([APP_ID.to_string()].into(), None)
            .unwrap()
            .register(
                &changed,
                apple_app_attest_root_ca(),
                AnchorTime(FIXTURE_VALIDATION_TIME),
            ),
        Err(AttestationError::Credential)
    );
}

#[test]
fn real_assertion_verifies_with_app_rp_id_and_direct_cd_hash_allowlist() {
    let fixture = fixture();
    let other_key = registered(&signing_key());
    let registered = registered_fixture(&fixture);
    let client_data_hash = decode_hex_32(fixture.assertion_client_data_hash_hex);
    let assertion = decode_base64(fixture.assertion_object_base64);
    let policy =
        ApplePolicy::new([APP_ID.to_string()].into(), Some([REAL_CD_HASH].into())).unwrap();

    let claims = policy
        .verify_assertion(&assertion, &client_data_hash, &registered)
        .unwrap();
    assert_eq!(claims.counter, 1);
    assert_eq!(claims.cd_hash, REAL_CD_HASH);

    let hashed_cd_policy = ApplePolicy::new(
        [APP_ID.to_string()].into(),
        Some([Sha256::digest(REAL_CD_HASH).into()].into()),
    )
    .unwrap();
    assert_eq!(
        hashed_cd_policy.verify_assertion(&assertion, &client_data_hash, &registered),
        Err(AttestationError::Credential)
    );
    let mut changed = client_data_hash;
    changed[0] ^= 1;
    assert_eq!(
        policy.verify_assertion(&assertion, &changed, &registered),
        Err(AttestationError::Signature)
    );
    assert_eq!(
        policy.verify_assertion(&assertion, &client_data_hash, &other_key),
        Err(AttestationError::Signature)
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
    let hashed_cd_hash: [u8; 32] = Sha256::digest(identity.cd_hash).into();
    assert_ne!(apple_app_id_hash(APP_ID), hashed_cd_hash);

    // register_apple would reject a changed key ID at the nonce check first, so
    // check the key-ID binding here. The ID follows the RP hash, flags, counter,
    // AAGUID and ID length.
    let mut object: BTreeMap<String, ciborium::Value> =
        ciborium::from_reader(credential.attestation.as_slice()).unwrap();
    object.get_mut("authData").unwrap().as_bytes_mut().unwrap()[55] ^= 1;
    let mut attestation = Vec::new();
    ciborium::into_writer(&object, &mut attestation).unwrap();
    assert_eq!(
        apple_credential_identity(&attestation),
        Err(AttestationError::Credential)
    );
}

#[test]
fn verifies_assertion_from_an_updated_allowlisted_cd_hash() {
    let signing_key = signing_key();
    let registered = registered(&signing_key);
    let rp_id_hash = apple_app_id_hash(APP_ID);
    let old_cd_hash = [1; 32];
    let updated_cd_hash = [2; 32];
    let policy = ApplePolicy::new(
        [APP_ID.to_string()].into(),
        Some([old_cd_hash, updated_cd_hash].into()),
    )
    .unwrap();
    let client_data_hash = [3; 32];
    let assertion = assertion(
        &signing_key,
        rp_id_hash,
        updated_cd_hash,
        1,
        &client_data_hash,
    );
    let claims = policy
        .verify_assertion(&assertion, &client_data_hash, &registered)
        .unwrap();

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
    let policy =
        ApplePolicy::new([APP_ID.to_string()].into(), Some([allowed_cd_hash].into())).unwrap();

    let wrong_app = assertion(
        &signing_key,
        apple_app_id_hash("OTHERTEAM.example.app"),
        allowed_cd_hash,
        1,
        &client_data_hash,
    );
    assert_eq!(
        policy.verify_assertion(&wrong_app, &client_data_hash, &registered),
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
        policy.verify_assertion(&denied_build, &client_data_hash, &registered),
        Err(AttestationError::Credential)
    );
}

#[test]
fn rejects_signed_assertion_that_omits_cd_hash_evidence() {
    let signing_key = signing_key();
    let registered = registered(&signing_key);
    let rp_id_hash = apple_app_id_hash(APP_ID);
    let client_data_hash = [3; 32];
    let policy = ApplePolicy::new([APP_ID.to_string()].into(), Some([[1; 32]].into())).unwrap();
    let mut authenticator_data = Vec::new();
    authenticator_data.extend_from_slice(&rp_id_hash);
    authenticator_data.push(0xc0);
    authenticator_data.extend_from_slice(&1_u32.to_be_bytes());
    let assertion = signed_assertion(&signing_key, authenticator_data, &client_data_hash);

    assert_eq!(
        policy.verify_assertion(&assertion, &client_data_hash, &registered),
        Err(AttestationError::AppleCdHashMissing)
    );
}

#[test]
fn rejects_credential_with_invalid_authenticator_flags() {
    let credential = fixture_credential(&fixture());
    let mut object: BTreeMap<String, ciborium::Value> =
        ciborium::from_reader(credential.attestation.as_slice()).unwrap();

    for flags in [0x00, 0x40, 0x80, 0xc1] {
        object.get_mut("authData").unwrap().as_bytes_mut().unwrap()[32] = flags;
        let mut attestation = Vec::new();
        ciborium::into_writer(&object, &mut attestation).unwrap();

        assert_eq!(
            apple_credential_identity(&attestation),
            Err(AttestationError::Credential)
        );
        assert_eq!(
            ApplePolicy::new([APP_ID.to_string()].into(), None)
                .unwrap()
                .register(
                    &AppleCredential {
                        attestation,
                        client_data_hash: credential.client_data_hash,
                    },
                    apple_app_attest_root_ca(),
                    AnchorTime(FIXTURE_VALIDATION_TIME),
                ),
            Err(AttestationError::Credential)
        );
    }
}

#[test]
fn rejects_signed_assertion_with_invalid_authenticator_flags() {
    let fixture = fixture();
    let signing_key = signing_key();
    let registered = registered(&signing_key);
    let client_data_hash = decode_hex_32(fixture.assertion_client_data_hash_hex);
    let assertion = decode_base64(fixture.assertion_object_base64);
    let mut object: BTreeMap<String, ByteBuf> =
        ciborium::from_reader(assertion.as_slice()).unwrap();
    let mut auth_data = object.remove("authenticatorData").unwrap().into_vec();
    let policy =
        ApplePolicy::new([APP_ID.to_string()].into(), Some([REAL_CD_HASH].into())).unwrap();

    for flags in [0x00, 0x40, 0x80, 0xc1] {
        auth_data[32] = flags;
        let assertion = signed_assertion(&signing_key, auth_data.clone(), &client_data_hash);

        assert_eq!(
            policy.verify_assertion(&assertion, &client_data_hash, &registered),
            Err(AttestationError::Binding)
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
    let policy = ApplePolicy::new([APP_ID.to_string()].into(), Some([cd_hash].into())).unwrap();
    let assertion = assertion(&signing_key, rp_id_hash, cd_hash, 2, &client_data_hash);

    let first = policy
        .verify_assertion(&assertion, &client_data_hash, &registered)
        .unwrap();
    let second = policy
        .verify_assertion(&assertion, &client_data_hash, &registered)
        .unwrap();

    assert_eq!(first, second);
    assert_eq!(second.counter, 2);
}
