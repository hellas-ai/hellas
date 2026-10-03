use std::collections::BTreeMap;
use std::io::Cursor;
use std::sync::OnceLock;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hellas_rpc::pb::execute::AssuranceEvidence;
use hellas_rpc::{APPLE_APP_ATTEST, ContentId, DagCborEncoder};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use rustls_pki_types::{CertificateDer, UnixTime};
use serde::Deserialize;
use serde_bytes::ByteBuf;
use sha2::{Digest as _, Sha256};
use webpki::{EndEntityCert, KeyUsage, anchor_from_trusted_cert, ring};
use x509_cert::Certificate;
use x509_cert::der::Decode;

use crate::{AnchorTime, AttestationError, Binding};

const APP_ATTEST_EKU: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x04, 0x18];
const APP_ATTEST_EKU_DER: &[u8] = &[
    0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x63, 0x64, 0x04, 0x18,
];
const NONCE_OID: &str = "1.2.840.113635.100.8.2";
const PLATFORM_OID: &str = "1.2.840.113635.100.8.7";
const ACL_OID: &str = "1.2.840.113635.100.8.6";
const ACL: &[u8] = &[
    0x30, 0x46, 0xa3, 0x44, 0x04, 0x42, 0x30, 0x40, 0x0c, 0x02, 0x31, 0x31, 0x30, 0x3a, 0x30, 0x09,
    0x0c, 0x02, 0x6f, 0x6b, 0xa1, 0x03, 0x01, 0x01, 0xff, 0x30, 0x09, 0x0c, 0x02, 0x6f, 0x61, 0xa1,
    0x03, 0x01, 0x01, 0xff, 0x30, 0x0b, 0x0c, 0x04, 0x6f, 0x64, 0x65, 0x6c, 0xa1, 0x03, 0x01, 0x01,
    0xff, 0x30, 0x15, 0x0c, 0x04, 0x6f, 0x73, 0x67, 0x6e, 0xa0, 0x06, 0x0c, 0x04, 0x72, 0x73, 0x65,
    0x63, 0x30, 0x05, 0xa6, 0x03, 0x02, 0x01, 0x01,
];
const PRODUCTION_AAGUID: &[u8; 16] = b"appattest\0\0\0\0\0\0\0";
const APP_ATTEST_ROOT_CA_BASE64: &str = "MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYwJAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNaFw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlvbiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdhNbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9auYen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijVoyFraWVIyd/dganmrduC1bmTBGwD";

/// Apple's pinned App Attestation Root CA in DER form.
pub fn apple_app_attest_root_ca() -> &'static [u8] {
    static ROOT: OnceLock<Vec<u8>> = OnceLock::new();
    ROOT.get_or_init(|| {
        STANDARD
            .decode(APP_ATTEST_ROOT_CA_BASE64)
            .expect("embedded Apple App Attestation Root CA is valid base64")
    })
}

/// Compute the WebAuthn RP-ID hash for the pinned Apple application identity.
pub fn apple_app_id_hash(team_id_and_bundle_id: &str) -> [u8; 32] {
    Sha256::digest(team_id_and_bundle_id.as_bytes()).into()
}

/// Apple App Attest's `clientDataHash` for protocol-owned statement bytes.
pub fn apple_client_data_hash(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub struct AppleCredential {
    pub attestation: Vec<u8>,
    pub client_data_hash: [u8; 32],
}

impl AppleCredential {
    pub fn content_id(&self) -> ContentId {
        let mut e = DagCborEncoder::new();
        e.array(3);
        e.str("hellas.apple.app-attest.credential.v1");
        e.bytes(&self.attestation);
        e.bytes(&self.client_data_hash);
        ContentId::hash(&e.into_bytes())
    }
}

/// The persistable output of one successful Apple credential registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegisteredAppleCredential {
    pub id: ContentId,
    pub public_key: [u8; 33],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppleCredentialIdentity {
    pub public_key: [u8; 33],
    pub rp_id_hash: [u8; 32],
    pub cd_hash: [u8; 32],
}

/// Persistent high-water-mark port for live Apple assertion counters.
pub trait AssertionCounterStore {
    fn advance(&self, public_key: &[u8; 33], counter: u32) -> Result<(), AttestationError>;
}

/// A provisioned app instance on a Full-Security/SIP Mac endorsed the statement.
/// This does not prove that the computation was performed or performed correctly.
#[derive(Debug, PartialEq, Eq)]
pub struct AppleClaims {
    pub cd_hash: [u8; 32],
    pub counter: u32,
}

pub struct ApplePolicy {
    pub expected_rp_id_hash: [u8; 32],
    pub allowed_cd_hashes: Vec<[u8; 32]>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AppleVerdict {
    Accepted,
    CodeDenied,
}

pub fn appraise_apple(claims: &AppleClaims, policy: &ApplePolicy) -> AppleVerdict {
    if policy.allowed_cd_hashes.contains(&claims.cd_hash) {
        AppleVerdict::Accepted
    } else {
        AppleVerdict::CodeDenied
    }
}

pub fn register_apple(
    credential: &AppleCredential,
    expected_rp_id_hash: [u8; 32],
    root: &[u8],
    anchor: AnchorTime,
) -> Result<RegisteredAppleCredential, AttestationError> {
    let object: AttestationObject = cbor(&credential.attestation, "Apple attestation")?;
    if object.fmt != "apple-appattest" || object.statement.certificates.len() != 2 {
        return Err(AttestationError::Credential);
    }
    let leaf = verify_chain(&object.statement.certificates, root, anchor)?;
    let auth = attestation_auth_data(&object.auth_data, expected_rp_id_hash)?;
    let extensions = leaf
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or(AttestationError::Credential)?;
    let extension = |oid: &str| {
        extensions
            .iter()
            .find(|extension| extension.extn_id.to_string() == oid)
            .map(|extension| extension.extn_value.as_bytes())
            .ok_or(AttestationError::Credential)
    };
    if extension(ACL_OID)? != ACL || !extension(PLATFORM_OID)?.ends_with(b"\x04\x06macosx") {
        return Err(AttestationError::Credential);
    }
    let nonce =
        Sha256::digest([object.auth_data.as_slice(), &credential.client_data_hash].concat());
    let nonce_extension = extension(NONCE_OID)?;
    if nonce_extension.len() != 38
        || nonce_extension[..6] != [0x30, 0x24, 0xa1, 0x22, 0x04, 0x20]
        || nonce_extension[6..] != nonce[..]
    {
        return Err(AttestationError::Credential);
    }
    let compressed = public_key(&leaf, auth.credential_id)?;
    Ok(RegisteredAppleCredential {
        id: credential.content_id(),
        public_key: compressed,
    })
}

pub fn apple_credential_identity(
    attestation: &[u8],
) -> Result<AppleCredentialIdentity, AttestationError> {
    let object: AttestationObject = cbor(attestation, "Apple attestation")?;
    let rp_id_hash = object
        .auth_data
        .get(..32)
        .and_then(|value| value.try_into().ok())
        .ok_or(AttestationError::Credential)?;
    let auth = attestation_auth_data(&object.auth_data, rp_id_hash)?;
    let leaf = object
        .statement
        .certificates
        .first()
        .ok_or(AttestationError::Credential)?;
    let leaf = Certificate::from_der(leaf).map_err(|_| AttestationError::Credential)?;
    let cd_hash = attestation_cd_hash(auth.credential_data)?;
    Ok(AppleCredentialIdentity {
        public_key: public_key(&leaf, auth.credential_id)?,
        rp_id_hash,
        cd_hash,
    })
}

fn attestation_cd_hash(credential_data: &[u8]) -> Result<[u8; 32], AttestationError> {
    let mut cursor = Cursor::new(credential_data);
    let _: ciborium::Value = ciborium::from_reader(&mut cursor)
        .map_err(|_| AttestationError::Malformed("Apple credential public key"))?;
    let extensions = credential_data
        .get(cursor.position() as usize..)
        .ok_or(AttestationError::Credential)?;
    apple_cd_hash(extensions, "Apple attestation extensions")
}

fn public_key(
    certificate: &Certificate,
    credential_id: &[u8],
) -> Result<[u8; 33], AttestationError> {
    let public_key = certificate
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or(AttestationError::Credential)?;
    if Sha256::digest(public_key).as_slice() != credential_id {
        return Err(AttestationError::Credential);
    }
    let key =
        VerifyingKey::from_sec1_bytes(public_key).map_err(|_| AttestationError::Credential)?;
    key.to_sec1_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| AttestationError::Credential)
}

pub fn verify_apple(
    evidence: &AssuranceEvidence,
    expected: Binding,
    credential: &RegisteredAppleCredential,
    policy: &ApplePolicy,
    counters: &dyn AssertionCounterStore,
) -> Result<AppleClaims, AttestationError> {
    if evidence.codec != APPLE_APP_ATTEST {
        return Err(AttestationError::Codec);
    }
    if evidence.credential != credential.id.as_bytes() {
        return Err(AttestationError::Credential);
    }
    let claims = verify_apple_assertion(&evidence.proof, expected.as_bytes(), credential, policy)?;
    counters.advance(&credential.public_key, claims.counter)?;
    Ok(claims)
}

pub fn verify_apple_assertion(
    assertion: &[u8],
    client_data_hash: &[u8; 32],
    credential: &RegisteredAppleCredential,
    policy: &ApplePolicy,
) -> Result<AppleClaims, AttestationError> {
    let assertion: Assertion = cbor(assertion, "Apple assertion")?;
    let rp_id_hash = assertion
        .authenticator_data
        .get(..32)
        .ok_or(AttestationError::Binding)?;
    if rp_id_hash != policy.expected_rp_id_hash {
        return Err(AttestationError::Binding);
    }
    let signature =
        Signature::from_der(&assertion.signature).map_err(|_| AttestationError::Signature)?;
    let key = VerifyingKey::from_sec1_bytes(&credential.public_key)
        .map_err(|_| AttestationError::Credential)?;
    let digest =
        Sha256::digest([assertion.authenticator_data.as_slice(), client_data_hash].concat());
    key.verify(&digest, &signature)
        .map_err(|_| AttestationError::Signature)?;
    let claims = assertion_auth_data(&assertion.authenticator_data)?;
    if !policy.allowed_cd_hashes.contains(&claims.cd_hash) {
        return Err(AttestationError::Credential);
    }
    Ok(claims)
}

fn verify_chain(
    certificates: &[ByteBuf],
    root: &[u8],
    anchor: AnchorTime,
) -> Result<Certificate, AttestationError> {
    let leaf = CertificateDer::from(certificates[0].as_ref());
    let intermediate = CertificateDer::from(certificates[1].as_ref());
    let root = CertificateDer::from(root);
    let end = EndEntityCert::try_from(&leaf).map_err(|_| AttestationError::Credential)?;
    let anchors = [anchor_from_trusted_cert(&root).map_err(|_| AttestationError::Credential)?];
    let intermediates = [intermediate];
    #[allow(deprecated)]
    let algorithms = [
        ring::ECDSA_P256_SHA256,
        ring::ECDSA_P384_SHA256,
        ring::ECDSA_P384_SHA384,
    ];
    end.verify_for_usage(
        &algorithms,
        &anchors,
        &intermediates,
        UnixTime::since_unix_epoch(Duration::from_secs(anchor.0)),
        KeyUsage::required_if_present(APP_ATTEST_EKU),
        None,
        None,
    )
    .map_err(|_| AttestationError::Credential)?;
    let leaf = Certificate::from_der(&certificates[0]).map_err(|_| AttestationError::Credential)?;
    let eku = leaf
        .tbs_certificate
        .extensions
        .as_ref()
        .and_then(|extensions| {
            extensions
                .iter()
                .find(|extension| extension.extn_id.to_string() == "2.5.29.37")
        })
        .ok_or(AttestationError::Credential)?;
    if eku.extn_value.as_bytes() != APP_ATTEST_EKU_DER {
        return Err(AttestationError::Credential);
    }
    Ok(leaf)
}

struct AttestationAuth<'a> {
    credential_id: &'a [u8],
    credential_data: &'a [u8],
}

fn attestation_auth_data(
    data: &[u8],
    rp_id_hash: [u8; 32],
) -> Result<AttestationAuth<'_>, AttestationError> {
    if data.len() < 55
        || data[..32] != rp_id_hash
        || !valid_auth_flags(data[32])
        || data[33..37] != [0; 4]
    {
        return Err(AttestationError::Credential);
    }
    if data[37..53] != *PRODUCTION_AAGUID {
        return Err(AttestationError::Credential);
    }
    let credential_len = u16::from_be_bytes([data[53], data[54]]) as usize;
    let credential_end = 55_usize
        .checked_add(credential_len)
        .ok_or(AttestationError::Credential)?;
    let credential_id = data
        .get(55..credential_end)
        .ok_or(AttestationError::Credential)?;
    if credential_id.len() != 32 {
        return Err(AttestationError::Credential);
    }
    Ok(AttestationAuth {
        credential_id,
        credential_data: &data[credential_end..],
    })
}

fn assertion_auth_data(data: &[u8]) -> Result<AppleClaims, AttestationError> {
    if data.len() < 37 || !valid_auth_flags(data[32]) {
        return Err(AttestationError::Binding);
    }
    let cd_hash = apple_cd_hash(&data[37..], "Apple authenticator extensions")?;
    Ok(AppleClaims {
        cd_hash,
        counter: u32::from_be_bytes(data[33..37].try_into().unwrap()),
    })
}

fn valid_auth_flags(flags: u8) -> bool {
    // Current macOS evidence sets the extensions bit; early seeds omitted it.
    matches!(flags, 0x40 | 0xc0)
}

fn apple_cd_hash(bytes: &[u8], name: &'static str) -> Result<[u8; 32], AttestationError> {
    if bytes.is_empty() {
        return Err(AttestationError::AppleCdHashMissing);
    }
    let extensions: BTreeMap<String, ByteBuf> = cbor(bytes, name)?;
    let cd_hash: [u8; 32] = extensions
        .get("apple_cd_hash_hash_01")
        .and_then(|value| value.as_ref().try_into().ok())
        .ok_or(AttestationError::AppleCdHashMissing)?;
    if extensions.get("apple_cd_hash_type_01").map(ByteBuf::as_ref) != Some(&[2])
        || extensions
            .get("apple_validation_category_01")
            .map(ByteBuf::as_ref)
            != Some(&[6, 0, 0, 0])
    {
        return Err(AttestationError::Credential);
    }
    Ok(cd_hash)
}

fn cbor<T: for<'de> Deserialize<'de>>(
    bytes: &[u8],
    name: &'static str,
) -> Result<T, AttestationError> {
    let mut cursor = Cursor::new(bytes);
    let value =
        ciborium::from_reader(&mut cursor).map_err(|_| AttestationError::Malformed(name))?;
    if cursor.position() as usize != bytes.len() {
        return Err(AttestationError::Malformed(name));
    }
    Ok(value)
}

#[derive(Deserialize)]
struct AttestationObject {
    fmt: String,
    #[serde(rename = "attStmt")]
    statement: AttestationStatement,
    #[serde(rename = "authData")]
    auth_data: ByteBuf,
}

#[derive(Deserialize)]
struct AttestationStatement {
    #[serde(rename = "x5c")]
    certificates: Vec<ByteBuf>,
}

#[derive(Deserialize)]
struct Assertion {
    #[serde(rename = "authenticatorData")]
    authenticator_data: ByteBuf,
    signature: ByteBuf,
}

/// Verify the reusable provider genesis assertion under an already registered
/// Apple credential. Enrollment assertions never advance the live Open counter.
pub fn verify_apple_provider_genesis(
    genesis: &hellas_rpc::SignedProviderGenesis,
    credential: &RegisteredAppleCredential,
    policy: &ApplePolicy,
) -> Result<(), AttestationError> {
    use hellas_rpc::{PlatformCredential, PublicKey, RootKind, RootProof};
    let statement = &genesis.statement;
    if statement.root_kind != RootKind::SecureEnclave
        || statement.platform_credential != PlatformCredential::Registered(credential.id)
        || statement.root_public_key != PublicKey::P256(credential.public_key)
    {
        return Err(AttestationError::Credential);
    }
    let RootProof::AppleAppAttest(assertion) = &genesis.root_proof else {
        return Err(AttestationError::Codec);
    };
    verify_apple_assertion(
        assertion,
        &apple_client_data_hash(&statement.canonical_bytes()),
        credential,
        policy,
    )?;
    Ok(())
}
