use crate::model::grant::{ChannelClient, GrantJobAuthorizationV1, grant_work_id};
use crate::model::work::PrivateRecord as _;
use hellas_auth::authority::PrincipalId;
use hellas_auth::{Digest, ProducerSigningKey, PublicKey};
use hellas_kernel::NetworkId;
use hellas_rpc::*;

pub fn network() -> NetworkId {
    NetworkId::new("grants-fixture").unwrap()
}
/// A fixture principal and the node key of its device. The passkey seed is
/// disjoint from the node key seed, which also serves provider producer keys.
pub fn principal(seed: u8) -> (PrincipalId, ProducerSigningKey) {
    let principal =
        PrincipalId::from_public_key(PublicKey::P256(passkey(seed).party_key().to_bytes()))
            .unwrap();
    (
        principal,
        ProducerSigningKey::from_secret_bytes([seed; 32]).unwrap(),
    )
}
/// The node key of `principal(seed)`'s device.
pub fn node_key(seed: u8) -> hellas_auth::authority::NodeKey {
    hellas_auth::authority::NodeKey::from_public_key(principal(seed).1.public_key()).unwrap()
}
pub fn passkey(seed: u8) -> hellas_kernel::SoftPasskey {
    hellas_kernel::SoftPasskey::from_secret_scalar([0x80 | seed; 32]).unwrap()
}
/// Disjoint from the actors' node key seeds (0x61..=0x69).
const SEEDS: std::ops::RangeInclusive<u8> = 1..=0x5f;
const ACTORS: [hellas_auth::test_support::Actor; 9] = {
    use hellas_auth::test_support::actors::*;
    [
        ROOT,
        OPERATOR,
        FRIEND,
        AGENT,
        PROVIDER,
        STRANGER,
        RECOVERY_OWNER,
        SUCCESSOR,
        ATTACKER,
    ]
};
/// The passkey of a fixture subject: an auth actor or a `principal(seed)`.
pub fn passkey_of(subject: PrincipalId) -> hellas_kernel::SoftPasskey {
    ACTORS
        .into_iter()
        .find(|actor| actor.principal() == subject)
        .map(|actor| actor.passkey())
        .or_else(|| SEEDS.map(passkey).find(|p| principal_of(p) == subject))
        .expect("subject is a fixture principal")
}
/// The node key of a fixture subject's device.
pub fn device(subject: PrincipalId) -> ProducerSigningKey {
    ACTORS
        .into_iter()
        .find(|actor| actor.principal() == subject)
        .map(|actor| actor.node_key())
        .or_else(|| SEEDS.map(principal).find(|p| p.0 == subject).map(|p| p.1))
        .expect("subject is a fixture principal")
}
/// The fixture subject whose device holds `key`.
pub fn subject_of(key: &ProducerSigningKey) -> PrincipalId {
    ACTORS
        .into_iter()
        .find(|actor| actor.node_key().public_key() == key.public_key())
        .map(|actor| actor.principal())
        .or_else(|| {
            SEEDS
                .map(principal)
                .find(|p| p.1.public_key() == key.public_key())
                .map(|p| p.0)
        })
        .expect("key is a fixture device")
}
/// The channel a fixture subject's own device opens.
pub fn channel_client(subject: PrincipalId) -> ChannelClient {
    ChannelClient {
        principal: subject,
        node: hellas_auth::authority::NodeKey::from_public_key(device(subject).public_key())
            .unwrap(),
    }
}
/// Credentials in fixtures are held by their subject's own device.
pub fn holder(subject: PrincipalId) -> hellas_auth::authority::CredentialHolder {
    hellas_auth::authority::CredentialHolder::Node(
        hellas_auth::authority::NodeKey::from_public_key(device(subject).public_key()).unwrap(),
    )
}
fn principal_of(passkey: &hellas_kernel::SoftPasskey) -> PrincipalId {
    PrincipalId::from_public_key(PublicKey::P256(passkey.party_key().to_bytes())).unwrap()
}

/// A provider's self-attested enrollment whose node key is `[seed; 32]`, the
/// node key of `principal(seed)`'s device. Its software root has its own key.
pub fn software_enrollment(seed: u8, transport: [u8; 32]) -> ProviderEnrollmentBundle {
    let root = ProducerSigningKey::from_secret_bytes([0xc0 | seed; 32]).unwrap();
    let key = ProducerSigningKey::from_secret_bytes([seed; 32]).unwrap();
    enrollment(&root, &key, transport, [seed; 32])
}

/// Keep root, producer, transport and installation identities independent in fixtures.
pub fn enrollment(
    root: &ProducerSigningKey,
    producer: &ProducerSigningKey,
    transport: [u8; 32],
    nonce: [u8; 32],
) -> ProviderEnrollmentBundle {
    let statement = ProviderGenesisStatement {
        root_kind: RootKind::Software,
        root_public_key: root.public_key(),
        producer_public_key: producer.public_key(),
        transport_public_key: PublicKey::Ed25519(transport),
        platform_credential: PlatformCredential::Absent,
        installation_nonce: nonce,
    };
    let proof = root
        .sign_digest(Digest::hash(&statement.canonical_bytes()))
        .unwrap();
    ProviderEnrollmentBundle {
        genesis: SignedProviderGenesis {
            statement,
            root_proof: RootProof::Software(proof),
        },
        platform: PlatformEnrollment::Absent,
    }
}

/// Every file under `root`, so a privacy scan also reads a database's
/// `-wal` and `-shm` companions.
pub fn all_files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            paths.extend(all_files(&path));
        } else {
            paths.push(path);
        }
    }
    paths
}

pub fn test_responses_contract() -> hellas_rpc::FetchContract {
    hellas_rpc::FetchContract::new(
        "openai-responses-0.0.2",
        hellas_rpc::FetchSchema::StatelessResponsesV1,
        "openai-responses-driver-0.0.1",
        hellas_rpc::FetchEgress::FixedHttps("https://api.openai.com/v1/responses".into()),
    )
    .unwrap()
}

/// Turns a fixture's locally held input body into signed upload RPCs and a
/// reference-only acceptance. Provider handlers never receive the body inline.
pub fn grant_upload_requests(
    request: &hellas_rpc::pb::work::AcceptWorkRequest,
    signer: &ProducerSigningKey,
    network: NetworkId,
    exporter: [u8; 32],
) -> (
    hellas_rpc::pb::work::AcceptWorkRequest,
    Vec<hellas_rpc::pb::work::UploadContentRequest>,
) {
    use hellas_rpc::protocol::content_upload::{
        CONTENT_CHUNK_BYTES, chunk_digest, encode_reference,
    };
    let mut wire = request.clone();
    let Ok(a) = GrantJobAuthorizationV1::decode(&request.authorization) else {
        return (wire, Vec::new());
    };
    if request.prepared_input.is_empty() {
        return (wire, Vec::new());
    }
    let reference = ContentRef::new(
        ContentId::hash(&request.prepared_input),
        request.prepared_input.len() as u64,
    );
    wire.prepared_input = encode_reference(reference);
    let work = grant_work_id(network, &a);
    let chunks = request
        .prepared_input
        .chunks(CONTENT_CHUNK_BYTES)
        .enumerate()
        .map(|(index, chunk)| {
            let offset = (index * CONTENT_CHUNK_BYTES) as u64;
            let signature = signer
                .sign_digest(chunk_digest(
                    a.channel_id.0,
                    work,
                    reference,
                    offset,
                    chunk,
                    &exporter,
                ))
                .unwrap();
            hellas_rpc::pb::work::UploadContentRequest {
                route: wire.route.clone(),
                authorization: wire.authorization.clone(),
                client_signature: wire.client_signature.clone(),
                content_id: reference.id().as_bytes().to_vec(),
                total_bytes: reference.bytes(),
                offset,
                chunk: chunk.to_vec(),
                chunk_signature: signature.bytes().to_vec(),
            }
        })
        .collect();
    (wire, chunks)
}

pub fn upload_failure(
    response: Result<hellas_rpc::pb::work::UploadContentResponse, hellas_wire::WireStatus>,
) -> Option<hellas_rpc::pb::work::AcceptWorkResponse> {
    use hellas_rpc::pb::work::{
        AcceptWorkResponse, WorkRefusalCode, WorkRefused, accept_work_response,
    };
    let refusal = match response {
        Ok(response) => response.refused?,
        Err(error) => WorkRefused {
            code: WorkRefusalCode::Unavailable as i32,
            reason: error.to_string(),
            grant: None,
        },
    };
    Some(AcceptWorkResponse {
        outcome: Some(accept_work_response::Outcome::Refused(refusal)),
    })
}
pub mod backend;
pub mod channel;
pub mod transport;
pub use hellas_auth::{
    assert_err,
    test_support::{Actor, Rights, actors},
};
