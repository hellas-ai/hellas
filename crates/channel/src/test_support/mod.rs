use crate::model::grant::{ChannelClient, GrantJobAuthorizationV1};
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

/// Encode real generic Content frames for a fixture's already signed opening.
pub fn upload_frames(
    wire: &hellas_rpc::pb::work::AcceptWorkRequest,
    manifest: Vec<u8>,
    root: Vec<u8>,
    input: &[u8],
    sign: impl FnOnce(&hellas_rpc::pb::content::WorkOpening) -> Vec<u8>,
) -> Vec<hellas_rpc::pb::content::UploadRequest> {
    use hellas_rpc::pb::content as pb;
    use prost::Message;
    let root_ref = (!root.is_empty()).then(|| ContentRef::for_bytes(&root));
    let wire_ref = |object: ContentRef| pb::ContentRef {
        id: object.id().as_bytes().to_vec(),
        bytes: object.bytes(),
    };
    let mut opening = pb::WorkOpening {
        signed_opening: wire.encode_to_vec(),
        manifest,
        root: root_ref.map(wire_ref),
        binding_signature: vec![],
    };
    opening.binding_signature = sign(&opening);
    let mut frames = Vec::new();
    for bytes in root_ref.map(|_| root.as_slice()).into_iter().chain([input]) {
        let reference = ContentRef::for_bytes(bytes);
        frames.push(pb::UploadRequest {
            part: Some(pb::upload_request::Part::Open(pb::UploadOpen {
                object: Some(wire_ref(reference)),
                pin: None,
                work: (frames.is_empty()).then(|| opening.clone()),
            })),
        });
        let chunks = hellas_xet::chunk(bytes);
        let mut cursor = hellas_store::content::Cursor::default();
        loop {
            let page = hellas_store::content::chunk_page(reference, &chunks, cursor).unwrap();
            frames.push(pb::UploadRequest {
                part: Some(pb::upload_request::Part::List(pb::ChunkList {
                    chunks: page
                        .chunks
                        .iter()
                        .map(|chunk| pb::Chunk {
                            hash: chunk.hash.as_bytes().to_vec(),
                            bytes: chunk.data_len,
                        })
                        .collect(),
                    complete: page.next.is_none(),
                })),
            });
            match page.next {
                Some(next) => cursor = next,
                None => break,
            }
        }
        let mut offset = 0;
        for chunk in chunks {
            let end = offset + chunk.data_len as usize;
            frames.push(pb::UploadRequest {
                part: Some(pb::upload_request::Part::Chunk(bytes[offset..end].to_vec())),
            });
            offset = end;
        }
    }
    frames
}

pub fn grant_upload_requests(
    request: &hellas_rpc::pb::work::AcceptWorkRequest,
    signer: &ProducerSigningKey,
    _network: NetworkId,
    exporter: [u8; 32],
) -> (
    hellas_rpc::pb::work::AcceptWorkRequest,
    Vec<hellas_rpc::pb::content::UploadRequest>,
) {
    let mut wire = request.clone();
    if GrantJobAuthorizationV1::decode(&request.authorization).is_err() {
        return (wire, vec![]);
    }
    let Ok(input) = hellas_rpc::protocol::invocation::PreparedInvocation::from_canonical_bytes(
        &request.prepared_input,
        crate::content::MAX_CONTENT_BYTES,
    ) else {
        return (wire, vec![]);
    };
    wire.prepared_input = hellas_rpc::protocol::content::encode_reference(ContentRef::for_bytes(
        &request.prepared_input,
    ));
    let frames = upload_frames(
        &wire,
        input.manifest().unwrap().canonical_bytes(),
        channel::program_root(&input),
        &request.prepared_input,
        |opening| {
            signer
                .sign_digest(crate::job::opening_digest(opening, &exporter))
                .unwrap()
                .bytes()
                .to_vec()
        },
    );
    (wire, frames)
}

pub async fn drive_upload(
    response: Result<
        hellas_rpc::call::ResponseStream<hellas_rpc::pb::content::UploadResponse>,
        hellas_wire::WireStatus,
    >,
) -> Result<(), hellas_wire::WireStatus> {
    use futures::StreamExt;
    let mut response = response?;
    while let Some(progress) = response.next().await {
        progress?;
    }
    Ok(())
}

pub fn upload_failure(
    response: Result<(), hellas_wire::WireStatus>,
) -> Option<hellas_rpc::pb::work::AcceptWorkResponse> {
    use hellas_rpc::pb::work::{
        AcceptWorkResponse, WorkRefusalCode, WorkRefused, accept_work_response,
    };
    response.err().map(|error| AcceptWorkResponse {
        outcome: Some(accept_work_response::Outcome::Refused(WorkRefused {
            code: WorkRefusalCode::Unavailable as i32,
            reason: error.to_string(),
            grant: None,
        })),
    })
}
pub mod backend;
pub mod channel;
pub mod transport;
pub use hellas_auth::{
    assert_err,
    test_support::{Actor, Rights, actors},
};
