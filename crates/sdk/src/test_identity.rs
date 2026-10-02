use hellas_rpc::{
    Digest, PlatformCredential, PlatformEnrollment, ProducerSigningKey, ProviderEnrollmentBundle,
    ProviderGenesisStatement, PublicKey, RootKind, RootProof, SignedProviderGenesis,
};
use iroh::EndpointId;

pub(crate) fn enrollment(peer: EndpointId) -> (ProviderEnrollmentBundle, ProducerSigningKey) {
    let root = ProducerSigningKey::from_secret_bytes([1; 32]).unwrap();
    let producer = ProducerSigningKey::from_secret_bytes([2; 32]).unwrap();
    let statement = ProviderGenesisStatement {
        root_kind: RootKind::Software,
        root_public_key: root.public_key(),
        producer_public_key: producer.public_key(),
        transport_public_key: PublicKey::Ed25519(*peer.as_bytes()),
        platform_credential: PlatformCredential::Absent,
        installation_nonce: [3; 32],
    };
    let proof = root
        .sign_digest(Digest::hash(&statement.canonical_bytes()))
        .unwrap();
    (
        ProviderEnrollmentBundle {
            genesis: SignedProviderGenesis {
                statement,
                root_proof: RootProof::Software(proof),
            },
            platform: PlatformEnrollment::Absent,
        },
        producer,
    )
}
