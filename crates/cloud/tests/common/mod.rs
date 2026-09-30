use hellas_rpc::*;

pub fn bundle(transport: &iroh::SecretKey) -> ProviderEnrollmentBundle {
    let key = ProducerSigningKey::from_secret_bytes([7; 32]).unwrap();
    let statement = ProviderGenesisStatement {
        root_kind: RootKind::Software,
        root_public_key: key.public_key(),
        producer_public_key: key.public_key(),
        transport_public_key: PublicKey::Ed25519(*transport.public().as_bytes()),
        platform_credential: PlatformCredential::Absent,
        installation_nonce: [7; 32],
    };
    let proof = key
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
