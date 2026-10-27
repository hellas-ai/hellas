use hellas_auth::ProducerSigningKey;
use hellas_rpc::ProviderEnrollmentBundle;
use iroh::EndpointId;

pub(crate) struct OpenProof(pub ProviderEnrollmentBundle, pub ProducerSigningKey);
impl hellas_rpc::open::OpenHandler for OpenProof {
    async fn open(
        &self,
        request: hellas_rpc::pb::execute::OpenRequest,
        context: hellas_wire::TransportContext,
        alpn: &'static [u8],
    ) -> Result<hellas_rpc::pb::execute::OpenResponse, hellas_wire::WireStatus> {
        let nonce: [u8; 32] = request.nonce.try_into().unwrap();
        let binding = hellas_rpc::open_proof_binding(
            &context.open_exporter.unwrap(),
            &nonce,
            &self.1.public_key(),
            self.0.content_id(),
            alpn,
        );
        Ok(hellas_rpc::pb::execute::OpenResponse {
            provider_genesis: self.0.canonical_bytes(),
            proof: Some(
                hellas_rpc::pb::execute::open_response::Proof::ProducerSignature(
                    hellas_rpc::signature_wire::signature_to_pb(
                        &self.1.sign_digest(binding).unwrap(),
                    ),
                ),
            ),
        })
    }
}

pub(crate) fn enrollment(peer: EndpointId) -> (ProviderEnrollmentBundle, ProducerSigningKey) {
    let root = ProducerSigningKey::from_secret_bytes([1; 32]).unwrap();
    let producer = ProducerSigningKey::from_secret_bytes([2; 32]).unwrap();
    (
        hellas_channel::test_support::enrollment(&root, &producer, *peer.as_bytes(), [3; 32]),
        producer,
    )
}
