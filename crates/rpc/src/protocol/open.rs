use crate::ContentId;
use hellas_auth::{Digest, PublicKey, hash_tuple};

pub const OPEN_PROOF_DOMAIN: &str = "hellas.attest.open.proof.v1";
pub const OPEN_PROVIDER_ROLE: &[u8] = b"provider";
pub const OPEN_NONCE_LEN: usize = 32;
pub const OPEN_EXPORTER_LEN: usize = 32;

/// The statement authenticated by a provider's confidential-open proof.
/// Every variable-length field is length-delimited by `hash_tuple`.
pub fn open_proof_binding(
    exporter: &[u8; OPEN_EXPORTER_LEN],
    requester_nonce: &[u8; OPEN_NONCE_LEN],
    producer_public_key: &PublicKey,
    provider_genesis: ContentId,
    alpn: &[u8],
) -> Digest {
    let key_kind = [producer_public_key.kind().to_byte()];
    hash_tuple(
        OPEN_PROOF_DOMAIN,
        &[
            exporter,
            requester_nonce,
            &key_kind,
            producer_public_key.bytes(),
            provider_genesis.as_bytes(),
            alpn,
            OPEN_PROVIDER_ROLE,
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exporter_changes_binding() {
        let key = PublicKey::Secp256k1([2; 33]);
        let genesis = ContentId::from_bytes([3; 32]);
        assert_ne!(
            open_proof_binding(&[4; 32], &[5; 32], &key, genesis, b"/service/2.0"),
            open_proof_binding(&[6; 32], &[5; 32], &key, genesis, b"/service/2.0"),
        );
    }
}
