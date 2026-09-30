//! Chain identity bridge.
//!
//! [`kernel_signer`] is the identity bridge: the provider's on-chain
//! party key IS its RPC producer identity, one secp256k1 scalar read
//! through two primitive crates.

use hellas_kernel::Secp256k1Signer;
use hellas_rpc::ProducerSigningKey;

/// Kernel signer sharing the producer identity's secp256k1 scalar: the
/// provider's on-chain party key IS its RPC identity.
///
/// Same curve, same 32-byte scalar, same 33-byte compressed public key
/// and 64-byte low-S compact signature — only the primitive crate
/// differs (k256 here, libsecp256k1 in the kernel), and the wire bytes
/// are interoperable.
#[must_use]
pub fn kernel_signer(producer: &ProducerSigningKey) -> Secp256k1Signer {
    Secp256k1Signer::from_secret_scalar(producer.to_secret_bytes())
        .expect("producer keys are valid secp256k1 scalars")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hellas_rpc::PublicKey;

    #[test]
    fn kernel_signer_shares_the_producer_identity() {
        let producer = ProducerSigningKey::from_secret_bytes([7; 32])
            .expect("non-zero scalar is a valid producer key");
        let signer = kernel_signer(&producer);
        let PublicKey::Secp256k1(compressed) = producer.public_key() else {
            panic!("producer keys are secp256k1");
        };
        assert_eq!(signer.party_key().as_bytes(), &compressed);
    }
}
