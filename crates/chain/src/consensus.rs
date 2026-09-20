#[cfg(any(feature = "indexer", feature = "validator"))]
mod full {
    use crate::domain::{Scheme, ThresholdVariant};
    use crate::{CONSENSUS_NAMESPACE, ConsensusInfo, LatestBlock, QueryError};
    use commonware_codec::{Decode, DecodeExt};
    use commonware_consensus::simplex::types::Finalization as SimplexFinalization;
    use commonware_cryptography::{certificate::Verifier as _, sha256::Digest};
    use commonware_parallel::Sequential;
    use thiserror::Error;

    pub type Finalization = SimplexFinalization<Scheme, Digest>;

    type ConsensusIdentity = <ThresholdVariant as commonware_cryptography::bls12381::primitives::variant::Variant>::Public;

    #[derive(Debug, Clone, PartialEq, Eq, Error)]
    pub enum ConsensusVerificationError {
        #[error("threshold identity was empty")]
        EmptyThresholdIdentity,
        #[error("invalid threshold identity")]
        InvalidThresholdIdentity,
        #[error("invalid finalization")]
        InvalidFinalization,
        #[error("finalization payload mismatch")]
        PayloadMismatch,
        #[error("finalization verification failed")]
        VerificationFailed,
    }

    impl From<ConsensusVerificationError> for QueryError {
        fn from(err: ConsensusVerificationError) -> Self {
            Self::Remote(err.to_string())
        }
    }

    #[derive(Clone)]
    pub struct ConsensusVerifier {
        scheme: Scheme,
    }

    impl ConsensusVerifier {
        pub fn new(info: &ConsensusInfo) -> Result<Self, ConsensusVerificationError> {
            if info.threshold_identity.is_empty() {
                return Err(ConsensusVerificationError::EmptyThresholdIdentity);
            }
            let identity = ConsensusIdentity::decode(info.threshold_identity.as_slice())
                .map_err(|_| ConsensusVerificationError::InvalidThresholdIdentity)?;
            Ok(Self {
                scheme: Scheme::certificate_verifier(CONSENSUS_NAMESPACE, identity),
            })
        }

        pub const fn scheme(&self) -> &Scheme {
            &self.scheme
        }

        pub fn decode_finalization(
            encoded: &[u8],
        ) -> Result<Finalization, ConsensusVerificationError> {
            Finalization::decode_cfg(encoded, &Scheme::certificate_codec_config_unbounded())
                .map_err(|_| ConsensusVerificationError::InvalidFinalization)
        }

        pub fn verify_finalization(
            &self,
            finalization: &Finalization,
            expected_payload: Digest,
        ) -> Result<(), ConsensusVerificationError> {
            if finalization.proposal.payload != expected_payload {
                return Err(ConsensusVerificationError::PayloadMismatch);
            }
            let mut rng = rand::rng();
            if !finalization.verify(&mut rng, &self.scheme, &Sequential) {
                return Err(ConsensusVerificationError::VerificationFailed);
            }
            Ok(())
        }

        pub fn verify_snapshot(
            &self,
            snapshot: &LatestBlock,
        ) -> Result<(), ConsensusVerificationError> {
            crate::finality_proof::FinalityProof::decode(&snapshot.finalization)?
                .verify(self, snapshot)
        }
    }
}

#[cfg(not(any(feature = "indexer", feature = "validator")))]
mod light {
    use crate::{CONSENSUS_NAMESPACE, ConsensusInfo, LatestBlock, QueryError};
    use commonware_codec::{DecodeExt, ReadExt, Write, varint::UInt};
    use commonware_cryptography::{
        bls12381::primitives::{
            ops::batch,
            variant::{MinPk as ThresholdVariant, Variant},
        },
        sha256::Digest,
    };
    use commonware_parallel::Sequential;
    use thiserror::Error;

    type ConsensusIdentity = <ThresholdVariant as Variant>::Public;
    type ThresholdSignature = <ThresholdVariant as Variant>::Signature;

    #[derive(Debug, Clone, PartialEq, Eq, Error)]
    pub enum ConsensusVerificationError {
        #[error("threshold identity was empty")]
        EmptyThresholdIdentity,
        #[error("invalid threshold identity")]
        InvalidThresholdIdentity,
        #[error("invalid finalization")]
        InvalidFinalization,
        #[error("finalization payload mismatch")]
        PayloadMismatch,
        #[error("finalization verification failed")]
        VerificationFailed,
    }

    impl From<ConsensusVerificationError> for QueryError {
        fn from(err: ConsensusVerificationError) -> Self {
            Self::Remote(err.to_string())
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct Round {
        pub epoch: u64,
        pub view: u64,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct Proposal {
        pub round: Round,
        pub parent: u64,
        pub payload: Digest,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct Certificate {
        pub vote_signature: ThresholdSignature,
        pub seed_signature: ThresholdSignature,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct Finalization {
        pub proposal: Proposal,
        pub certificate: Certificate,
    }

    impl Finalization {
        pub const fn round(&self) -> Round {
            self.proposal.round
        }
    }

    #[derive(Clone)]
    pub struct ConsensusVerifier {
        identity: ConsensusIdentity,
    }

    impl ConsensusVerifier {
        pub fn new(info: &ConsensusInfo) -> Result<Self, ConsensusVerificationError> {
            if info.threshold_identity.is_empty() {
                return Err(ConsensusVerificationError::EmptyThresholdIdentity);
            }
            let identity = ConsensusIdentity::decode(info.threshold_identity.as_slice())
                .map_err(|_| ConsensusVerificationError::InvalidThresholdIdentity)?;
            Ok(Self { identity })
        }

        pub fn decode_finalization(
            encoded: &[u8],
        ) -> Result<Finalization, ConsensusVerificationError> {
            let mut reader = encoded;
            let proposal = Proposal {
                round: Round {
                    epoch: read_u64(&mut reader)?,
                    view: read_u64(&mut reader)?,
                },
                parent: read_u64(&mut reader)?,
                payload: Digest::read(&mut reader)
                    .map_err(|_| ConsensusVerificationError::InvalidFinalization)?,
            };
            let certificate = Certificate {
                vote_signature: ThresholdSignature::read(&mut reader)
                    .map_err(|_| ConsensusVerificationError::InvalidFinalization)?,
                seed_signature: ThresholdSignature::read(&mut reader)
                    .map_err(|_| ConsensusVerificationError::InvalidFinalization)?,
            };
            if !reader.is_empty() {
                return Err(ConsensusVerificationError::InvalidFinalization);
            }
            Ok(Finalization {
                proposal,
                certificate,
            })
        }

        pub fn verify_finalization(
            &self,
            finalization: &Finalization,
            expected_payload: Digest,
        ) -> Result<(), ConsensusVerificationError> {
            if finalization.proposal.payload != expected_payload {
                return Err(ConsensusVerificationError::PayloadMismatch);
            }

            let finalize_namespace = namespace(b"_FINALIZE");
            let seed_namespace = namespace(b"_SEED");
            let proposal_message = encode_proposal(&finalization.proposal);
            let seed_message = encode_round(finalization.proposal.round);
            let entries = [
                (
                    finalize_namespace.as_slice(),
                    proposal_message.as_slice(),
                    finalization.certificate.vote_signature,
                ),
                (
                    seed_namespace.as_slice(),
                    seed_message.as_slice(),
                    finalization.certificate.seed_signature,
                ),
            ];

            let mut rng = rand::rng();
            if batch::verify_same_signer::<_, ThresholdVariant, _>(
                &mut rng,
                &self.identity,
                entries.iter(),
                &Sequential,
            )
            .is_err()
            {
                return Err(ConsensusVerificationError::VerificationFailed);
            }
            Ok(())
        }

        pub fn verify_snapshot(
            &self,
            snapshot: &LatestBlock,
        ) -> Result<(), ConsensusVerificationError> {
            crate::finality_proof::FinalityProof::decode(&snapshot.finalization)?
                .verify(self, snapshot)
        }
    }

    fn read_u64(reader: &mut &[u8]) -> Result<u64, ConsensusVerificationError> {
        Ok(UInt::read(reader)
            .map_err(|_| ConsensusVerificationError::InvalidFinalization)?
            .into())
    }

    fn write_u64(value: u64, out: &mut Vec<u8>) {
        UInt(value).write(out);
    }

    fn encode_round(round: Round) -> Vec<u8> {
        let mut encoded = Vec::new();
        write_u64(round.epoch, &mut encoded);
        write_u64(round.view, &mut encoded);
        encoded
    }

    fn encode_proposal(proposal: &Proposal) -> Vec<u8> {
        let mut encoded = encode_round(proposal.round);
        write_u64(proposal.parent, &mut encoded);
        proposal.payload.write(&mut encoded);
        encoded
    }

    fn namespace(suffix: &[u8]) -> Vec<u8> {
        let mut namespace = Vec::with_capacity(CONSENSUS_NAMESPACE.len() + suffix.len());
        namespace.extend_from_slice(CONSENSUS_NAMESPACE);
        namespace.extend_from_slice(suffix);
        namespace
    }
}

#[cfg(any(feature = "indexer", feature = "validator"))]
pub use full::*;
#[cfg(not(any(feature = "indexer", feature = "validator")))]
pub use light::*;
