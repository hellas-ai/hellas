//! Runtime-independent verification and persistence boundary for native and edge explorers.
//!
//! A trust document must be authenticated independently of the indexer. An embedded bundle
//! proves consensus finality, not that its observation timestamp or latest-block claim is fresh.
use crate::domain::Digest;
use crate::{
    ConsensusInfo, ConsensusVerifier, FinalizedBlock, FinalizedBlockQuery, FinalizedBlockView,
    LatestBlock,
};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::CertifiableBlock as _;
use commonware_cryptography::{Hasher as _, Sha256};
use hellas_genesis::{HELLAS_DEVNET_1_JSON, TrustDocument};
use serde::{Deserialize, Serialize};

pub const PROOF_SCHEMA_VERSION: u32 = 1;
pub const MAX_PROOF_BYTES: usize = 16 * 1024 * 1024;

/// The JSON and protobuf representations carry identical proof fields. Byte vectors are JSON
/// arrays; no JSON rendering or observation timestamp is covered by the consensus certificate.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, prost::Message)]
#[serde(deny_unknown_fields)]
pub struct ProofBundle {
    #[prost(uint32, tag = "1")]
    pub schema_version: u32,
    #[prost(string, tag = "2")]
    pub network_id: String,
    #[prost(string, tag = "3")]
    pub trust_sha256: String,
    #[prost(uint64, tag = "4")]
    pub height: u64,
    #[prost(string, tag = "5")]
    pub payload: String,
    #[prost(string, tag = "6")]
    pub state_root: String,
    #[prost(bytes = "vec", tag = "7")]
    pub finalization: Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    pub canonical_block: Vec<u8>,
    #[prost(uint64, tag = "9")]
    pub observed_at_ms: u64,
    #[prost(uint64, tag = "10")]
    pub epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExplorerQuery {
    Block(FinalizedBlockQuery),
    /// SHA-256 of the transaction's canonical chain encoding.
    Transaction(Digest),
}

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error(transparent)]
    Trust(#[from] hellas_genesis::TrustError),
    #[error(transparent)]
    Consensus(#[from] crate::ConsensusVerificationError),
    #[error(transparent)]
    Block(#[from] crate::BlockViewError),
    #[error("trust document does not name the shipped devnet genesis")]
    Genesis,
    #[error("proof schema, network, or trust document does not match")]
    Identity,
    #[error("proof exceeds the maximum supported size")]
    Size,
    #[error("invalid canonical hexadecimal digest")]
    Digest,
    #[error("certificate epoch does not match the trusted height schedule")]
    Epoch,
    #[error("certificate round does not match the block context")]
    Round,
    #[error("proof does not answer the requested route")]
    Query,
}

pub struct ExplorerVerifier {
    trust: TrustDocument,
    trust_sha256: String,
    verifiers: Vec<ConsensusVerifier>,
}

impl ExplorerVerifier {
    /// `trust` is an authenticated deployment input, never a document accepted from a query peer.
    pub fn new(trust: TrustDocument) -> Result<Self, VerificationError> {
        trust.validate()?;
        if trust.genesis_sha256 != hex::encode(Sha256::hash(HELLAS_DEVNET_1_JSON.as_bytes())) {
            return Err(VerificationError::Genesis);
        }
        let trust_sha256 = hex::encode(Sha256::hash(
            &serde_json::to_vec(&trust).expect("trust serializes"),
        ));
        let verifiers = trust
            .epochs
            .iter()
            .map(|epoch| {
                ConsensusVerifier::new(&ConsensusInfo {
                    validators: Vec::new(),
                    network_id: trust.network_id.clone(),
                    threshold_identity: hex::decode(&epoch.threshold_identity)
                        .expect("validated hex"),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            trust,
            trust_sha256,
            verifiers,
        })
    }

    pub fn trust_sha256(&self) -> &str {
        &self.trust_sha256
    }

    pub fn verify(
        &self,
        bundle: ProofBundle,
        query: ExplorerQuery,
    ) -> Result<VerifiedBlock, VerificationError> {
        if bundle.schema_version != PROOF_SCHEMA_VERSION
            || bundle.network_id != self.trust.network_id
            || bundle.trust_sha256 != self.trust_sha256
        {
            return Err(VerificationError::Identity);
        }
        if bundle.canonical_block.len() > MAX_PROOF_BYTES || bundle.finalization.len() > 4096 {
            return Err(VerificationError::Size);
        }
        let epoch = self.trust.epoch_at(bundle.height)?;
        if bundle.epoch != epoch.epoch {
            return Err(VerificationError::Epoch);
        }
        let position = self
            .trust
            .epochs
            .iter()
            .position(|candidate| candidate.epoch == epoch.epoch)
            .expect("selected epoch");
        let finalized = FinalizedBlock {
            snapshot: LatestBlock {
                height: bundle.height,
                payload: parse_digest(&bundle.payload)?,
                state_root: parse_digest(&bundle.state_root)?,
                finalization: bundle.finalization.clone(),
            },
            block: bundle.canonical_block.clone(),
        };
        let finalization = ConsensusVerifier::decode_finalization(&bundle.finalization)?;
        #[cfg(any(feature = "indexer", feature = "validator"))]
        let certificate_epoch = finalization.proposal.round.epoch().get();
        #[cfg(not(any(feature = "indexer", feature = "validator")))]
        let certificate_epoch = finalization.proposal.round.epoch;
        if certificate_epoch != epoch.epoch {
            return Err(VerificationError::Epoch);
        }
        self.verifiers[position].verify_finalization(&finalization, finalized.snapshot.payload)?;
        let view = FinalizedBlockView::decode(&finalized)?;
        let block = crate::HellasBlock::decode(finalized.block.as_slice())
            .map_err(|_| VerificationError::Round)?;
        let context = block.context();
        #[cfg(any(feature = "indexer", feature = "validator"))]
        let round_matches = context.round == finalization.proposal.round;
        #[cfg(not(any(feature = "indexer", feature = "validator")))]
        let round_matches = context.round.epoch().get() == finalization.proposal.round.epoch
            && context.round.view().get() == finalization.proposal.round.view;
        if !round_matches {
            return Err(VerificationError::Round);
        }
        let transaction_index = match query {
            ExplorerQuery::Block(FinalizedBlockQuery::Latest) => None,
            ExplorerQuery::Block(FinalizedBlockQuery::Height(height))
                if height == view.height() =>
            {
                None
            }
            ExplorerQuery::Block(FinalizedBlockQuery::Payload(payload))
                if payload == view.payload() =>
            {
                None
            }
            ExplorerQuery::Transaction(wanted) => Some(
                view.txs()
                    .iter()
                    .position(|tx| transaction_digest(tx) == wanted)
                    .ok_or(VerificationError::Query)?,
            ),
            _ => return Err(VerificationError::Query),
        };
        Ok(VerifiedBlock {
            bundle,
            view,
            transaction_index,
        })
    }
}

pub fn transaction_digest(tx: &crate::domain::Transaction) -> Digest {
    Sha256::hash(&tx.encode())
}

fn parse_digest(value: &str) -> Result<Digest, VerificationError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(VerificationError::Digest);
    }
    let bytes: [u8; 32] = hex::decode(value)
        .map_err(|_| VerificationError::Digest)?
        .try_into()
        .map_err(|_| VerificationError::Digest)?;
    Ok(Digest::from(bytes))
}

/// Cannot be constructed without certificate, canonical-block, epoch, and route verification.
pub struct VerifiedBlock {
    bundle: ProofBundle,
    view: FinalizedBlockView,
    transaction_index: Option<usize>,
}
impl VerifiedBlock {
    pub fn bundle(&self) -> &ProofBundle {
        &self.bundle
    }
    pub fn view(&self) -> &FinalizedBlockView {
        &self.view
    }
    pub fn transaction_index(&self) -> Option<usize> {
        self.transaction_index
    }
    pub fn cursor(&self) -> VerifiedCursor {
        VerifiedCursor {
            height: self.view.height(),
            payload: self.view.payload(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedCursor {
    pub height: u64,
    pub payload: Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CursorError {
    #[error("conflicting finalized payload at the same height")]
    Conflict,
}

/// Historical fills never regress the head. A backend must perform this check and its write in
/// one transaction, and reject any conflicting immutable height/payload already in its cache.
pub fn advance_cursor(
    current: Option<VerifiedCursor>,
    incoming: VerifiedCursor,
) -> Result<VerifiedCursor, CursorError> {
    match current {
        Some(cursor) if cursor.height == incoming.height && cursor.payload != incoming.payload => {
            Err(CursorError::Conflict)
        }
        Some(cursor) if cursor.height >= incoming.height => Ok(cursor),
        _ => Ok(incoming),
    }
}

/// Backends retain canonical evidence. Re-verify returned bundles against the current pinned
/// trust document before rendering. Futures intentionally need not be Send on a WASM isolate.
/// `commit` atomically stores evidence and advances the cursor, rejects immutable-key conflicts,
/// and may evict old bundles without evicting the durable cursor. Observation time is advisory.
#[allow(async_fn_in_trait)]
pub trait VerifiedStore {
    type Error;
    async fn cursor(&self) -> Result<Option<VerifiedCursor>, Self::Error>;
    async fn get(&self, query: FinalizedBlockQuery) -> Result<Option<ProofBundle>, Self::Error>;
    async fn commit(&self, block: &VerifiedBlock) -> Result<(), Self::Error>;
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::domain::{Scheme, ThresholdVariant};
    use commonware_consensus::{
        Heightable as _,
        simplex::types::{Context, Finalization as NativeFinalization, Finalize, Proposal},
        types::{Epoch, Height, Round, View},
    };
    use commonware_cryptography::{
        Digest as _, Digestible as _, Signer as _, bls12381::dkg::feldman_desmedt::deal, ed25519,
    };
    use commonware_parallel::Sequential;
    use commonware_storage::{merkle::Location, mmr};
    use commonware_utils::{N3f1, non_empty_range, ordered::Set};
    use hellas_genesis::{HELLAS_DEVNET_1_ID, TrustEpoch};
    use rand::{SeedableRng, rngs::StdRng};

    fn fixture() -> (ExplorerVerifier, ProofBundle) {
        let keys = (0..4)
            .map(ed25519::PrivateKey::from_seed)
            .collect::<Vec<_>>();
        let participants =
            Set::try_from(keys.iter().map(|key| key.public_key()).collect::<Vec<_>>()).unwrap();
        let (output, shares) = deal::<ThresholdVariant, _, N3f1>(
            &mut StdRng::seed_from_u64(42),
            Default::default(),
            participants.clone(),
        )
        .unwrap();
        let polynomial = output.public().clone();
        let schemes = keys
            .iter()
            .map(|key| {
                Scheme::signer(
                    crate::CONSENSUS_NAMESPACE,
                    participants.clone(),
                    polynomial.clone(),
                    shares.get_value(&key.public_key()).unwrap().clone(),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let assembler = Scheme::verifier(crate::CONSENSUS_NAMESPACE, participants, polynomial);
        let trust = TrustDocument {
            schema_version: 1,
            network_id: HELLAS_DEVNET_1_ID.into(),
            genesis_sha256: hex::encode(Sha256::hash(HELLAS_DEVNET_1_JSON.as_bytes())),
            epochs: vec![TrustEpoch {
                epoch: 0,
                start_height: 0,
                end_height: None,
                threshold_identity: hex::encode(assembler.identity().encode()),
            }],
        };
        let verifier = ExplorerVerifier::new(trust).unwrap();
        let block = crate::HellasBlock::new(
            Context {
                round: Round::new(Epoch::zero(), View::new(1)),
                leader: keys[0].public_key(),
                parent: (View::zero(), Digest::EMPTY),
            },
            Digest::EMPTY,
            Height::new(1),
            1000,
            Digest::from([5; 32]),
            crate::UtxoSyncTarget::new(
                Digest::from([5; 32]),
                non_empty_range!(
                    Location::<mmr::Family>::new(0),
                    Location::<mmr::Family>::new(1)
                ),
            ),
            vec![crate::domain::Transaction::Kernel(
                hellas_kernel::test_support::valid_open_tx().unwrap(),
            )],
        );
        let proposal = Proposal::new(block.context().round, View::zero(), block.digest());
        let votes = schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
            .collect::<Vec<_>>();
        let certificate =
            NativeFinalization::from_finalizes(&assembler, &votes, &Sequential).unwrap();
        let bundle = ProofBundle {
            schema_version: 1,
            network_id: HELLAS_DEVNET_1_ID.into(),
            trust_sha256: verifier.trust_sha256().into(),
            height: block.height().get(),
            payload: hex::encode(block.digest()),
            state_root: hex::encode(block.state_root()),
            finalization: certificate.encode().to_vec(),
            canonical_block: block.encode().to_vec(),
            observed_at_ms: 1000,
            epoch: 0,
        };
        (verifier, bundle)
    }

    #[test]
    fn verifies_block_transaction_and_both_wire_encodings() {
        let (verifier, bundle) = fixture();
        let json: ProofBundle =
            serde_json::from_slice(&serde_json::to_vec(&bundle).unwrap()).unwrap();
        let proto = <ProofBundle as prost::Message>::decode(
            prost::Message::encode_to_vec(&bundle).as_slice(),
        )
        .unwrap();
        assert_eq!(json, proto);
        let block = verifier
            .verify(json, ExplorerQuery::Block(FinalizedBlockQuery::Height(1)))
            .unwrap();
        let tx = transaction_digest(&block.view().txs()[0]);
        assert_eq!(
            verifier
                .verify(proto, ExplorerQuery::Transaction(tx))
                .unwrap()
                .transaction_index(),
            Some(0)
        );
        assert!(matches!(
            verifier.verify(
                bundle.clone(),
                ExplorerQuery::Block(FinalizedBlockQuery::Height(2))
            ),
            Err(VerificationError::Query)
        ));
        assert!(matches!(
            verifier.verify(bundle, ExplorerQuery::Transaction(Digest::from([9; 32]))),
            Err(VerificationError::Query)
        ));
    }

    #[test]
    fn rejects_tampered_certificate_block_snapshot_and_identity() {
        let (verifier, bundle) = fixture();
        let query = ExplorerQuery::Block(FinalizedBlockQuery::Latest);
        let mut bad = bundle.clone();
        bad.finalization[10] ^= 1;
        assert!(verifier.verify(bad, query).is_err());
        let mut bad = bundle.clone();
        bad.canonical_block[10] ^= 1;
        assert!(matches!(
            verifier.verify(bad, query),
            Err(VerificationError::Block(_))
        ));
        let mut bad = bundle.clone();
        bad.height += 1;
        assert!(matches!(
            verifier.verify(bad, query),
            Err(VerificationError::Block(_))
        ));
        let mut bad = bundle.clone();
        bad.state_root = "11".repeat(32);
        assert!(matches!(
            verifier.verify(bad, query),
            Err(VerificationError::Block(_))
        ));
        let mut bad = bundle.clone();
        bad.epoch = 1;
        assert!(matches!(
            verifier.verify(bad, query),
            Err(VerificationError::Epoch)
        ));
        let mut bad = bundle.clone();
        bad.network_id = "another-network".into();
        assert!(matches!(
            verifier.verify(bad, query),
            Err(VerificationError::Identity)
        ));
        let mut bad = bundle.clone();
        bad.trust_sha256 = "ff".repeat(32);
        assert!(matches!(
            verifier.verify(bad, query),
            Err(VerificationError::Identity)
        ));
        // Observation time deliberately makes no cryptographic freshness claim.
        let mut changed = bundle;
        changed.observed_at_ms = u64::MAX;
        assert!(verifier.verify(changed, query).is_ok());
    }

    #[test]
    fn historical_fills_preserve_cursor_and_conflicts_are_rejected() {
        let old = VerifiedCursor {
            height: 1,
            payload: Digest::from([1; 32]),
        };
        let new = VerifiedCursor {
            height: 2,
            payload: Digest::from([2; 32]),
        };
        assert_eq!(advance_cursor(None, old), Ok(old));
        assert_eq!(advance_cursor(Some(old), new), Ok(new));
        assert_eq!(advance_cursor(Some(new), old), Ok(new));
        assert_eq!(advance_cursor(Some(new), new), Ok(new));
        assert_eq!(
            advance_cursor(Some(new), VerifiedCursor { height: 2, ..old }),
            Err(CursorError::Conflict)
        );
    }
}
