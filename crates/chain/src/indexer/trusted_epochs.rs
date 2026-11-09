use super::*;
use crate::ConsensusVerifier;

use commonware_consensus::types::{Epoch, EpochInfo, Epocher};
use commonware_cryptography::certificate::{Provider, Scoped};
use hellas_genesis::TrustDocument;

#[derive(Debug, thiserror::Error)]
pub(crate) enum TrustError {
    #[error("invalid trust schedule: {0}")]
    Schedule(String),
    #[error(transparent)]
    Consensus(#[from] crate::consensus::ConsensusVerificationError),
}

#[derive(Clone)]
pub(crate) struct TrustedEpochs {
    trust: Arc<TrustDocument>,
    verifiers: Arc<Vec<ConsensusVerifier>>,
}
impl TrustedEpochs {
    pub fn with_genesis(trust: TrustDocument, genesis_json: &[u8]) -> Result<Self, TrustError> {
        crate::proof_verify::ProofVerifier::with_genesis(trust.clone(), genesis_json)
            .map_err(|error| TrustError::Schedule(error.to_string()))?;
        // Marshal's transition logic asks for epoch.next(), so native ingestion requires
        // consecutive round epochs even though an offline verifier can inspect sparse IDs.
        if trust
            .epochs
            .iter()
            .enumerate()
            .any(|(position, epoch)| epoch.epoch != position as u64)
        {
            return Err(TrustError::Schedule(
                "native marshal requires consecutive epochs beginning at zero".into(),
            ));
        }
        let genesis = serde_json::from_slice(genesis_json)
            .map_err(|e| TrustError::Schedule(e.to_string()))?;
        let genesis_digest = crate::genesis_digest(&genesis);
        let verifiers = trust
            .epochs
            .iter()
            .map(|epoch| {
                ConsensusVerifier::new(
                    &crate::ConsensusInfo {
                        network_id: trust.network_id.clone(),
                        validators: Vec::new(),
                        threshold_identity: hex::decode(&epoch.threshold_identity)
                            .expect("validated threshold encoding"),
                    },
                    genesis_digest,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            trust: Arc::new(trust),
            verifiers: Arc::new(verifiers),
        })
    }
}
impl Epocher for TrustedEpochs {
    fn containing(&self, height: Height) -> Option<EpochInfo> {
        let selected = self.trust.epoch_at(height.get()).ok()?;
        let epoch = Epoch::new(selected.epoch);
        Some(EpochInfo::new(
            epoch,
            height,
            self.first(epoch)?,
            self.last(epoch)?,
        ))
    }
    fn first(&self, epoch: Epoch) -> Option<Height> {
        self.trust
            .epochs
            .get(usize::try_from(epoch.get()).ok()?)
            .map(|entry| Height::new(entry.start_height))
    }
    fn last(&self, epoch: Epoch) -> Option<Height> {
        self.trust
            .epochs
            .get(usize::try_from(epoch.get()).ok()?)
            .map(|entry| Height::new(entry.end_height.map_or(u64::MAX, |end| end - 1)))
    }
}
impl Provider for TrustedEpochs {
    type Scope = Epoch;
    type Scheme = Scheme;
    fn scoped(&self, epoch: Epoch) -> Option<Scoped<Scheme>> {
        self.verifiers
            .get(usize::try_from(epoch.get()).ok()?)
            .map(|verifier| Scoped::scheme(Arc::new(verifier.scheme().clone())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::test_support::{finality_envelope, index_block, index_genesis};
    use commonware_consensus::{
        simplex::types::Context,
        types::{Round, View},
    };
    use commonware_cryptography::{Hasher as _, Sha256};
    use commonware_runtime::{Runner as _, deterministic};
    use hellas_genesis::{HELLAS_DEVNET_3_ID, HELLAS_DEVNET_3_JSON, TrustEpoch};

    #[test]
    fn proof_verifier_accepts_rotated_threshold_keys_only_at_the_scheduled_height() {
        deterministic::Runner::default().start(|_context| async move {
            let first = crate::execution::test_support::consensus_fixture_in(
                501,
                4,
                hellas_kernel::NetworkId::new(HELLAS_DEVNET_3_ID).unwrap(),
                crate::genesis_digest(&serde_json::from_str(HELLAS_DEVNET_3_JSON).unwrap()),
            );
            let second = crate::execution::test_support::consensus_fixture_in(
                601,
                4,
                hellas_kernel::NetworkId::new(HELLAS_DEVNET_3_ID).unwrap(),
                crate::genesis_digest(&serde_json::from_str(HELLAS_DEVNET_3_JSON).unwrap()),
            );
            let trust = TrustDocument {
                schema_version: 1,
                network_id: HELLAS_DEVNET_3_ID.into(),
                genesis_sha256: hex::encode(Sha256::hash(HELLAS_DEVNET_3_JSON.as_bytes())),
                epochs: vec![
                    TrustEpoch {
                        epoch: 0,
                        start_height: 0,
                        end_height: Some(2),
                        threshold_identity: hex::encode(first.assembler.identity().encode()),
                    },
                    TrustEpoch {
                        epoch: 1,
                        start_height: 2,
                        end_height: None,
                        threshold_identity: hex::encode(second.assembler.identity().encode()),
                    },
                ],
            };
            let schedule =
                TrustedEpochs::with_genesis(trust.clone(), HELLAS_DEVNET_3_JSON.as_bytes())
                    .unwrap();
            assert_eq!(schedule.first(Epoch::new(1)), Some(Height::new(2)));
            assert_eq!(schedule.last(Epoch::zero()), Some(Height::new(1)));
            assert!(schedule.scoped(Epoch::new(2)).is_none());
            let genesis = index_genesis();
            let block1 = index_block(&genesis, Digest::from([1; 32]), Vec::new());
            let base = index_block(&block1, Digest::from([2; 32]), Vec::new());
            let block2 = HellasBlock::new(
                Context {
                    round: Round::new(Epoch::new(1), View::new(2)),
                    leader: second.leaders[0].clone(),
                    parent: (View::new(1), block1.digest()),
                },
                block1.digest(),
                Height::new(2),
                2,
                base.state_root(),
                base.sync_target(),
                Vec::new(),
            );
            let verifier = crate::proof_verify::ProofVerifier::with_genesis(
                trust,
                HELLAS_DEVNET_3_JSON.as_bytes(),
            )
            .unwrap();
            let check = |block: &HellasBlock, committee| {
                let bundle = verifier.bundle(super::finalized_block(
                    block.clone(),
                    finality_envelope(committee, block),
                ));
                verifier.verify(
                    bundle,
                    crate::proof_verify::ProofQuery::Block(crate::FinalizedBlockQuery::Height(
                        block.height().get(),
                    )),
                )
            };
            check(&block1, &first).unwrap();
            assert!(check(&block2, &first).is_err());
            assert!(check(&base, &second).is_err());
            check(&block2, &second).unwrap();
        });
    }
}
