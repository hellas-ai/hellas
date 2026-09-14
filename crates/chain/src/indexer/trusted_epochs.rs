use super::*;
use commonware_consensus::types::{Epoch, EpochInfo, Epocher};
use commonware_cryptography::certificate::{Provider, Scoped};
use hellas_genesis::TrustDocument;

#[derive(Clone)]
pub(super) struct TrustedEpochs {
    trust: Arc<TrustDocument>,
    verifiers: Arc<Vec<ConsensusVerifier>>,
}
impl TrustedEpochs {
    pub fn new(trust: TrustDocument) -> Result<Self, IngestError> {
        crate::verified_explorer::ExplorerVerifier::new(trust.clone())
            .map_err(|error| IngestError::TrustSchedule(error.to_string()))?;
        // Marshal's transition logic asks for epoch.next(), so native ingestion requires
        // consecutive round epochs even though an offline verifier can inspect sparse IDs.
        if trust
            .epochs
            .iter()
            .enumerate()
            .any(|(position, epoch)| epoch.epoch != position as u64)
        {
            return Err(IngestError::TrustSchedule(
                "native marshal requires consecutive epochs beginning at zero".into(),
            ));
        }
        let verifiers = trust
            .epochs
            .iter()
            .map(|epoch| {
                ConsensusVerifier::new(&crate::ConsensusInfo {
                    network_id: trust.network_id.clone(),
                    validators: Vec::new(),
                    threshold_identity: hex::decode(&epoch.threshold_identity)
                        .expect("validated threshold encoding"),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            trust: Arc::new(trust),
            verifiers: Arc::new(verifiers),
        })
    }
    pub fn verifier(
        &self,
        height: Height,
        epoch: Epoch,
    ) -> Result<&ConsensusVerifier, IngestError> {
        let selected = self
            .trust
            .epoch_at(height.get())
            .map_err(|error| IngestError::TrustSchedule(error.to_string()))?;
        if selected.epoch != epoch.get() {
            return Err(IngestError::TrustSchedule(
                "certificate epoch disagrees with finalized height".into(),
            ));
        }
        self.verifiers
            .get(epoch.get() as usize)
            .ok_or_else(|| IngestError::TrustSchedule("unknown certificate epoch".into()))
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
    use crate::execution::test_support::{
        consensus_fixture, finalization, index_block, index_genesis,
    };
    use commonware_consensus::{
        simplex::types::Context,
        types::{Round, View},
    };
    use commonware_cryptography::{Hasher as _, Sha256};
    use commonware_runtime::{Runner as _, deterministic};
    use hellas_genesis::{HELLAS_DEVNET_1_ID, HELLAS_DEVNET_1_JSON, TrustEpoch};

    #[test]
    fn follower_accepts_rotated_threshold_keys_only_at_the_scheduled_height() {
        deterministic::Runner::default().start(|context| async move {
            let first = consensus_fixture(501);
            let second = consensus_fixture(601);
            let trust = TrustDocument {
                schema_version: 1,
                network_id: HELLAS_DEVNET_1_ID.into(),
                genesis_sha256: hex::encode(Sha256::hash(HELLAS_DEVNET_1_JSON.as_bytes())),
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
            let schedule = TrustedEpochs::new(trust.clone()).unwrap();
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
            let (indexer, _handle) = spawn_trusted_follower_indexer(
                context,
                "rotated-origin",
                Config::default(),
                trust,
                genesis,
            )
            .await
            .unwrap();
            indexer
                .ingest_finalized(block1.clone(), finalization(&first, &block1))
                .await
                .unwrap();
            assert!(
                indexer
                    .ingest_finalized(block2.clone(), finalization(&first, &block2))
                    .await
                    .is_err()
            );
            assert!(matches!(
                indexer
                    .ingest_finalized(base.clone(), finalization(&second, &base))
                    .await,
                Err(IngestError::TrustSchedule(_))
            ));
            indexer
                .ingest_finalized(block2.clone(), finalization(&second, &block2))
                .await
                .unwrap();
            assert_eq!(indexer.get_latest_block().await.unwrap().unwrap().height, 2);
        });
    }
}
