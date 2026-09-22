use super::*;
use crate::domain::{Digest, Scheme, ThresholdVariant};
use commonware_consensus::{
    simplex::types::{Context, Finalization as NativeFinalization, Finalize, Proposal},
    types::{Epoch, Height, Round, View},
};
use commonware_cryptography::{
    Digest as _, Signer as _, bls12381::dkg::feldman_desmedt::deal, ed25519,
};
use commonware_parallel::Sequential;
use commonware_storage::{merkle::Location, mmr};
use commonware_utils::{N3f1, non_empty_range, ordered::Set};
use rand::{SeedableRng, rngs::StdRng};

fn fixture() -> (ConsensusVerifier, Vec<HellasBlock>, Vec<u8>, Vec<u8>) {
    fixture_with_epochs(false)
}

fn fixture_with_epochs(
    cross_epoch: bool,
) -> (ConsensusVerifier, Vec<HellasBlock>, Vec<u8>, Vec<u8>) {
    let keys = (0..4)
        .map(ed25519::PrivateKey::from_seed)
        .collect::<Vec<_>>();
    let participants =
        Set::try_from(keys.iter().map(|k| k.public_key()).collect::<Vec<_>>()).unwrap();
    let (output, shares) = deal::<ThresholdVariant, _, N3f1>(
        &mut StdRng::seed_from_u64(428),
        Default::default(),
        participants.clone(),
    )
    .unwrap();
    let schemes = keys
        .iter()
        .map(|key| {
            Scheme::signer(
                crate::CONSENSUS_NAMESPACE,
                participants.clone(),
                output.public().clone(),
                shares.get_value(&key.public_key()).unwrap().clone(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let assembler = Scheme::verifier(
        crate::CONSENSUS_NAMESPACE,
        participants,
        output.public().clone(),
    );
    let identity = assembler.identity().encode().to_vec();
    let verifier = ConsensusVerifier::new(&crate::ConsensusInfo {
        network_id: crate::domain::TEST_NETWORK.as_str().into(),
        validators: Vec::new(),
        threshold_identity: identity.clone(),
    })
    .unwrap();
    let genesis = HellasBlock::genesis(
        keys[0].public_key(),
        Digest::EMPTY,
        crate::UtxoSyncTarget::new(
            Digest::EMPTY,
            non_empty_range!(
                Location::<mmr::Family>::new(0),
                Location::<mmr::Family>::new(1)
            ),
        ),
    );
    let mut blocks = vec![genesis];
    for height in 1..=3 {
        let parent = blocks.last().unwrap();
        blocks.push(HellasBlock::new(
            Context {
                round: Round::new(
                    Epoch::new(u64::from(cross_epoch && height >= 2)),
                    View::new(height),
                ),
                leader: keys[0].public_key(),
                parent: (parent.context().round.view(), parent.digest()),
            },
            parent.digest(),
            Height::new(height),
            height,
            Digest::from([height as u8; 32]),
            parent.sync_target(),
            Vec::new(),
        ));
    }
    let terminal = blocks.last().unwrap();
    let proposal = Proposal::new(
        terminal.context().round,
        terminal.context().parent.0,
        terminal.digest(),
    );
    let votes = schemes
        .iter()
        .map(|scheme| Finalize::sign(scheme, proposal.clone()).unwrap())
        .collect::<Vec<_>>();
    let certificate =
        NativeFinalization::<Scheme, Digest>::from_finalizes(&assembler, &votes, &Sequential)
            .unwrap();
    (verifier, blocks, certificate.encode().to_vec(), identity)
}

fn snapshot(block: &HellasBlock, proof: Vec<u8>) -> LatestBlock {
    LatestBlock {
        height: block.height().get(),
        payload: block.digest(),
        state_root: block.state_root(),
        finalization: proof,
    }
}

#[test]
fn descendant_finality_verifies_with_full_and_light_consensus() {
    let (verifier, blocks, certificate, _) = fixture();
    verifier
        .verify_snapshot(&snapshot(&blocks[3], certificate.clone()))
        .unwrap();
    let encoded = encode(&certificate, &blocks[2..]).unwrap();
    let target = snapshot(&blocks[1], encoded.clone());
    verifier.verify_snapshot(&target).unwrap();
    assert_eq!(
        FinalityProof::decode(&encoded)
            .unwrap()
            .certified_height(1)
            .unwrap(),
        3
    );

    // A real signature cannot authenticate a different target, reordered ancestry,
    // omitted intermediate block, altered block body, or dishonest target height.
    for invalid in [
        snapshot(&blocks[0], encoded.clone()),
        snapshot(
            &blocks[1],
            encode(&certificate, &[blocks[3].clone(), blocks[2].clone()]).unwrap(),
        ),
        snapshot(&blocks[1], encode(&certificate, &blocks[3..]).unwrap()),
        snapshot(
            &blocks[1],
            encode(
                &certificate,
                &[
                    blocks[2].clone().with_owner_root([9; 32]),
                    blocks[3].clone(),
                ],
            )
            .unwrap(),
        ),
        LatestBlock {
            height: 0,
            ..target.clone()
        },
    ] {
        assert!(verifier.verify_snapshot(&invalid).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(FinalityProof::decode(&trailing).is_err());
    assert!(FinalityProof::decode(&encoded[..encoded.len() - 1]).is_err());
    assert!(FinalityProof::decode(&vec![0; MAX_FINALITY_PROOF_BYTES + 1]).is_err());
    assert!(
        encode(
            &certificate,
            &vec![blocks[2].clone(); MAX_FINALITY_DESCENDANTS + 1]
        )
        .is_err()
    );
}

#[cfg(feature = "proof-verify")]
#[test]
fn descendant_finality_uses_the_certified_height_trust_and_checks_each_epoch() {
    use crate::proof_verify::{ProofBundle, ProofQuery, ProofVerifier};
    use commonware_cryptography::{Hasher as _, Sha256};
    use hellas_genesis::{HELLAS_DEVNET_1_ID, HELLAS_DEVNET_1_JSON, TrustDocument, TrustEpoch};
    let (_, blocks, certificate, identity) = fixture_with_epochs(true);
    let mut trust = TrustDocument {
        schema_version: 1,
        network_id: HELLAS_DEVNET_1_ID.into(),
        genesis_sha256: hex::encode(Sha256::hash(HELLAS_DEVNET_1_JSON.as_bytes())),
        epochs: vec![
            TrustEpoch {
                epoch: 0,
                start_height: 0,
                end_height: Some(2),
                threshold_identity: hex::encode(&identity),
            },
            TrustEpoch {
                epoch: 1,
                start_height: 2,
                end_height: None,
                threshold_identity: hex::encode(&identity),
            },
        ],
    };
    let verifier = ProofVerifier::new(trust.clone()).unwrap();
    let target = &blocks[1];
    let bundle = ProofBundle {
        schema_version: 1,
        network_id: trust.network_id.clone(),
        trust_sha256: verifier.trust_sha256().into(),
        height: 1,
        payload: hex::encode(target.digest()),
        state_root: hex::encode(target.state_root()),
        finalization: encode(&certificate, &blocks[2..]).unwrap(),
        canonical_block: target.encode().to_vec(),
        observed_at_ms: 0,
        epoch: 1,
    };
    let query = ProofQuery::Block(crate::FinalizedBlockQuery::Height(1));
    verifier.verify(bundle.clone(), query).unwrap();
    #[cfg(feature = "indexer-api")]
    {
        use commonware_runtime::{Runner as _, deterministic};
        let trust = trust.clone();
        let blocks = blocks.clone();
        let encoded = bundle.finalization.clone();
        deterministic::Runner::default().start(|context| async move {
            let (indexer, _task) = crate::indexer::spawn_trusted_follower_indexer(
                context,
                "ancestry-epoch-transition",
                crate::config::Config::default(),
                trust,
                blocks[0].clone(),
            )
            .await
            .unwrap();
            indexer
                .ingest_finalized_proof(blocks[1].clone(), &encoded)
                .await
                .unwrap();
            assert_eq!(indexer.get_latest_block().await.unwrap().unwrap().height, 3);
        });
    }
    let mut wrong_epoch = bundle.clone();
    wrong_epoch.epoch = 0;
    assert!(verifier.verify(wrong_epoch, query).is_err());
    trust.epochs[0].end_height = Some(3);
    trust.epochs[1].start_height = 3;
    let wrong_schedule = ProofVerifier::new(trust).unwrap();
    let mut wrong_bundle = bundle;
    wrong_bundle.trust_sha256 = wrong_schedule.trust_sha256().into();
    // The terminal certificate still belongs to epoch 1 at height 3, but the
    // intermediate block's epoch now disagrees with the authenticated schedule.
    assert!(wrong_schedule.verify(wrong_bundle, query).is_err());
}

#[cfg(feature = "indexer")]
#[test]
fn descendant_finality_persists_every_ancestor_before_advancing_follower() {
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    deterministic::Runner::default().start(|context| async move {
        let (verifier, blocks, certificate, _) = fixture();
        let (source, _source_task) = crate::spawn_follower_indexer(
            context.child("source"),
            "descendant-source",
            crate::config::Config::default(),
            verifier.clone(),
            blocks[0].clone(),
        )
        .await
        .unwrap();
        // Use the public ingestion path with the actual ancestor-only proof. Marshal
        // archives heights 1 and 2 without certificates and height 3 with its certificate.
        let encoded = encode(&certificate, &blocks[2..]).unwrap();
        source
            .ingest_finalized_proof(blocks[1].clone(), &encoded)
            .await
            .unwrap();
        assert_eq!(source.get_latest_block().await.unwrap().unwrap().height, 3);
        let (replica, _replica_task) = crate::spawn_follower_indexer(
            context.child("replica"),
            "descendant-replica",
            crate::config::Config::default(),
            verifier.clone(),
            blocks[0].clone(),
        )
        .await
        .unwrap();
        let tampered = blocks[1].clone().with_owner_root([8; 32]);
        assert!(
            replica
                .ingest_finalized_proof(tampered.clone(), &encoded)
                .await
                .is_err()
        );
        assert!(
            replica
                .get_finalized_block(crate::FinalizedBlockQuery::Height(1))
                .await
                .unwrap()
                .is_none()
        );
        let answer = source
            .get_finalized_block(crate::FinalizedBlockQuery::Height(1))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(answer.snapshot.finalization, encoded);
        crate::follower::ingest_finalized_block(
            &replica,
            answer,
            1,
            &crate::follower::FollowerStatusSink::quiet(),
        )
        .await
        .unwrap();
        assert_eq!(replica.get_latest_block().await.unwrap().unwrap().height, 3);
        for block in &blocks[1..] {
            let answer = replica
                .get_finalized_block(crate::FinalizedBlockQuery::Height(block.height().get()))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(answer.block, block.encode().to_vec());
            verifier.verify_snapshot(&answer.snapshot).unwrap();
            assert_eq!(
                replica
                    .get_finalization(block.digest())
                    .await
                    .unwrap()
                    .unwrap(),
                answer.snapshot.finalization
            );
        }
        assert_eq!(
            replica
                .ingest_finalized_proof(blocks[1].clone(), &encoded)
                .await
                .unwrap(),
            crate::IngestOutcome::Duplicate
        );
    });
}
