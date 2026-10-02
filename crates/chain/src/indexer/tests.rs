use super::*;
use crate::execution::test_support::{ConsensusFixture, consensus_fixture, finalization};
use crate::{Application, ApplicationConfig};
use commonware_consensus::{
    simplex::types::{Context, Finalize, Proposal},
    types::{Epoch, Round, View},
};
use commonware_parallel::Sequential;
use commonware_runtime::{Runner as _, Supervisor as _, deterministic};

async fn genesis(context: deterministic::Context, leader: PublicKey, prefix: &str) -> HellasBlock {
    Application::new(
        context,
        crate::domain::TEST_NETWORK,
        leader,
        Vec::new(),
        prefix,
        ApplicationConfig {
            page_cache_size: 1024,
            page_cache_count: 8,
        },
    )
    .await
    .genesis_block()
}

fn block(parent: &HellasBlock, leader: PublicKey, view: u64, state: u8) -> HellasBlock {
    let parent_context = parent.context();
    HellasBlock::new(
        Context {
            round: Round::new(Epoch::zero(), View::new(view)),
            leader,
            parent: (parent_context.round.view(), parent.digest()),
        },
        parent.digest(),
        parent.height().next(),
        view,
        Digest::from([state; 32]),
        parent.sync_target(),
        Vec::new(),
    )
}

async fn setup(
    context: deterministic::Context,
    seed: u64,
) -> (ChainIndexer, Handle<()>, ConsensusFixture, HellasBlock) {
    let fixture = consensus_fixture(seed);
    let genesis = genesis(
        context.child("app"),
        fixture.leaders[0].clone(),
        &format!("genesis-{seed}"),
    )
    .await;
    let config = Config {
        mailbox_size: 32,
        replay_buffer: 32,
        write_buffer: 32,
        page_cache_size: 1024,
        page_cache_count: 8,
        ..Config::default()
    };
    let (indexer, handle) = spawn_archive(
        context.child("indexer"),
        &format!("indexer-{seed}"),
        config,
        fixture.verifier.clone(),
        genesis.clone(),
    )
    .await
    .expect("indexer");
    (indexer, handle, fixture, genesis)
}

#[test]
fn ingest_finalized_block_stores_through_marshal() {
    deterministic::Runner::default().start(|context| async move {
        let (indexer, _handle, fixture, genesis) = setup(context, 10).await;
        let block = block(&genesis, fixture.leaders[1].clone(), 1, 1);
        let finalization = finalization(&fixture, &block);

        assert_eq!(
            indexer
                .ingest_finalized(block.clone(), finalization)
                .await
                .expect("ingest"),
            IngestOutcome::Applied
        );
        let stored = indexer
            .get_finalized_block(FinalizedBlockQuery::Height(block.height().get()))
            .await
            .expect("query")
            .expect("stored block");
        assert_eq!(stored.snapshot.payload, block.digest());
    });
}

#[test]
fn duplicate_ingest_is_idempotent() {
    deterministic::Runner::default().start(|context| async move {
        let (indexer, _handle, fixture, genesis) = setup(context, 20).await;
        let block = block(&genesis, fixture.leaders[1].clone(), 1, 1);
        let finalization = finalization(&fixture, &block);

        assert_eq!(
            indexer
                .ingest_finalized(block.clone(), finalization.clone())
                .await
                .expect("first ingest"),
            IngestOutcome::Applied
        );
        assert_eq!(
            indexer
                .ingest_finalized(block, finalization)
                .await
                .expect("duplicate ingest"),
            IngestOutcome::Duplicate
        );
    });
}

#[test]
fn wrong_identity_rejects_finalization() {
    deterministic::Runner::default().start(|context| async move {
        let (indexer, _handle, fixture, genesis) = setup(context, 30).await;
        let wrong = consensus_fixture(300);
        let indexer = indexer.with_verifier(wrong.verifier);
        let block = block(&genesis, fixture.leaders[1].clone(), 1, 1);
        let finalization = finalization(&fixture, &block);

        assert!(matches!(
            indexer.ingest_finalized(block, finalization).await,
            Err(IngestError::Consensus(
                ConsensusVerificationError::VerificationFailed
            ))
        ));
    });
}

#[test]
fn payload_mismatch_rejects_before_marshal() {
    deterministic::Runner::default().start(|context| async move {
        let (indexer, _handle, fixture, genesis) = setup(context, 40).await;
        let candidate = block(&genesis, fixture.leaders[1].clone(), 1, 1);
        let other = block(&genesis, fixture.leaders[1].clone(), 1, 2);
        let finalization = finalization(&fixture, &other);

        assert!(matches!(
            indexer.ingest_finalized(candidate, finalization).await,
            Err(IngestError::Consensus(
                ConsensusVerificationError::PayloadMismatch
            ))
        ));
    });
}

#[test]
fn same_height_different_payload_rejects() {
    deterministic::Runner::default().start(|context| async move {
        let (indexer, _handle, fixture, genesis) = setup(context, 50).await;
        let first = block(&genesis, fixture.leaders[1].clone(), 1, 1);
        let second = block(&genesis, fixture.leaders[1].clone(), 1, 2);
        let first_finalization = finalization(&fixture, &first);
        let second_finalization = finalization(&fixture, &second);

        assert_eq!(
            indexer
                .ingest_finalized(first.clone(), first_finalization)
                .await
                .expect("first ingest"),
            IngestOutcome::Applied
        );
        assert!(matches!(
            indexer.ingest_finalized(second.clone(), second_finalization).await,
            Err(IngestError::ConflictingHeight {
                height: 1,
                existing,
                incoming,
            }) if existing == first.digest() && incoming == second.digest()
        ));
    });
}

#[test]
fn block_round_must_match_finalization_round() {
    deterministic::Runner::default().start(|context| async move {
        let (indexer, _handle, fixture, genesis) = setup(context, 60).await;
        let block = block(&genesis, fixture.leaders[1].clone(), 1, 1);
        let proposal = Proposal::new(
            Round::new(Epoch::zero(), View::new(2)),
            View::zero(),
            block.digest(),
        );
        let votes = fixture
            .schemes
            .iter()
            .map(|scheme| Finalize::sign(scheme, proposal.clone()).expect("finalize vote"))
            .collect::<Vec<_>>();
        let finalization = Finalization::from_finalizes(&fixture.assembler, &votes, &Sequential)
            .expect("finalization");

        assert!(matches!(
            indexer.ingest_finalized(block, finalization).await,
            Err(IngestError::RoundMismatch)
        ));
    });
}

#[cfg(feature = "full-node")]
#[test]
fn pruning_reclaims_old_marshal_sections() {
    deterministic::Runner::default().start(|context| async move {
        let (indexer, _handle, fixture, mut parent) = setup(context, 97989).await;
        for height in 1..=260 {
            let next = block(&parent, fixture.leaders[0].clone(), height, 1);
            indexer
                .ingest_finalized(next.clone(), finalization(&fixture, &next))
                .await
                .unwrap();
            parent = next;
        }
        indexer.prune_before(259);
        // This bypasses the public retention floor: the backing archive itself
        // must have removed the first section, not merely hidden its entries.
        assert!(indexer.marshal.get_block(Height::new(1)).await.is_none());
        assert!(indexer.marshal.get_block(Height::new(260)).await.is_some());
        assert!(
            indexer
                .get_finalized_block(FinalizedBlockQuery::Height(258))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            indexer
                .get_finalized_block(FinalizedBlockQuery::Height(259))
                .await
                .unwrap()
                .is_some()
        );
    });
}
